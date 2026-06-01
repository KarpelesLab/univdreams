//! Headless Win16 GUI model.
//!
//! Instead of rendering pixels, the USER stubs record window /
//! dialog / control structure and the messages flowing through them
//! as **data**. That state serialises to JSON (see the `serde`
//! derives) so an external "expect"-style driver can observe what the
//! program put on screen (a dialog's title + its buttons, a message
//! box's prompt) and inject the response (click a button, dismiss a
//! box) to run a GUI program — e.g. an installer — non-interactively.
//!
//! The model is deliberately minimal: enough structure for modal
//! dialog automation, not a faithful window manager.

use std::collections::BTreeMap;

use serde::Serialize;

/// A registered window class (`RegisterClass`).
#[derive(Debug, Clone, Serialize)]
pub struct WndClass {
    pub name: String,
    /// Window procedure as a far `selector:offset` pair.
    pub wndproc_sel: u16,
    pub wndproc_off: u16,
    pub style: u32,
}

/// A live window (top-level, child, or dialog control).
#[derive(Debug, Clone, Serialize)]
pub struct Window {
    pub hwnd: u16,
    pub class: String,
    pub title: String,
    pub parent: u16,
    /// Control id (child windows) or menu handle (top-level).
    pub id: u16,
    pub style: u32,
    pub wndproc_sel: u16,
    pub wndproc_off: u16,
    pub visible: bool,
    /// Child window handles, in creation order.
    pub children: Vec<u16>,
}

/// A control inside a dialog template (parsed from the resource).
#[derive(Debug, Clone, Serialize)]
pub struct DialogControl {
    pub id: u16,
    pub class: String,
    pub text: String,
    pub style: u32,
}

/// One observable GUI action, appended in order. This is the
/// "transcript" an expect-style driver reads.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GuiEvent {
    RegisterClass {
        name: String,
    },
    CreateWindow {
        hwnd: u16,
        class: String,
        title: String,
        parent: u16,
        id: u16,
    },
    ShowWindow {
        hwnd: u16,
        cmd: u16,
    },
    MessageBox {
        caption: String,
        text: String,
        flags: u16,
        result: u16,
    },
    DialogStart {
        title: String,
        controls: Vec<DialogControl>,
    },
    DialogEnd {
        result: i16,
    },
    SetWindowText {
        hwnd: u16,
        text: String,
    },
}

/// The whole headless GUI state for a task.
#[derive(Debug, Default, Clone, Serialize)]
pub struct GuiState {
    pub classes: BTreeMap<String, WndClass>,
    pub windows: BTreeMap<u16, Window>,
    /// Next window handle to hand out.
    #[serde(skip)]
    pub next_hwnd: u16,
    /// Next GDI/USER object handle (brush/cursor/icon/…).
    #[serde(skip)]
    pub next_obj_handle: u16,
    /// Ordered transcript of GUI actions.
    pub events: Vec<GuiEvent>,
}

/// Window handles start here so they don't collide with the synthetic
/// selector / thunk ranges.
const HWND_BASE: u16 = 0x1000;
/// GDI/USER object handles start here, above the window-handle range.
const OBJ_HANDLE_BASE: u16 = 0x8000;

impl GuiState {
    /// Allocate a fresh, distinct GDI/USER object handle (brush, cursor,
    /// icon, …) — non-zero and unique so the program can tell them apart
    /// and free them individually.
    pub fn alloc_obj_handle(&mut self) -> u16 {
        // Object handles live above the window-handle range.
        if self.next_obj_handle < OBJ_HANDLE_BASE {
            self.next_obj_handle = OBJ_HANDLE_BASE;
        }
        let h = self.next_obj_handle;
        self.next_obj_handle = self.next_obj_handle.wrapping_add(4);
        h
    }

    /// Allocate a fresh window handle.
    pub fn alloc_hwnd(&mut self) -> u16 {
        if self.next_hwnd < HWND_BASE {
            self.next_hwnd = HWND_BASE;
        }
        let h = self.next_hwnd;
        self.next_hwnd = self.next_hwnd.wrapping_add(4);
        h
    }

    /// Record a registered window class.
    pub fn register_class(&mut self, name: &str, wndproc_sel: u16, wndproc_off: u16, style: u32) {
        self.classes.insert(
            name.to_string(),
            WndClass {
                name: name.to_string(),
                wndproc_sel,
                wndproc_off,
                style,
            },
        );
        self.events.push(GuiEvent::RegisterClass {
            name: name.to_string(),
        });
    }

    /// Create a window and record it; returns its handle.
    #[allow(clippy::too_many_arguments)]
    pub fn create_window(
        &mut self,
        class: &str,
        title: &str,
        parent: u16,
        id: u16,
        style: u32,
    ) -> u16 {
        // Inherit the wndproc from the registered class, if any.
        let (sel, off) = self
            .classes
            .get(class)
            .map_or((0, 0), |c| (c.wndproc_sel, c.wndproc_off));
        let hwnd = self.alloc_hwnd();
        self.windows.insert(
            hwnd,
            Window {
                hwnd,
                class: class.to_string(),
                title: title.to_string(),
                parent,
                id,
                style,
                wndproc_sel: sel,
                wndproc_off: off,
                visible: false,
                children: Vec::new(),
            },
        );
        if parent != 0 {
            if let Some(p) = self.windows.get_mut(&parent) {
                p.children.push(hwnd);
            }
        }
        self.events.push(GuiEvent::CreateWindow {
            hwnd,
            class: class.to_string(),
            title: title.to_string(),
            parent,
            id,
        });
        hwnd
    }

    /// The window procedure for `hwnd` (its own, else its class's).
    pub fn wndproc_of(&self, hwnd: u16) -> Option<(u16, u16)> {
        self.windows.get(&hwnd).and_then(|w| {
            if w.wndproc_off != 0 || w.wndproc_sel != 0 {
                Some((w.wndproc_sel, w.wndproc_off))
            } else {
                self.classes
                    .get(&w.class)
                    .map(|c| (c.wndproc_sel, c.wndproc_off))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_window_links_to_parent_and_logs() {
        let mut g = GuiState::default();
        g.register_class("AfxFrameOrView", 1, 0x100, 0);
        let frame = g.create_window("AfxFrameOrView", "Setup", 0, 0, 0);
        let btn = g.create_window("BUTTON", "Install", frame, 1, 0);
        assert_eq!(g.windows[&frame].children, vec![btn]);
        assert_eq!(g.wndproc_of(frame), Some((1, 0x100)));
        // events: register + 2 creates.
        assert_eq!(g.events.len(), 3);
    }
}
