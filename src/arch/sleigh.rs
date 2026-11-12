//! Instruction decoding through Ghidra's SLEIGH processor specifications.
//!
//! The specifications (`sleigh-specs/`, Apache-2.0, from Ghidra) are
//! embedded when the `sleigh` feature is on, and compiled on first use
//! by the vendored engine in [`crate::sleigh`]. Every language their
//! `.ldefs` files declare is available by its Ghidra id, such as
//! `ARM:LE:32:v8` or `Hexagon:LE:32:default`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::sleigh::runtime::{Runtime, RuntimeConfig, SleighData};

/// Every embedded spec file: (path under `sleigh-specs/`, contents).
static FILES: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/sleigh_specs.rs"));

/// A language a `.ldefs` file declares.
#[derive(Debug, Clone)]
pub struct LanguageDef {
    /// Ghidra's id: `processor:endian:size:variant`.
    pub id: String,
    pub processor: String,
    pub big_endian: bool,
    /// Address size in bits.
    pub size: u32,
    pub variant: String,
    /// The directory under `sleigh-specs/` holding its files.
    dir: String,
    slaspec: String,
    pspec: String,
}

/// Every language the embedded specifications declare.
#[must_use]
pub fn languages() -> &'static [LanguageDef] {
    static LANGUAGES: OnceLock<Vec<LanguageDef>> = OnceLock::new();
    LANGUAGES.get_or_init(|| {
        FILES
            .iter()
            .filter(|(path, _)| {
                std::path::Path::new(path)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("ldefs"))
            })
            .flat_map(|(path, text)| {
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                parse_ldefs(dir, text)
            })
            .collect()
    })
}

/// The `<language>` entries of an `.ldefs` file in `dir`.
fn parse_ldefs(dir: &str, text: &str) -> Vec<LanguageDef> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<language ") {
        rest = &rest[start..];
        let Some(end) = rest.find('>') else { break };
        let attrs = attributes(&rest[..end]);
        rest = &rest[end..];
        let get = |name: &str| attrs.get(name).cloned().unwrap_or_default();
        let slafile = get("slafile");
        out.push(LanguageDef {
            id: get("id"),
            processor: get("processor"),
            big_endian: get("endian") == "big",
            size: get("size").parse().unwrap_or(0),
            variant: get("variant"),
            dir: dir.to_string(),
            slaspec: format!(
                "{}.slaspec",
                slafile.strip_suffix(".sla").unwrap_or(&slafile)
            ),
            pspec: get("processorspec"),
        });
    }
    out
}

/// The `name="value"` attributes of an XML start tag.
fn attributes(tag: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = tag;
    while let Some(eq) = rest.find("=\"") {
        let name = rest[..eq]
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("");
        let value_start = eq + 2;
        let Some(len) = rest[value_start..].find('"') else {
            break;
        };
        out.insert(
            name.to_string(),
            rest[value_start..value_start + len].to_string(),
        );
        rest = &rest[value_start + len + 1..];
    }
    out
}

/// The initial context values a `.pspec` sets: `(field, value)`.
fn pspec_context(text: &str) -> Vec<(String, i64)> {
    let Some(start) = text.find("<context_set") else {
        return Vec::new();
    };
    let body = &text[start..];
    let body = &body[..body.find("</context_set>").unwrap_or(body.len())];
    body.split("<set ")
        .skip(1)
        .filter_map(|set| {
            let attrs = attributes(&set[..set.find('>').unwrap_or(set.len())]);
            let val = attrs.get("val")?;
            let val = match val.strip_prefix("0x") {
                Some(hex) => i64::from_str_radix(hex, 16).ok()?,
                None => val.parse().ok()?,
            };
            Some((attrs.get("name")?.clone(), val))
        })
        .collect()
}

fn file(path: &str) -> Option<&'static str> {
    FILES
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, text)| *text)
}

/// The spec files of one directory, for the SLEIGH preprocessor.
struct Embedded {
    dir: String,
}

impl crate::sleigh::parse::Input for Embedded {
    fn open(&mut self, name: &str) -> std::io::Result<String> {
        file(&format!("{}/{name}", self.dir))
            .map(str::to_string)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, name.to_string()))
    }
}

/// A compiled language.
pub struct Language {
    pub def: LanguageDef,
    sleigh: SleighData,
    initial_ctx: u64,
}

impl std::fmt::Debug for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Language")
            .field("def", &self.def)
            .finish_non_exhaustive()
    }
}

/// A language compiled, or why it couldn't be.
type Compiled = Result<Arc<Language>, String>;

/// Compile (once) the language with Ghidra id `id`.
pub fn language(id: &str) -> Result<Arc<Language>, String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Compiled>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    if let Some(found) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(id)
    {
        return found.clone();
    }
    // The engine asserts on some inputs it doesn't support; a spec it
    // can't handle is an error, not a crash.
    let compiled = std::panic::catch_unwind(|| compile(id))
        .unwrap_or_else(|_| Err(format!("SLEIGH engine panicked compiling `{id}`")))
        .map(Arc::new);
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id.to_string(), compiled.clone());
    compiled
}

fn compile(id: &str) -> Result<Language, String> {
    let def = languages()
        .iter()
        .find(|l| l.id == id)
        .ok_or_else(|| format!("no SLEIGH language `{id}`"))?
        .clone();
    let mut parser = crate::sleigh::parse::Parser::new(
        Embedded {
            dir: def.dir.clone(),
        },
        &["ICICLE"],
    );
    if let Err(e) = parser.include_file(def.slaspec.clone()) {
        return Err(format!("{}", parser.error_formatter(e)));
    }
    let sleigh = crate::sleigh::compile::build_inner(parser, false)?;
    let mut initial_ctx = 0u64;
    let pspec = file(&format!("{}/{}", def.dir, def.pspec)).unwrap_or("");
    for (name, val) in pspec_context(pspec) {
        if let Some(field) = sleigh.get_context_field(&name) {
            field.field.set(&mut initial_ctx, val);
        }
    }
    Ok(Language {
        def,
        sleigh,
        initial_ctx,
    })
}

impl Language {
    /// A disassembler starting from the language's initial context.
    #[must_use]
    pub fn disassembler(&self) -> Disassembler<'_> {
        Disassembler {
            lang: self,
            runtime: Runtime::new_with_config(&RuntimeConfig {
                context: self.initial_ctx,
                ignore_delay_slots: true,
                ..RuntimeConfig::default()
            }),
        }
    }
}

/// Decodes instructions one at a time.
pub struct Disassembler<'a> {
    lang: &'a Language,
    runtime: Runtime,
}

impl std::fmt::Debug for Disassembler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Disassembler")
            .field("lang", &self.lang.def.id)
            .finish_non_exhaustive()
    }
}

impl Disassembler<'_> {
    /// The instruction at the start of `bytes`, loaded at `addr`: its
    /// length and text. `None` if the bytes don't decode.
    pub fn decode(&mut self, bytes: &[u8], addr: u64) -> Option<(usize, String)> {
        let sleigh = &self.lang.sleigh;
        let insn = self.runtime.decode(sleigh, addr, bytes)?;
        let len = usize::try_from(insn.inst_next.checked_sub(insn.inst_start)?).ok()?;
        if len == 0 || len > bytes.len() {
            return None;
        }
        let text = self.runtime.disasm(sleigh)?.to_string();
        Some((len, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_are_declared() {
        let ids: Vec<&str> = languages().iter().map(|l| l.id.as_str()).collect();
        for id in ["ARM:LE:32:v8", "MIPS:BE:32:default", "Xtensa:LE:32:default"] {
            assert!(
                ids.contains(&id),
                "{id} missing from {} languages",
                ids.len()
            );
        }
    }

    #[test]
    fn arm_decodes() {
        let arm = language("ARM:LE:32:v8").expect("compile ARM");
        let mut d = arm.disassembler();
        // mov r0, #1 ; bx lr
        let code = [0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
        let (len, text) = d.decode(&code, 0x1000).unwrap();
        assert_eq!(len, 4);
        assert_eq!(text, "mov r0,#0x1");
        let (len, text) = d.decode(&code[4..], 0x1004).unwrap();
        assert_eq!(len, 4);
        assert_eq!(text, "bx lr");
    }

    #[test]
    fn pspec_context_values() {
        let ctx = pspec_context(
            r#"<context_data><context_set space="ram">
            <set name="TMode" val="0" description="x"/><set name="LRset" val="0x1"/>
            </context_set></context_data>"#,
        );
        assert_eq!(ctx, [("TMode".into(), 0), ("LRset".into(), 1)]);
    }
}
#[cfg(test)]
mod survey {
    #[test]
    #[ignore = "survey"]
    fn compile_all() {
        let mut seen = std::collections::HashSet::new();
        for l in super::languages() {
            if !seen.insert((l.dir.clone(), l.slaspec.clone())) {
                continue;
            }
            let t = std::time::Instant::now();
            match super::language(&l.id) {
                Ok(_) => println!("OK   {:40} {:?}", l.id, t.elapsed()),
                Err(e) => println!(
                    "FAIL {:40} {}",
                    l.id,
                    e.lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(150)
                        .collect::<String>()
                ),
            }
        }
    }
}
