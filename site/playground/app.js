// Playground glue: load the WASM module, wire up file upload,
// CodeMirror 6 editor, and the Verify / Compile buttons.
//
// CodeMirror 6 is loaded as ESM from esm.sh so we don't need a
// bundler. The .cpp grammar gives us tolerable highlighting for
// .ud syntax (curly braces, strings, hex literals, comments) — a
// dedicated .ud grammar can come later.

import { EditorState } from "https://esm.sh/@codemirror/state@6";
import { EditorView, keymap, lineNumbers, highlightActiveLine } from "https://esm.sh/@codemirror/view@6";
import { defaultKeymap, history, historyKeymap } from "https://esm.sh/@codemirror/commands@6";
import { bracketMatching, indentOnInput, syntaxHighlighting, defaultHighlightStyle } from "https://esm.sh/@codemirror/language@6";
import { cpp } from "https://esm.sh/@codemirror/lang-cpp@6";
import { oneDark } from "https://esm.sh/@codemirror/theme-one-dark@6";

import init, { decompile, compile, verify } from "../wasm/ud_wasm.js";

const $status   = document.getElementById("status");
const $filename = document.getElementById("filename");
const $upload   = document.getElementById("upload");
const $compile  = document.getElementById("btn-compile");
const $verify   = document.getElementById("btn-verify");

let editor;
let uploadName = "input.bin";

function setStatus(msg, cls) {
  $status.textContent = msg;
  $status.className = cls || "";
}

const SAMPLE = `// Decompile a binary to populate this editor with real .ud source.
// Or start from scratch — a minimal raw 6502 image fits in a handful of lines:

@module {
    arch: "6502",
    format: "raw",
    bits: 0x10,
    endian: "little",
    build: { load: 0xff00, file_size: 0x100 },
}

@raw(0xff00, [
    0xa9, 0x00,        // lda #0
    0xea,              // nop
    // ... (255 bytes of body)
])
`;

async function start() {
  try {
    await init(new URL("../wasm/ud_wasm_bg.wasm", import.meta.url));
  } catch (e) {
    setStatus("Failed to load WASM: " + e, "error");
    return;
  }

  const state = EditorState.create({
    doc: SAMPLE,
    extensions: [
      lineNumbers(),
      highlightActiveLine(),
      history(),
      bracketMatching(),
      indentOnInput(),
      syntaxHighlighting(defaultHighlightStyle),
      cpp(),
      oneDark,
      keymap.of([...defaultKeymap, ...historyKeymap]),
      EditorView.lineWrapping,
    ],
  });
  editor = new EditorView({ state, parent: document.getElementById("editor") });

  $upload.addEventListener("change", onUpload);
  $compile.addEventListener("click", onCompile);
  $verify.addEventListener("click", onVerify);

  setStatus("Ready. Upload a binary, or edit the sample and click Compile.", "ok");
}

async function onUpload(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  uploadName = file.name;
  $filename.textContent = file.name + " (" + file.size + " bytes)";
  setStatus("Decompiling " + file.name + "…", "");
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const t0 = performance.now();
    const text = decompile(buf);
    const dt = (performance.now() - t0).toFixed(0);
    replaceEditor(text);
    setStatus(`Decompiled ${file.name} in ${dt} ms (${text.length} chars of source).`, "ok");
  } catch (e) {
    setStatus("Decompile failed: " + (e.message || e), "error");
  }
}

function replaceEditor(text) {
  editor.dispatch({
    changes: { from: 0, to: editor.state.doc.length, insert: text },
  });
}

function onCompile() {
  const source = editor.state.doc.toString();
  setStatus("Compiling…", "");
  try {
    const t0 = performance.now();
    const bytes = compile(source);
    const dt = (performance.now() - t0).toFixed(0);
    const outName = guessOutputName(uploadName);
    triggerDownload(bytes, outName);
    setStatus(`Compiled in ${dt} ms — wrote ${bytes.length} bytes to ${outName}.`, "ok");
  } catch (e) {
    setStatus("Compile failed: " + (e.message || e), "error");
  }
}

function onVerify() {
  const source = editor.state.doc.toString();
  try {
    const warnings = verify(source);
    if (!warnings) {
      setStatus("Verify: no @asm warnings.", "ok");
    } else {
      setStatus("Verify warnings:\n" + warnings, "warn");
    }
  } catch (e) {
    setStatus("Verify failed: " + (e.message || e), "error");
  }
}

function guessOutputName(inputName) {
  // If the upload was named "thing.dll", emit "thing.rebuilt.dll".
  // Falls back to "output.bin".
  if (!inputName || inputName === "input.bin") return "output.bin";
  const dot = inputName.lastIndexOf(".");
  if (dot <= 0) return inputName + ".rebuilt";
  return inputName.slice(0, dot) + ".rebuilt" + inputName.slice(dot);
}

function triggerDownload(bytes, name) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke after a tick so the browser commits the download first.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

start();
