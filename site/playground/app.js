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

import init, {
  decompile,
  compile,
  verify,
  solana_classify_loader,
  solana_programdata_pubkey_base58,
  solana_strip_elf,
} from "../wasm/ud_wasm.js";

const $status        = document.getElementById("status");
const $filename      = document.getElementById("filename");
const $upload        = document.getElementById("upload");
const $compile       = document.getElementById("btn-compile");
const $verify        = document.getElementById("btn-verify");
const $loadUrl       = document.getElementById("btn-load-url");
const $urlInput      = document.getElementById("url-input");
const $exampleMsmpeg = document.getElementById("example-msmpeg4");
const $exampleSolana = document.getElementById("example-solana");
const $format        = document.getElementById("format-select");
const $programId     = document.getElementById("program-id");
const $rpcUrl        = document.getElementById("rpc-url");
const $loadProgram   = document.getElementById("btn-load-program");
const $tabs          = document.querySelectorAll(".tabs .tab");
const $tabPanels     = document.querySelectorAll(".tab-panel");

const MSMPEG4_URL =
  "https://samples.oxideav.org/codecs/windows/msmpeg4/wmpcdcs8-mpg4c32.dll";

// Default mainnet RPC: Helius. `api.mainnet-beta.solana.com`
// rejects browser-origin requests with HTTP 403, so the
// playground needs an endpoint whose CORS policy lets a
// page on github.io read account data. Users can override
// in the RPC input or via ?rpc=<url>.
const SOLANA_RPC_DEFAULT =
  "https://kristi-cykm4t-fast-mainnet.helius-rpc.com";
const SOLANA_EXAMPLE = "3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr";

// Base58 alphabet — Bitcoin / Solana convention. Used to
// decode the user-supplied program ID and the RPC's `owner`
// field into raw 32-byte arrays the WASM bindings accept.
// Encoding back to base58 lives in Rust (bs58 crate via
// solana_programdata_pubkey_base58).
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    t[BASE58_ALPHABET.charCodeAt(i)] = i;
  }
  return t;
})();

function base58Decode(str) {
  if (typeof str !== "string" || str.length === 0) {
    throw new Error("base58: empty input");
  }
  // Count leading "1"s — each is one leading zero byte.
  let zeros = 0;
  while (zeros < str.length && str.charCodeAt(zeros) === 49 /* '1' */) {
    zeros++;
  }
  // Carry-multiply digits into a big-endian byte buffer
  // sized for the maximum possible decoded length.
  const size = (((str.length - zeros) * 733) / 1000) | 0; // log(58)/log(256) ≈ 0.733
  const b = new Uint8Array(size + 1);
  let length = 0;
  for (let i = zeros; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const digit = code < 128 ? BASE58_INDEX[code] : -1;
    if (digit < 0) {
      throw new Error(`base58: invalid character '${str[i]}'`);
    }
    let carry = digit;
    let j = 0;
    for (let k = b.length - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 58 * b[k];
      b[k] = carry % 256;
      carry = (carry / 256) | 0;
    }
    length = j;
  }
  // Skip leading buffer zeros, then prepend the explicit
  // leading-zero bytes encoded as "1"s.
  let skip = b.length - length;
  while (skip < b.length && b[skip] === 0) skip++;
  const out = new Uint8Array(zeros + (b.length - skip));
  out.set(b.subarray(skip), zeros);
  return out;
}

function base64Decode(str) {
  // Native atob is fine for arbitrary base64. Convert each
  // char to a byte; no DOMString roundtrip needed.
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function solanaRpc(rpcUrl, method, params) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!resp.ok) {
    throw new Error(`RPC HTTP ${resp.status} ${resp.statusText}`);
  }
  const json = await resp.json();
  if (json.error) {
    throw new Error(`RPC error ${json.error.code}: ${json.error.message}`);
  }
  return json.result;
}

async function fetchSolanaProgram(programId, rpcUrl) {
  setStatus(`Fetching ${programId} from ${new URL(rpcUrl).host}…`, "");
  const account = await solanaRpc(rpcUrl, "getAccountInfo", [
    programId,
    { encoding: "base64" },
  ]);
  if (!account || !account.value) {
    throw new Error(`account ${programId} does not exist`);
  }
  const owner = account.value.owner;
  const [b64payload, encoding] = account.value.data;
  if (encoding !== "base64") {
    throw new Error(`unexpected data encoding ${encoding}`);
  }
  const programAccountData = base64Decode(b64payload);
  const kind = solana_classify_loader(owner);
  if (kind === "unknown") {
    throw new Error(
      `${programId}: owner ${owner} is not a known BPF loader (BPFLoader2, BPFLoaderUpgradeable, LoaderV4)`,
    );
  }

  let elf;
  if (kind === "upgradeable") {
    const pdAddr = solana_programdata_pubkey_base58(programAccountData);
    setStatus(`Fetching ProgramData ${pdAddr.slice(0, 8)}…`, "");
    const pd = await solanaRpc(rpcUrl, "getAccountInfo", [
      pdAddr,
      { encoding: "base64" },
    ]);
    if (!pd || !pd.value) {
      throw new Error(`ProgramData account ${pdAddr} does not exist`);
    }
    const pdData = base64Decode(pd.value.data[0]);
    elf = solana_strip_elf(pdData, kind);
  } else {
    elf = solana_strip_elf(programAccountData, kind);
  }

  uploadName = `${programId}.elf`;
  $filename.textContent = `${programId} (${elf.length} bytes, ${kind})`;
  await decompileBytes(elf, programId);
}

function onLoadProgram() {
  const id = $programId.value.trim();
  if (!id) {
    setStatus("Enter a Solana program ID (base58) and click 'Load from chain'.", "warn");
    return;
  }
  // Cheap sanity check — base58 decodes to exactly 32 bytes
  // for a valid pubkey. Catches obvious typos before the
  // RPC roundtrip.
  try {
    const bytes = base58Decode(id);
    if (bytes.length !== 32) {
      throw new Error(`decoded to ${bytes.length} bytes (expected 32)`);
    }
  } catch (e) {
    setStatus(`Invalid program ID: ${e.message || e}`, "error");
    return;
  }
  const rpc = ($rpcUrl.value || "").trim() || SOLANA_RPC_DEFAULT;
  void fetchSolanaProgram(id, rpc).catch((e) => {
    setStatus(`Solana fetch failed: ${e.message || e}`, "error");
  });
}

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
  $loadUrl.addEventListener("click", onLoadFromUrl);
  $urlInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") onLoadFromUrl();
  });
  $loadProgram.addEventListener("click", onLoadProgram);
  $programId.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") onLoadProgram();
  });
  for (const tab of $tabs) {
    tab.addEventListener("click", () => selectTab(tab.dataset.tab));
  }
  if ($exampleMsmpeg) {
    $exampleMsmpeg.addEventListener("click", (ev) => {
      ev.preventDefault();
      selectTab("url");
      $urlInput.value = MSMPEG4_URL;
      void loadFromUrl(MSMPEG4_URL);
    });
  }
  if ($exampleSolana) {
    $exampleSolana.addEventListener("click", (ev) => {
      ev.preventDefault();
      selectTab("chain");
      $programId.value = SOLANA_EXAMPLE;
      onLoadProgram();
    });
  }

  // Populate the RPC input with the default (and any
  // `?rpc=<url>` override) so the user can see / edit it
  // before triggering a fetch.
  const params = new URLSearchParams(window.location.search);
  $rpcUrl.value = params.get("rpc") || SOLANA_RPC_DEFAULT;

  // Deep-link: ?program=<id> auto-loads on page load and
  // switches the toolbar to the Solana-chain tab.
  const queryProgram = params.get("program");
  if (queryProgram) {
    selectTab("chain");
    $programId.value = queryProgram;
    onLoadProgram();
    return;
  }
  // Same for ?url=<binary-url>: pre-load the URL tab.
  const queryUrl = params.get("url");
  if (queryUrl) {
    selectTab("url");
    $urlInput.value = queryUrl;
    void loadFromUrl(queryUrl);
    return;
  }

  setStatus("Ready. Upload a binary, paste a URL or Solana program ID, or edit the sample and click Compile.", "ok");
}

function selectTab(name) {
  for (const tab of $tabs) {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", active ? "true" : "false");
  }
  for (const panel of $tabPanels) {
    panel.classList.toggle("hidden", panel.dataset.panel !== name);
  }
}

function onLoadFromUrl() {
  const url = ($urlInput.value || "").trim();
  if (!url) {
    setStatus("Enter a URL and click Fetch.", "warn");
    return;
  }
  void loadFromUrl(url);
}

async function loadFromUrl(url) {
  setStatus(`Fetching ${url}…`, "");
  try {
    const resp = await fetch(url, { mode: "cors" });
    if (!resp.ok) {
      setStatus(
        `Fetch failed: HTTP ${resp.status} ${resp.statusText} from ${url}`,
        "error",
      );
      return;
    }
    const buf = new Uint8Array(await resp.arrayBuffer());
    // Derive a display name from the URL path so guessOutputName
    // can synthesize a sensible download name later.
    const parsed = new URL(url, window.location.href);
    const tail = parsed.pathname.split("/").filter(Boolean).pop() || "input.bin";
    uploadName = tail;
    $filename.textContent = `${tail} (${buf.length} bytes, from ${parsed.host})`;
    await decompileBytes(buf, tail);
  } catch (e) {
    setStatus(
      `Fetch / decode failed for ${url}: ${e.message || e}` +
        " — the server must send `Access-Control-Allow-Origin` for cross-origin fetches.",
      "error",
    );
  }
}

async function decompileBytes(buf, name) {
  const format = $format.value;
  setStatus(`Decompiling ${name} (${buf.length} bytes, format: ${format})…`, "");
  // Yield to the event loop so the status message paints before
  // the synchronous decompile call ties up the main thread.
  await new Promise((r) => setTimeout(r, 0));
  try {
    const t0 = performance.now();
    const text = decompile(buf, format);
    const dt = (performance.now() - t0).toFixed(0);
    replaceEditor(text);
    setStatus(
      `Decompiled ${name} in ${dt} ms (${text.length.toLocaleString()} chars of source, format: ${format}).`,
      "ok",
    );
  } catch (e) {
    setStatus("Decompile failed: " + (e.message || e), "error");
  }
}

async function onUpload(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  uploadName = file.name;
  $filename.textContent = file.name + " (" + file.size + " bytes)";
  const buf = new Uint8Array(await file.arrayBuffer());
  await decompileBytes(buf, file.name);
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
