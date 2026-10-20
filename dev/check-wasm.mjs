// Checks the invariant wasm-bindgen needs at startup, on the built module.
//
//   node dev/check-wasm.mjs dist/pkg/pigeons_web_bg.wasm
//
// wasm-bindgen's glue does `wasm.__wbindgen_externrefs.grow(4)` before anything
// else, so that export must be a growable externref table. A wasm-opt release
// (binaryen 116, which Ubuntu ships) rewrote the export to point at the
// fixed-size funcref table instead; the page then failed with "failed to grow
// table", and had the grow succeeded it would have written `null`/`true` into
// function pointers. This check turns that class of miscompilation into a build
// failure instead of a broken deployment.
import { readFile } from "node:fs/promises";

const path = process.argv[2] ?? "dist/pkg/pigeons_web_bg.wasm";
const bytes = new Uint8Array(await readFile(path));

const FUNCREF = 0x70;
const EXTERNREF = 0x6f;
const EXPORT_KIND_TABLE = 0x01;

let offset = 0;
const byte = () => bytes[offset++];
const u32 = () => {
  let result = 0;
  let shift = 0;
  let next;
  do {
    next = byte();
    result |= (next & 0x7f) << shift;
    shift += 7;
  } while (next & 0x80);
  return result >>> 0;
};

const magic = [0x00, 0x61, 0x73, 0x6d];
if (magic.some((expected, i) => bytes[i] !== expected)) {
  fail([`${path} is not a wasm module`]);
}
offset = 8; // magic + version

const tables = [];
const exports = [];
while (offset < bytes.length) {
  const id = byte();
  const size = u32();
  const end = offset + size;
  if (id === 4) {
    const count = u32();
    for (let i = 0; i < count; i++) {
      const type = byte();
      const flags = byte();
      const min = u32();
      const max = flags & 0x01 ? u32() : null;
      tables.push({ type, min, max });
    }
  } else if (id === 7) {
    const count = u32();
    for (let i = 0; i < count; i++) {
      const length = u32();
      const name = new TextDecoder().decode(bytes.subarray(offset, offset + length));
      offset += length;
      const kind = byte();
      const index = u32();
      exports.push({ name, kind, index });
    }
  }
  offset = end;
}

const problems = [];
const exported = exports.find((entry) => entry.name === "__wbindgen_externrefs");
if (!exported) {
  problems.push("no __wbindgen_externrefs export");
} else if (exported.kind !== EXPORT_KIND_TABLE) {
  problems.push("__wbindgen_externrefs is not exported as a table");
} else {
  const table = tables[exported.index];
  if (!table) {
    problems.push(`__wbindgen_externrefs points at table ${exported.index}, which does not exist`);
  } else {
    if (table.type !== EXTERNREF) {
      const what = table.type === FUNCREF ? "funcref" : `type 0x${table.type.toString(16)}`;
      problems.push(`__wbindgen_externrefs points at a ${what} table (index ${exported.index}), expected externref`);
    }
    if (table.max !== null) {
      problems.push(`externref table is limited to ${table.max} slots, but the runtime grows it at startup`);
    }
  }
}

if (problems.length > 0) {
  fail(problems);
}

const table = tables[exported.index];
console.log(
  `check-wasm: ok (__wbindgen_externrefs is table ${exported.index}, externref, ${table.min} slots, growable)`,
);

function fail(problems) {
  console.error("check-wasm: the built module is not usable in a browser:");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("  this is usually wasm-opt miscompiling; binaryen 126 is known good");
  process.exit(1);
}
