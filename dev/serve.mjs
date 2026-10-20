// Minimal static file server for the built page.
//
//   node dev/serve.mjs dist 8787
//
// Equivalent to any static host; it exists so `dist/` can be opened without a
// dependency on a particular toolchain.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const root = process.argv[2] ?? "dist";
const port = Number(process.argv[3] ?? 8787);
const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".wasm": "application/wasm",
  ".css": "text/css",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

createServer(async (request, response) => {
  const path = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const file = join(root, normalize(path === "/" ? "/index.html" : path));
  // Directory URLs get their index.html, the way any static host behaves; this
  // is what makes a project page at /pigeons-web/ work.
  const candidates = [file, join(file, "index.html")];
  for (const candidate of candidates) {
    try {
      const body = await readFile(candidate);
      response.writeHead(200, {
        "content-type": types[extname(candidate)] ?? "application/octet-stream",
      });
      response.end(body);
      return;
    } catch {
      // try the next candidate
    }
  }
  response.writeHead(404).end("not found");
}).listen(port, "127.0.0.1", () => {
  console.log(`serving ${root} on http://localhost:${port}`);
});
