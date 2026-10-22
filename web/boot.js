// Loads the wasm bundle. Kept out of index.html so the page can run under a
// Content-Security-Policy without allowing inline scripts.
import init from "./pkg/pigeons_web.js";

init().catch((error) => {
  const node = document.getElementById("boot-error");
  node.className = "boot-error visible";
  node.textContent = `could not start: ${error}`;
});
