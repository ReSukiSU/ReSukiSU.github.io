import init, { set_progress_callback } from "/tools/vivo-vr-patcher.js";

let wasm;

function wasmText(pointer, length) {
  return new TextDecoder().decode(
    new Uint8Array(wasm.memory.buffer, pointer, length),
  );
}

async function initialize() {
  wasm = await init("/tools/vivo-vr-patcher.wasm");
  set_progress_callback((message, percent) => {
    self.postMessage({ type: "progress", message, percent });
  });
  self.postMessage({ type: "ready" });
}

self.onmessage = async ({ data }) => {
  if (data.type !== "patch" || !wasm) return;
  try {
    const input = new Uint8Array(data.buffer);
    const pointer = wasm.alloc(input.byteLength);
    new Uint8Array(wasm.memory.buffer, pointer, input.byteLength).set(input);
    if (wasm.patch_vr(pointer, input.byteLength) !== 1) {
      throw new Error(wasmText(wasm.error_ptr(), wasm.error_len()));
    }
    const output = new Uint8Array(
      wasm.memory.buffer,
      wasm.result_ptr(),
      wasm.result_len(),
    ).slice();
    self.postMessage({ type: "done", buffer: output.buffer }, [output.buffer]);
  } catch (error) {
    self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};

initialize().catch((error) => {
  self.postMessage({
    type: "error",
    message: error instanceof Error ? error.message : String(error),
  });
});
