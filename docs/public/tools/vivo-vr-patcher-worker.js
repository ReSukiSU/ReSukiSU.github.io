let wasm;

function wasmText(pointer, length) {
  return new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, pointer, length));
}

async function initialize() {
  const response = await fetch("/tools/vivo-vr-patcher.wasm");
  if (!response.ok) throw new Error(`WASM Download FAILED! HTTP result: ${response.status}`);
  const imports = {
    env: {
      report_progress(pointer, length, percent) {
        self.postMessage({ type: "progress", message: wasmText(pointer, length), percent });
      },
    },
  };
  const instance = await WebAssembly.instantiate(await response.arrayBuffer(), imports);
  wasm = instance.instance.exports;
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
    const output = new Uint8Array(wasm.memory.buffer, wasm.result_ptr(), wasm.result_len()).slice();
    self.postMessage({ type: "done", buffer: output.buffer }, [output.buffer]);
  } catch (error) {
    self.postMessage({ type: "error", message: error instanceof Error ? error.message : String(error) });
  }
};

initialize().catch((error) => {
  self.postMessage({ type: "error", message: error instanceof Error ? error.message : String(error) });
});
