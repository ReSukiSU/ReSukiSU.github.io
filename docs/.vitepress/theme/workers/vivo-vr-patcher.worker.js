import * as wasm from "../wasm/vivo-vr-patcher/vivo_vr_patcher_bg.wasm";
import { set_progress_callback } from "../wasm/vivo-vr-patcher/vivo_vr_patcher.js";

const memory = () => new Uint8Array(wasm.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(memory().subarray(ptr, ptr + len));
const copyIn = (bytes) => {
  const ptr = wasm.alloc(bytes.length);
  memory().set(bytes, ptr);
  return ptr;
};

set_progress_callback((message, percent) =>
  self.postMessage({ type: "progress", message, percent }),
);

self.postMessage({ type: "ready" });

self.onmessage = async ({ data }) => {
  if (data.type !== "patch") return;
  try {
    const input = new Uint8Array(data.buffer);
    const ptr = copyIn(input);
    if (wasm.patch_vr(ptr, input.byteLength) !== 1) {
      throw new Error(text(wasm.error_ptr(), wasm.error_len()));
    }
    const out = memory()
      .subarray(wasm.result_ptr(), wasm.result_ptr() + wasm.result_len())
      .slice();
    self.postMessage({ type: "done", buffer: out.buffer }, [out.buffer]);
  } catch (error) {
    self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};
