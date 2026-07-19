let wasm;
const artifactsBase =
  "https://nightly.link/ReSukiSU/ReSukiSU/workflows/build-manager/main";
const text = (p, n) =>
  new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, p, n));
const copyIn = (bytes) => {
  const p = wasm.alloc(bytes.length);
  new Uint8Array(wasm.memory.buffer, p, bytes.length).set(bytes);
  return p;
};

async function unzipFile(buffer, wanted) {
  const data = new Uint8Array(buffer);
  const view = new DataView(buffer);
  for (let i = 0; i + 30 < data.length; i++) {
    if (view.getUint32(i, true) !== 0x04034b50) continue;
    const method = view.getUint16(i + 8, true),
      size = view.getUint32(i + 18, true);
    const nameLen = view.getUint16(i + 26, true),
      extraLen = view.getUint16(i + 28, true);
    const name = new TextDecoder().decode(
      data.subarray(i + 30, i + 30 + nameLen),
    );
    const start = i + 30 + nameLen + extraLen;
    if (!name.endsWith(wanted)) {
      i = start + size - 1;
      continue;
    }
    const payload = data.slice(start, start + size);
    if (method === 0) return payload;
    if (method === 8)
      return new Uint8Array(
        await new Response(
          new Blob([payload])
            .stream()
            .pipeThrough(new DecompressionStream("deflate-raw")),
        ).arrayBuffer(),
      );
    throw new Error("unsupported_zip_compression");
  }
  throw new Error(`artifact_file_missing:${wanted}`);
}
async function artifact(name, file) {
  const url = `${artifactsBase}/${name}.zip`;
  let response;
  try {
    response = await fetch(url, {
      cache: "no-store",
      credentials: "omit",
    });
  } catch (error) {
    throw new Error(
      [
        `artifact_download_network_error`,
        `artifact=${name}`,
        `url=${url}`,
        `cause=${error?.message || String(error)}`,
        "hint=The browser may have blocked the request because of CORS, DNS, TLS, an extension, or an offline network. Check the browser DevTools Console and Network panel for the exact browser diagnostic.",
      ].join("; "),
    );
  }
  if (!response.ok) {
    throw new Error(
      [
        "artifact_download_http_error",
        `artifact=${name}`,
        `url=${response.url || url}`,
        `status=${response.status}`,
        `statusText=${response.statusText || "unknown"}`,
        `redirected=${response.redirected}`,
      ].join("; "),
    );
  }
  try {
    return unzipFile(await response.arrayBuffer(), file);
  } catch (error) {
    throw new Error(
      [
        "artifact_archive_error",
        `artifact=${name}`,
        `url=${response.url || url}`,
        `cause=${error?.message || String(error)}`,
      ].join("; "),
    );
  }
}
self.onmessage = async ({ data }) => {
  let phase = data.type || "unknown";
  let activeKmi = data.kmi || "auto-detect";
  try {
    const image = new Uint8Array(data.image);
    if (data.type === "detect_kmi") {
      self.postMessage({ type: "progress", percent: 5, message: "detect_kmi" });
      const p = copyIn(image);
      if (wasm.detect_kmi(p, image.length) !== 1) {
        self.postMessage({ type: "kmi_required" });
        return;
      }
      self.postMessage({
        type: "kmi_detected",
        kmi: text(wasm.result_ptr(), wasm.result_len()),
      });
      return;
    }

    let kmi = data.kmi;
    if (!kmi) throw new Error("kmi_required");
    activeKmi = kmi;
    self.postMessage({ type: "kmi", kmi });
    self.postMessage({
      type: "progress",
      percent: 25,
      message: "download_assets",
    });
    phase = "download_assets";
    const [module, init] = await Promise.all([
      artifact(`${kmi}-lkm`, `${kmi}_kernelsu.ko`),
      artifact("ksuinit", "ksuinit"),
    ]);
    const ip = copyIn(image),
      mp = copyIn(module),
      kp = copyIn(init);
    if (
      wasm.patch_lkm(ip, image.length, mp, module.length, kp, init.length) !== 1
    )
      throw new Error(text(wasm.error_ptr(), wasm.error_len()));
    const output = new Uint8Array(
      wasm.memory.buffer,
      wasm.result_ptr(),
      wasm.result_len(),
    ).slice();
    self.postMessage({ type: "done", buffer: output.buffer }, [output.buffer]);
  } catch (error) {
    const cause = error?.message || String(error);
    const details = [
      "gki_lkm_patch_failed",
      `phase=${phase}`,
      `kmi=${activeKmi}`,
      `cause=${cause}`,
    ];
    if (phase === "download_assets") {
      details.push(
        `lkm_url=${artifactsBase}/${activeKmi}-lkm.zip`,
        `ksuinit_url=${artifactsBase}/ksuinit.zip`,
        "hint=Open both URLs directly and inspect the DevTools Network panel. If direct navigation works but fetch fails, the remote server or redirect target is blocking CORS.",
      );
    }
    const message = details.join("; ");
    console.error(message);
    if (error?.stack) console.error(error.stack);
    self.postMessage({
      type: "error",
      message,
    });
  }
};
(async () => {
  const response = await fetch("/tools/gki-lkm-patcher.wasm");
  const imports = {
    env: {
      report_progress(p, n, percent) {
        self.postMessage({ type: "progress", percent, message: text(p, n) });
      },
    },
  };
  wasm = (await WebAssembly.instantiate(await response.arrayBuffer(), imports))
    .instance.exports;
  self.postMessage({ type: "ready" });
})().catch((error) => {
  console.error("Failed to initialize GKI LKM patch worker", error);
  self.postMessage({
    type: "error",
    message: `wasm_initialization_error; url=/tools/gki-lkm-patcher.wasm; cause=${error?.message || String(error)}`,
  });
});
