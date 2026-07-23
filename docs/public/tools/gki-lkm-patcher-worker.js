import init, { set_progress_callback } from "/tools/gki-lkm-patcher.js";

let wasm;
const artifactsBase =
  "https://api.shiina.xyz/proxy?url=https://nightly.link/ReSukiSU/ReSukiSU/workflows/build-manager/main";
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

  const minimumEocdSize = 22;
  const maximumCommentSize = 0xffff;
  const eocdSearchStart = Math.max(
    0,
    data.length - minimumEocdSize - maximumCommentSize,
  );
  let eocdOffset = -1;
  for (let i = data.length - minimumEocdSize; i >= eocdSearchStart; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) throw new Error("zip_eocd_not_found");

  const entryCount = view.getUint16(eocdOffset + 10, true);
  const centralDirectorySize = view.getUint32(eocdOffset + 12, true);
  const centralDirectoryOffset = view.getUint32(eocdOffset + 16, true);
  if (
    entryCount === 0xffff ||
    centralDirectorySize === 0xffffffff ||
    centralDirectoryOffset === 0xffffffff
  ) {
    throw new Error("zip64_not_supported");
  }
  if (
    centralDirectoryOffset + centralDirectorySize > data.length ||
    centralDirectoryOffset + centralDirectorySize > eocdOffset
  ) {
    throw new Error("invalid_central_directory");
  }

  let offset = centralDirectoryOffset;
  for (let entry = 0; entry < entryCount; entry++) {
    if (
      offset + 46 > data.length ||
      view.getUint32(offset, true) !== 0x02014b50
    ) {
      throw new Error("invalid_central_directory_entry");
    }

    const method = view.getUint16(offset + 10, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localHeaderOffset = view.getUint32(offset + 42, true);
    if (
      compressedSize === 0xffffffff ||
      uncompressedSize === 0xffffffff ||
      localHeaderOffset === 0xffffffff
    ) {
      throw new Error("zip64_not_supported");
    }

    const nameStart = offset + 46;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > data.length) throw new Error("invalid_zip_entry_name");
    const name = new TextDecoder().decode(data.subarray(nameStart, nameEnd));

    if (name.endsWith(wanted)) {
      if (
        localHeaderOffset + 30 > data.length ||
        view.getUint32(localHeaderOffset, true) !== 0x04034b50
      ) {
        throw new Error("invalid_local_file_header");
      }

      const localNameLength = view.getUint16(localHeaderOffset + 26, true);
      const localExtraLength = view.getUint16(localHeaderOffset + 28, true);
      const payloadStart =
        localHeaderOffset + 30 + localNameLength + localExtraLength;
      const payloadEnd = payloadStart + compressedSize;
      if (payloadEnd > data.length) throw new Error("truncated_zip_entry");

      const payload = data.slice(payloadStart, payloadEnd);
      if (method === 0) {
        if (payload.length !== uncompressedSize) {
          throw new Error("stored_entry_size_mismatch");
        }
        return payload;
      }
      if (method === 8) {
        const output = new Uint8Array(
          await new Response(
            new Blob([payload])
              .stream()
              .pipeThrough(new DecompressionStream("deflate-raw")),
          ).arrayBuffer(),
        );
        if (output.length !== uncompressedSize) {
          throw new Error("deflated_entry_size_mismatch");
        }
        return output;
      }
      throw new Error(`unsupported_zip_compression:${method}`);
    }

    offset = nameEnd + extraLength + commentLength;
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
  wasm = await init("/tools/gki-lkm-patcher.wasm");
  set_progress_callback((message, percent) => {
    self.postMessage({ type: "progress", percent, message });
  });
  self.postMessage({ type: "ready" });
})().catch((error) => {
  console.error("Failed to initialize GKI LKM patch worker", error);
  self.postMessage({
    type: "error",
    message: `wasm_initialization_error; url=/tools/gki-lkm-patcher.wasm; cause=${error?.message || String(error)}`,
  });
});
