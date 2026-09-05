import * as wasm from "../wasm/gki-lkm-patcher/gki_lkm_patcher_bg.wasm";
import { set_progress_callback } from "../wasm/gki-lkm-patcher/gki_lkm_patcher.js";

const memory = () => new Uint8Array(wasm.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(memory().subarray(ptr, ptr + len));
const copyIn = (bytes) => {
  const ptr = wasm.alloc(bytes.length);
  memory().set(bytes, ptr);
  return ptr;
};

const ARTIFACTS_BASE =
  "https://api.shiina.xyz/proxy?url=https://nightly.link/ReSukiSU/ReSukiSU/workflows/build-manager/main";

async function unzipEntry(buffer, wanted) {
  const data = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const EOCD = 0x06054b50;
  const CD_ENTRY = 0x02014b50;
  const LFH = 0x04034b50;
  const MIN_EOCD = 22;
  const MAX_COMMENT = 0xffff;
  const searchStart = Math.max(0, data.length - MIN_EOCD - MAX_COMMENT);
  let eocd = -1;
  for (let i = data.length - MIN_EOCD; i >= searchStart; i--) {
    if (view.getUint32(i, true) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip_eocd_not_found");
  const count = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOff = view.getUint32(eocd + 16, true);
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff)
    throw new Error("zip64_not_supported");
  if (cdOff + cdSize > data.length || cdOff + cdSize > eocd)
    throw new Error("invalid_central_directory");

  let off = cdOff;
  for (let i = 0; i < count; i++) {
    if (off + 46 > data.length || view.getUint32(off, true) !== CD_ENTRY)
      throw new Error("invalid_central_directory_entry");
    const method = view.getUint16(off + 10, true);
    const compSize = view.getUint32(off + 20, true);
    const uncompSize = view.getUint32(off + 24, true);
    const nameLen = view.getUint16(off + 28, true);
    const extraLen = view.getUint16(off + 30, true);
    const commentLen = view.getUint16(off + 32, true);
    const lfhOff = view.getUint32(off + 42, true);
    if (compSize === 0xffffffff || uncompSize === 0xffffffff || lfhOff === 0xffffffff)
      throw new Error("zip64_not_supported");
    const nameStart = off + 46;
    const nameEnd = nameStart + nameLen;
    if (nameEnd > data.length) throw new Error("invalid_zip_entry_name");
    const name = new TextDecoder().decode(data.subarray(nameStart, nameEnd));
    if (name.endsWith(wanted)) {
      if (lfhOff + 30 > data.length || view.getUint32(lfhOff, true) !== LFH)
        throw new Error("invalid_local_file_header");
      const lNameLen = view.getUint16(lfhOff + 26, true);
      const lExtraLen = view.getUint16(lfhOff + 28, true);
      const payloadStart = lfhOff + 30 + lNameLen + lExtraLen;
      const payloadEnd = payloadStart + compSize;
      if (payloadEnd > data.length) throw new Error("truncated_zip_entry");
      const payload = data.slice(payloadStart, payloadEnd);
      if (method === 0) {
        if (payload.length !== uncompSize) throw new Error("stored_entry_size_mismatch");
        return payload;
      }
      if (method === 8) {
        const out = new Uint8Array(
          await new Response(
            new Blob([payload]).stream().pipeThrough(new DecompressionStream("deflate-raw")),
          ).arrayBuffer(),
        );
        if (out.length !== uncompSize) throw new Error("deflated_entry_size_mismatch");
        return out;
      }
      throw new Error(`unsupported_zip_compression:${method}`);
    }
    off = nameEnd + extraLen + commentLen;
  }
  throw new Error(`artifact_file_missing:${wanted}`);
}

async function fetchArtifact(name, file) {
  const url = `${ARTIFACTS_BASE}/${name}.zip`;
  let res;
  try {
    res = await fetch(url, { cache: "no-store", credentials: "omit" });
  } catch (err) {
    throw new Error(
      [
        "artifact_download_network_error",
        `artifact=${name}`,
        `url=${url}`,
        `cause=${err?.message || String(err)}`,
        "hint=Browser may have blocked the request (CORS/DNS/TLS/extension/offline). Check DevTools.",
      ].join("; "),
    );
  }
  if (!res.ok) {
    throw new Error(
      [
        "artifact_download_http_error",
        `artifact=${name}`,
        `url=${res.url || url}`,
        `status=${res.status}`,
        `statusText=${res.statusText || "unknown"}`,
        `redirected=${res.redirected}`,
      ].join("; "),
    );
  }
  try {
    return unzipEntry(await res.arrayBuffer(), file);
  } catch (err) {
    throw new Error(
      [
        "artifact_archive_error",
        `artifact=${name}`,
        `url=${res.url || url}`,
        `cause=${err?.message || String(err)}`,
      ].join("; "),
    );
  }
}

set_progress_callback((message, percent) =>
  self.postMessage({ type: "progress", percent, message }),
);

self.postMessage({ type: "ready" });

self.onmessage = async ({ data }) => {
  let phase = data.type || "unknown";
  let activeKmi = data.kmi || "auto-detect";
  let activeArch = data.arch || "aarch64";
  try {
    const image = new Uint8Array(data.image);
    if (data.type === "detect_kmi") {
      self.postMessage({ type: "progress", percent: 5, message: "detect_kmi" });
      const ptr = copyIn(image);
      if (wasm.detect_kmi(ptr, image.length) !== 1) {
        self.postMessage({ type: "kmi_required" });
        return;
      }
      self.postMessage({
        type: "kmi_detected",
        kmi: text(wasm.result_ptr(), wasm.result_len()),
      });
      return;
    }

    const kmi = data.kmi;
    const arch = data.arch;
    if (!kmi) throw new Error("kmi_required");
    if (!arch) throw new Error("arch_required");
    activeKmi = kmi;
    activeArch = arch;
    self.postMessage({ type: "kmi", kmi });
    self.postMessage({ type: "arch", arch });
    self.postMessage({ type: "progress", percent: 25, message: "download_assets" });
    phase = "download_assets";
    const [module, init] = await Promise.all([
      fetchArtifact(`${activeArch}-${kmi}-lkm`, `${kmi}_kernelsu.ko`),
      fetchArtifact(`ksuinit-${activeArch}`, "ksuinit"),
    ]);
    const ip = copyIn(image);
    const mp = copyIn(module);
    const kp = copyIn(init);
    if (wasm.patch_lkm(ip, image.length, mp, module.length, kp, init.length) !== 1)
      throw new Error(text(wasm.error_ptr(), wasm.error_len()));
    const out = memory()
      .subarray(wasm.result_ptr(), wasm.result_ptr() + wasm.result_len())
      .slice();
    self.postMessage({ type: "done", buffer: out.buffer }, [out.buffer]);
  } catch (err) {
    const cause = err?.message || String(err);
    const details = [
      "gki_lkm_patch_failed",
      `phase=${phase}`,
      `kmi=${activeKmi}`,
      `cause=${cause}`,
    ];
    if (phase === "download_assets") {
      details.push(
        `lkm_url=${ARTIFACTS_BASE}/${activeArch}-${activeKmi}-lkm.zip`,
        `ksuinit_url=${ARTIFACTS_BASE}/ksuinit-${activeArch}.zip`,
        "hint=Open both URLs directly; check DevTools Network. If direct navigation works but fetch fails, remote is blocking CORS.",
      );
    }
    const message = details.join("; ");
    console.error(message, err?.stack || "");
    self.postMessage({ type: "error", message });
  }
};
