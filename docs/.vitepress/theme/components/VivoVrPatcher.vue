<script setup>
import { computed, ref } from "vue";
import { useData } from "vitepress";

const { lang } = useData();
const messages = {
  zh: {
    summary: "在 vendor_boot 中移除 vr.ko",
    intro:
      "文件仅在本机浏览器中处理，不会上传到服务器。工具会直接删除 vr.ko文件，并清理相关的 modules.* 索引记录。",
    choose: "选择 vendor_boot.img",
    patch: "移除 vr.ko 并下载",
    processing: "处理中…",
    idle: "空闲",
    loading: "正在加载工具…",
    ready: "工具已就绪，请上传 vendor_boot 分区镜像。",
    selected: "已选择",
    working: "正在解析并重打包镜像，请勿关闭页面…",
    failed: "处理失败",
    loaded: "工具加载完成",
    started: "开始处理",
    done: "处理完成，已请求下载修补后的 vendor_boot 分区镜像。",
    logLabel: "修补日志",
    warning:
      "刷写错误或不匹配的镜像可能导致设备无法启动。请先备份原始 vendor_boot，并确认镜像与当前系统版本一致。",
    progress: {
      parse_image: "正在解析 vendor_boot 镜像",
      find_ramdisk: "正在查找目标 vendor ramdisk",
      decompress_ramdisk: "正在解压 vendor ramdisk",
      parse_cpio: "正在解析 ramdisk",
      remove_module: "正在删除 vr.ko 并清理模块索引",
      rebuild_cpio: "正在重建 ramdisk",
      repack_image: "正在重打包 vendor_boot 镜像",
      complete: "修补完成",
    },
    errors: {
      parse_boot_image: "无法解析 vendor_boot 镜像",
      missing_ramdisk: "镜像中没有 ramdisk",
      not_vendor_boot_v4:
        "上传的镜像不是带 vendor ramdisk table 的 vendor_boot v4 镜像",
      missing_vendor_ramdisk_entry: "找不到可修改的 vendor ramdisk 条目",
      decompress_vendor_ramdisk: "解压 vendor ramdisk 失败",
      parse_vendor_ramdisk_cpio: "解析 vendor ramdisk CPIO 失败",
      rebuild_cpio: "重建 cpio 失败",
      repack_vendor_boot: "重打包 vendor_boot 失败",
      invalid_index_file: "无效的模块索引文件",
    },
    removed: "已删除",
    not_found: "未发现 vr.ko：",
    cleaned: "已清理",
  },
  en: {
    summary: "Remove vr.ko from vendor_boot",
    intro:
      "The file is processed locally in your browser and is never uploaded. The tool removes vr.ko and cleans its modules.* index entries.",
    choose: "Choose vendor_boot.img",
    patch: "Remove vr.ko and download",
    processing: "Processing…",
    idle: "Idle",
    loading: "Loading tool…",
    ready: "Tool ready. Please upload a vendor_boot partition image.",
    selected: "Selected",
    working: "Parsing and repacking the image. Keep this page open…",
    failed: "Patch failed",
    loaded: "Tool loaded",
    started: "Starting processing",
    done: "Processing complete. The patched vendor_boot image download has been requested.",
    logLabel: "Patch log",
    warning:
      "Flashing an incorrect or mismatched image may prevent the device from booting. Back up the original vendor_boot and ensure the image matches the installed firmware.",
    progress: {
      parse_image: "Parsing vendor_boot image",
      find_ramdisk: "Finding the target vendor ramdisk",
      decompress_ramdisk: "Decompressing vendor ramdisk",
      parse_cpio: "Parsing ramdisk",
      remove_module: "Removing vr.ko and cleaning module indexes",
      rebuild_cpio: "Rebuilding ramdisk",
      repack_image: "Repacking vendor_boot image",
      complete: "Patch complete",
    },
    errors: {
      parse_boot_image: "Unable to parse the vendor_boot image",
      missing_ramdisk: "The image has no ramdisk",
      not_vendor_boot_v4:
        "The uploaded image is not a vendor_boot v4 image with a vendor ramdisk table",
      missing_vendor_ramdisk_entry:
        "No patchable vendor ramdisk entry was found",
      decompress_vendor_ramdisk: "Failed to decompress the vendor ramdisk",
      parse_vendor_ramdisk_cpio: "Failed to parse the vendor ramdisk CPIO",
      rebuild_cpio: "Failed to rebuild the CPIO",
      repack_vendor_boot: "Failed to repack vendor_boot",
      invalid_index_file: "Invalid module index file",
    },
    removed: "Removed",
    not_found: "vr.ko not found in",
    cleaned: "Cleaned",
  },
};
const t = computed(() =>
  lang.value?.startsWith("zh") ? messages.zh : messages.en,
);

const initialized = ref(false);
const loading = ref(false);
const processing = ref(false);
const progress = ref(0);
const logs = ref([]);
const status = ref("");
const selectedFile = ref(null);
let worker;

function initialize(event) {
  if (!event.currentTarget.open || initialized.value || loading.value) return;
  loading.value = true;
  status.value = t.value.loading;
  try {
    worker = new Worker("/tools/vivo-vr-patcher-worker.js?v=20260723-1", {
      type: "module",
    });
    worker.onmessage = handleWorkerMessage;
    worker.onerror = ({ message }) => handleError(message);
  } catch (error) {
    handleError(error instanceof Error ? error.message : String(error));
  }
}

function addLog(message) {
  logs.value.push(`[${new Date().toLocaleTimeString()}] ${message}`);
}

function handleError(message) {
  processing.value = false;
  loading.value = false;
  status.value = `${t.value.failed}: ${localizeError(message)}`;
  addLog(status.value);
}

function localizeError(value) {
  const [code, detail] = value.split(/:(.*)/s);
  const translated = t.value.errors[code];
  if (!translated) return value;
  return detail ? `${translated}: ${detail}` : translated;
}

function handleWorkerMessage({ data }) {
  if (data.type === "ready") {
    initialized.value = true;
    loading.value = false;
    status.value = t.value.ready;
    addLog(t.value.loaded);
  } else if (data.type === "progress") {
    progress.value = data.percent;
    const message = localizeProgress(data.message);
    status.value = message;
    addLog(`${data.percent}% ${message}`);
  } else if (data.type === "done") {
    downloadResult(data.buffer);
  } else if (data.type === "error") {
    handleError(data.message);
  }
}

function localizeProgress(value) {
  if (t.value.progress[value]) return t.value.progress[value];
  const [kind, detail] = value.split(/:(.*)/s);
  if (kind === "removed") return `${t.value.removed} ${detail}`;
  if (kind === "not_found") return `${t.value.not_found} ${detail}`;
  if (kind === "cleaned") return `${t.value.cleaned} ${detail}`;
  return value;
}

function chooseFile(event) {
  selectedFile.value = event.target.files?.[0] ?? null;
  if (selectedFile.value)
    status.value = `${t.value.selected} ${selectedFile.value.name}`;
}

async function patch() {
  if (!worker || !selectedFile.value || processing.value) return;
  processing.value = true;
  progress.value = 0;
  logs.value = [];
  status.value = t.value.working;
  addLog(
    `${t.value.started} ${selectedFile.value.name} (${(selectedFile.value.size / 1024 / 1024).toFixed(2)} MiB)`,
  );
  try {
    const buffer = await selectedFile.value.arrayBuffer();
    worker.postMessage({ type: "patch", buffer }, [buffer]);
  } catch (error) {
    handleError(error instanceof Error ? error.message : String(error));
  }
}

function downloadResult(buffer) {
  try {
    const url = URL.createObjectURL(
      new Blob([buffer], { type: "application/octet-stream" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "vendor_boot_no_vr.img";
    link.click();
    URL.revokeObjectURL(url);
    progress.value = 100;
    status.value = t.value.done;
    addLog(status.value);
  } catch (error) {
    handleError(error instanceof Error ? error.message : String(error));
  } finally {
    processing.value = false;
  }
}
</script>

<template>
  <details class="vivo-vr-tool" @toggle="initialize">
    <summary>{{ t.summary }}</summary>
    <div class="tool-body">
      <p>{{ t.intro }}</p>
      <label class="file-picker">
        <span>{{ t.choose }}</span>
        <input
          type="file"
          accept=".img,application/octet-stream"
          :disabled="!initialized || processing"
          @change="chooseFile"
        />
      </label>
      <button
        type="button"
        :disabled="!initialized || !selectedFile || processing"
        @click="patch"
      >
        {{ processing ? t.processing : t.patch }}
      </button>
      <div
        class="progress-row"
        role="progressbar"
        :aria-valuenow="progress"
        aria-valuemin="0"
        aria-valuemax="100"
      >
        <div class="progress-track">
          <div class="progress-value" :style="{ width: `${progress}%` }"></div>
        </div>
        <span>{{ progress }}%</span>
      </div>
      <p class="status" aria-live="polite">{{ status || t.idle }}</p>
      <pre
        v-if="logs.length"
        class="logs"
        :aria-label="t.logLabel"
      ><code>{{ logs.join("\n") }}</code></pre>
      <p class="danger">{{ t.warning }}</p>
    </div>
  </details>
</template>

<style scoped>
.vivo-vr-tool {
  margin: 24px 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg-soft);
}
.vivo-vr-tool summary {
  padding: 16px 18px;
  cursor: pointer;
  color: var(--vp-c-brand-1);
  font-weight: 600;
}
.tool-body {
  padding: 0 18px 18px;
}
.file-picker {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin: 16px 0;
}
.file-picker span,
button {
  display: inline-flex;
  border: 0;
  border-radius: 8px;
  padding: 10px 14px;
  background: var(--vp-c-brand-3);
  color: white;
  font-weight: 600;
}
.file-picker input {
  max-width: 100%;
}
button {
  cursor: pointer;
}
button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
.status {
  color: var(--vp-c-text-2);
}
.progress-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 16px;
}
.progress-track {
  height: 10px;
  flex: 1;
  overflow: hidden;
  border-radius: 999px;
  background: var(--vp-c-divider);
}
.progress-value {
  height: 100%;
  border-radius: inherit;
  background: var(--accent-gradient);
  transition: width 0.2s ease;
}
.progress-row span {
  min-width: 3em;
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.logs {
  max-height: 260px;
  overflow: auto;
  padding: 14px;
  border-radius: 8px;
  background: var(--vp-code-block-bg);
  font-size: 13px;
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.danger {
  padding: 12px 14px;
  border-left: 4px solid var(--vp-c-danger-1);
  border-radius: 6px;
  background: var(--vp-c-danger-soft);
  color: var(--vp-c-danger-1);
}
</style>
