import { onUnmounted, ref, shallowRef, markRaw } from "vue";
import { useData } from "vitepress";
import { patcherI18n } from "./patcher-i18n.js";

export function usePatcherWorker(WorkerFactory, { onError, onProgress, onCustom } = {}) {
  const { lang } = useData();
  const i18n = () => (lang.value?.startsWith("zh") ? patcherI18n.zh : patcherI18n.en);

  const ready = ref(false);
  const loading = ref(false);
  const busy = ref(false);
  const progress = ref(0);
  const status = ref("");
  const logs = ref([]);

  const worker = shallowRef(null);
  let terminated = false;

  function addLog(message) {
    logs.value.push(`[${new Date().toLocaleTimeString()}] ${message}`);
  }

  function setStatus(message) {
    status.value = message;
  }

  function fail(message) {
    busy.value = false;
    loading.value = false;
    const text = `${i18n().failed}: ${message}`;
    setStatus(text);
    addLog(text);
    onError?.(message);
  }

  function handleMessage({ data }) {
    switch (data.type) {
      case "ready":
        ready.value = true;
        loading.value = false;
        setStatus(i18n().ready);
        addLog(i18n().ready);
        break;
      case "progress":
        progress.value = data.percent;
        if (onProgress) {
          onProgress(data, { addLog, setStatus });
        } else {
          setStatus(data.message);
          addLog(`${data.percent}% ${data.message}`);
        }
        break;
      case "done":
        download(data.buffer);
        break;
      case "error":
        fail(data.message);
        break;
      default:
        onCustom?.(data, { addLog, setStatus });
    }
  }

  function download(buffer, filename = "patched.img") {
    try {
      const url = URL.createObjectURL(new Blob([buffer], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      progress.value = 100;
      setStatus(i18n().done);
      addLog(i18n().done);
    } catch (err) {
      fail(err instanceof Error ? err.message : String(err));
    } finally {
      busy.value = false;
    }
  }

  function start() {
    if (worker.value || loading.value || terminated) return;
    loading.value = true;
    setStatus(i18n().loading);
    addLog(i18n().loading);
    const w = WorkerFactory();
    w.onmessage = handleMessage;
    w.onerror = ({ message }) => fail(message);
    worker.value = markRaw(w);
  }

  function post(message, transfer = []) {
    if (!worker.value) return;
    busy.value = true;
    progress.value = 0;
    logs.value = [];
    worker.value.postMessage(message, transfer);
  }

  function reset() {
    worker.value?.terminate();
    worker.value = null;
    ready.value = false;
    loading.value = false;
    busy.value = false;
    progress.value = 0;
    status.value = "";
    logs.value = [];
  }

  onUnmounted(() => {
    terminated = true;
    worker.value?.terminate();
  });

  return {
    ready,
    loading,
    busy,
    progress,
    status,
    logs,
    i18n,
    addLog,
    setStatus,
    fail,
    download,
    start,
    post,
    reset,
  };
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}
