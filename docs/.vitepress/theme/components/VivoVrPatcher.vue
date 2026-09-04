<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { useData } from "vitepress";
import { usePatcherWorker, formatBytes } from "../composables/usePatcherWorker.js";
import VivoVrWorker from "../workers/vivo-vr-patcher.worker.js?worker";
import { vivoVrI18n } from "../composables/patcher-i18n.js";
import "../styles/patcher.css";

const { lang } = useData();
const isZh = computed(() => lang.value?.startsWith("zh"));
const t = computed(() => (isZh.value ? vivoVrI18n.zh : vivoVrI18n.en));

const file = ref(null);
const dragging = ref(false);
const fileInput = ref(null);
let dragDepth = 0;
let pendingAuto = false;

function localizeError(value) {
  const [code, detail] = value.split(/:(.*)/s);
  const translated = t.value.errors[code];
  if (!translated) return value;
  return detail ? `${translated}: ${detail}` : translated;
}

function localizeProgress(value) {
  if (t.value.progress[value]) return t.value.progress[value];
  const [kind, detail] = value.split(/:(.*)/s);
  if (kind === "removed") return `${t.value.removed} ${detail}`;
  if (kind === "not_found") return `${t.value.not_found} ${detail}`;
  if (kind === "cleaned") return `${t.value.cleaned} ${detail}`;
  return value;
}

const { ready, busy, progress, status, logs, i18n, addLog, setStatus, start, post, fail } =
  usePatcherWorker(() => new VivoVrWorker(), {
    onProgress: (data, { addLog: log, setStatus }) => {
      const msg = localizeProgress(data.message);
      setStatus(msg);
      log(`${data.percent}% ${msg}`);
    },
    onError: (msg) => fail(localizeError(msg)),
  });

onMounted(() => start());

function patch(f) {
  if (!f || busy.value) return;
  pendingAuto = false;
  addLog(`${i18n().started} ${f.name}`);
  f.arrayBuffer().then((buf) => {
    post({ type: "patch", buffer: buf }, [buf]);
  });
}

function onFilePicked(f) {
  if (!f || busy.value) return;
  file.value = f;
  addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
  // No button — patching starts immediately once the worker is ready.
  if (ready.value) patch(f);
  else pendingAuto = true;
}

// Worker loads async; start the pending patch as soon as it's ready.
watch(ready, (ok) => {
  if (ok && pendingAuto && file.value) patch(file.value);
});

function onInputChange(event) {
  onFilePicked(event.target.files?.[0] ?? null);
  if (event.target.value) event.target.value = "";
}

function onKeydown(event) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.value?.click();
  }
}

function onDragEnter(event) {
  event.preventDefault();
  dragDepth++;
  dragging.value = true;
}

function onDragOver(event) {
  event.preventDefault();
  dragging.value = true;
}

function onDragLeave(event) {
  event.preventDefault();
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) dragging.value = false;
}

function onDrop(event) {
  event.preventDefault();
  dragDepth = 0;
  dragging.value = false;
  onFilePicked(event.dataTransfer?.files?.[0] ?? null);
}

function clearFile(event) {
  event.preventDefault();
  file.value = null;
  pendingAuto = false;
  progress.value = 0;
  setStatus("");
}

const isError = computed(() => status.value.startsWith(i18n().failed));
const isDone = computed(() => progress.value === 100 && !isError.value);
const dropHint = computed(() => {
  if (dragging.value) return i18n().drop;
  if (busy.value) return t.value.working;
  if (isDone.value) return t.value.doneHint;
  return t.value.choose;
});
</script>

<template>
  <div class="pt">
    <div class="pt-head">
      <p class="pt-title">{{ t.summary }}</p>
      <span class="pt-pill" :class="{ ready: ready && !busy, busy }">
        <span class="dot"></span>
        {{ busy ? i18n().processing : ready ? i18n().ready : i18n().loading }}
      </span>
    </div>
    <div class="pt-body">
      <p class="pt-desc">{{ t.intro }}</p>

    <label
      class="pt-drop"
      :class="{ dragging, disabled: !ready || busy, 'has-file': !!file }"
      tabindex="0"
      @keydown="onKeydown"
      @dragenter="onDragEnter"
      @dragover="onDragOver"
      @dragleave="onDragLeave"
      @drop="onDrop"
    >
      <span class="pt-drop-icon" aria-hidden="true">
        <i v-if="isDone" class="ri-checkbox-circle-line ok"></i>
        <i v-else-if="busy" class="ri-loader-4-line pt-spin-icon"></i>
        <i v-else-if="dragging" class="ri-download-cloud-2-line"></i>
        <i v-else class="ri-upload-cloud-2-line"></i>
      </span>
      <span v-if="!file" class="pt-drop-hint">{{ dropHint }}</span>
      <span v-if="!file" class="pt-drop-sub">{{ i18n().drop }} · .img</span>
      <span v-if="file" class="pt-file">
        <span class="name">{{ file.name }}</span>
        <span class="size">{{ formatBytes(file.size) }}</span>
        <button v-if="!busy" type="button" :aria-label="i18n().remove" @click="clearFile">×</button>
      </span>
      <span v-if="file && !busy" class="pt-drop-sub">{{ dropHint }}</span>
      <input
        ref="fileInput"
        type="file"
        accept=".img,application/octet-stream"
        :disabled="!ready || busy"
        tabindex="-1"
        @change="onInputChange"
      />
    </label>

    <div
      class="pt-progress"
      role="progressbar"
      :aria-valuenow="progress"
      aria-valuemin="0"
      aria-valuemax="100"
    >
      <div class="pt-track">
        <div
          class="pt-fill"
          :class="{ error: isError, done: isDone }"
          :style="{ width: `${progress}%` }"
        ></div>
      </div>
      <span class="pt-pct">{{ progress }}%</span>
    </div>

    <p class="pt-status" :class="{ error: isError }" aria-live="polite">
      {{ status || i18n().idle }}
    </p>

    <details v-if="logs.length" class="pt-logs">
      <summary>{{ i18n().logLabel }} ({{ logs.length }})</summary>
      <pre><code>{{ logs.join("\n") }}</code></pre>
    </details>
    </div>
    <div class="pt-foot">
      <p class="pt-warn">{{ i18n().warning }}</p>
    </div>
  </div>
</template>
