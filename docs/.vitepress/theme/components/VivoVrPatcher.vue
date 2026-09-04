<script setup>
import { computed, onMounted, ref } from "vue";
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
const dropzone = ref(null);
let dragDepth = 0;

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

const { ready, busy, progress, status, logs, i18n, addLog, start, post, fail } =
  usePatcherWorker(() => new VivoVrWorker(), {
    onProgress: (data, { addLog: log, setStatus }) => {
      const msg = localizeProgress(data.message);
      setStatus(msg);
      log(`${data.percent}% ${msg}`);
    },
    onError: (msg) => fail(localizeError(msg)),
  });

onMounted(() => start());

function onFilePicked(f) {
  if (!f || busy.value) return;
  file.value = f;
  addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
}

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
}

function patch() {
  if (!file.value || busy.value) return;
  const name = file.value.name;
  file.value.arrayBuffer().then((buf) => {
    addLog(`${i18n().started} ${name}`);
    post({ type: "patch", buffer: buf }, [buf]);
  });
}

const isError = computed(() => status.value.startsWith(i18n().failed));
const isDone = computed(() => progress.value === 100 && !isError.value);
</script>

<template>
  <div class="pt">
    <p class="pt-title">{{ t.summary }}</p>
    <p class="pt-desc">{{ t.intro }}</p>

    <label
      ref="dropzone"
      class="pt-drop"
      :class="{ dragging, disabled: !ready || busy }"
      tabindex="0"
      @keydown="onKeydown"
      @dragenter="onDragEnter"
      @dragover="onDragOver"
      @dragleave="onDragLeave"
      @drop="onDrop"
    >
      <span v-if="!file" class="pt-drop-hint">{{ t.choose }}</span>
      <span v-if="!file" class="pt-drop-sub">{{ i18n().drop }} · .img</span>
      <span v-if="file" class="pt-file">
        <span class="name">{{ file.name }}</span>
        <span class="size">{{ formatBytes(file.size) }}</span>
        <button v-if="!busy" type="button" @click="clearFile">{{ i18n().close }}</button>
      </span>
      <input
        ref="fileInput"
        type="file"
        accept=".img,application/octet-stream"
        :disabled="!ready || busy"
        tabindex="-1"
        @change="onInputChange"
      />
    </label>

    <div class="pt-actions">
      <button type="button" class="pt-btn" :disabled="!ready || !file || busy" @click="patch">
        {{ busy ? i18n().processing : t.patch }}
      </button>
    </div>

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
        />
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

    <p class="pt-warn">{{ i18n().warning }}</p>
  </div>
</template>
