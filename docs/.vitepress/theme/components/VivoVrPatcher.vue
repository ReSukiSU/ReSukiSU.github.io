<script setup>
import { computed, ref } from "vue";
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
const showLogs = ref(false);

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

const { ready, loading, busy, progress, status, logs, i18n, addLog, start, post, fail } =
  usePatcherWorker(() => new VivoVrWorker(), {
    onProgress: (data, { addLog: log, setStatus }) => {
      const msg = localizeProgress(data.message);
      setStatus(msg);
      log(`${data.percent}% ${msg}`);
    },
    onError: (msg) => fail(localizeError(msg)),
  });

function onToggle(event) {
  if (!event.currentTarget.open) return;
  start();
}

function onFilePicked(f) {
  file.value = f;
  if (f) addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
}

function onInputChange(event) {
  onFilePicked(event.target.files?.[0] ?? null);
  if (event.target.value) event.target.value = "";
}

function onDrop(event) {
  dragging.value = false;
  const f = event.dataTransfer?.files?.[0];
  if (f) onFilePicked(f);
}

function onDragOver() {
  dragging.value = true;
}

function onDragLeave() {
  dragging.value = false;
}

function patch() {
  if (!file.value || busy.value) return;
  file.value.arrayBuffer().then((buf) => {
    addLog(`${i18n().started} ${file.value.name}`);
    post({ type: "patch", buffer: buf }, [buf]);
  });
}

const statusClass = computed(() => {
  if (status.value.startsWith(i18n().failed)) return "error";
  if (progress.value === 100) return "success";
  return "";
});

const buttonLabel = computed(() => {
  if (busy.value) return i18n().processing;
  return t.value.patch;
});
</script>

<template>
  <details class="patcher" :open="false" @toggle="onToggle">
    <summary>{{ t.summary }}</summary>
    <div class="patcher-body">
      <p class="patcher-intro">{{ t.intro }}</p>

      <div
        class="dropzone"
        :class="{ dragging, disabled: !ready || busy }"
        role="button"
        tabindex="0"
        :aria-label="i18n().choose"
        @dragover.prevent="onDragOver"
        @dragleave.prevent="onDragLeave"
        @drop.prevent="onDrop"
      >
        <span class="dropzone-icon"><i class="ri-upload-cloud-2-line" /></span>
        <span class="dropzone-hint">
          {{ file ? file.name : i18n().drop }}
        </span>
        <span v-if="file" class="dropzone-file">{{ formatBytes(file.size) }}</span>
        <input
          type="file"
          accept=".img,application/octet-stream"
          :disabled="!ready || busy"
          @change="onInputChange"
        />
      </div>

      <div class="patcher-controls">
        <button
          type="button"
          class="patcher-btn"
          :disabled="!ready || !file || busy"
          @click="patch"
        >
          <span v-if="busy" class="spin" />
          {{ buttonLabel }}
        </button>
      </div>

      <div
        class="progress-row"
        role="progressbar"
        :aria-valuenow="progress"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-label="i18n().processing"
      >
        <div class="progress-track">
          <div class="progress-value" :style="{ width: `${progress}%` }" />
        </div>
        <span class="progress-pct">{{ progress }}%</span>
      </div>

      <p class="status" :class="statusClass" aria-live="polite">
        {{ status || i18n().idle }}
      </p>

      <details v-if="logs.length" class="log-toggle" :aria-label="i18n().logLabel">
        <summary>{{ i18n().logLabel }}</summary>
        <pre class="logs"><code>{{ logs.join("\n") }}</code></pre>
      </details>

      <p class="warning">{{ i18n().warning }}</p>
    </div>
  </details>
</template>
