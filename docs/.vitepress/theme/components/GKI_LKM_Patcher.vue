<script setup>
import { computed, ref } from "vue";
import { useData } from "vitepress";
import { usePatcherWorker, formatBytes } from "../composables/usePatcherWorker.js";
import GkiLkmWorker from "../workers/gki-lkm-patcher.worker.js?worker";
import { gkiLkmI18n, SUPPORTED_KMIS } from "../composables/patcher-i18n.js";
import "../styles/patcher.css";

const { lang } = useData();
const isZh = computed(() => lang.value?.startsWith("zh"));
const t = computed(() => (isZh.value ? gkiLkmI18n.zh : gkiLkmI18n.en));

const file = ref(null);
const dragging = ref(false);
const showLogs = ref(false);
const detecting = ref(false);
const kmiRequired = ref(false);
const selectedKmi = ref("");

function stage(value) {
  return t.value.stages[value] ?? value;
}

const { ready, loading, busy, progress, status, logs, i18n, addLog, setStatus, start, post, fail } =
  usePatcherWorker(() => new GkiLkmWorker(), {
    onProgress: (data, { addLog: log, setStatus }) => {
      const msg = stage(data.message);
      setStatus(msg);
      log(`${data.percent}% ${msg}`);
    },
    onCustom,
  });

function onToggle(event) {
  if (!event.currentTarget.open) return;
  start();
}

function onFilePicked(f) {
  file.value = f;
  selectedKmi.value = "";
  kmiRequired.value = false;
  if (f) {
    addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
    if (ready.value) detectKmi();
  }
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

async function detectKmi() {
  if (!file.value || detecting.value || busy.value) return;
  detecting.value = true;
  setStatus(i18n().detecting);
  addLog(i18n().detecting);
  const buf = await file.value.arrayBuffer();
  post({ type: "detect_kmi", image: buf }, [buf]);
  detecting.value = false;
}

function patch() {
  if (!file.value || !selectedKmi.value || busy.value) return;
  file.value.arrayBuffer().then((buf) => {
    addLog(`${i18n().started} ${file.value.name}`);
    post({ type: "patch", image: buf, kmi: selectedKmi.value }, [buf]);
  });
}

const patchDisabled = computed(
  () => !ready.value || !file.value || !selectedKmi.value || detecting.value || busy.value,
);

const statusClass = computed(() => {
  if (status.value.startsWith(i18n().failed)) return "error";
  if (progress.value === 100) return "success";
  return "";
});

const buttonLabel = computed(() => {
  if (busy.value) return i18n().processing;
  return i18n().patch;
});

const onCustom = (data) => {
  if (data.type === "kmi") {
    setStatus(`KMI: ${data.kmi}`);
    addLog(`KMI: ${data.kmi}`);
  } else if (data.type === "kmi_detected") {
    detecting.value = false;
    selectedKmi.value = data.kmi;
    kmiRequired.value = false;
    progress.value = 0;
    setStatus(`${i18n().kmiDetected}: ${data.kmi}`);
    addLog(`${i18n().kmiDetected}: ${data.kmi}`);
  } else if (data.type === "kmi_required") {
    detecting.value = false;
    kmiRequired.value = true;
    progress.value = 0;
    setStatus(i18n().kmiRequired);
    addLog(i18n().kmiRequired);
  }
};
</script>

<template>
  <details class="patcher" :open="false" @toggle="onToggle">
    <summary>{{ t.summary }}</summary>
    <div class="patcher-body">
      <p class="patcher-intro">{{ t.intro }}</p>

      <div
        class="dropzone"
        :class="{ dragging, disabled: busy }"
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
        <input type="file" accept=".img" :disabled="busy" @change="onInputChange" />
      </div>

      <div class="patcher-controls">
        <div v-if="kmiRequired" class="patcher-field">
          <label>{{ t.selectKmi }}</label>
          <select v-model="selectedKmi" :disabled="busy">
            <option value="" disabled>{{ t.selectKmiPlaceholder }}</option>
            <option v-for="kmi in SUPPORTED_KMIS" :key="kmi" :value="kmi">
              {{ kmi }}
            </option>
          </select>
        </div>
        <button
          v-if="kmiRequired"
          type="button"
          class="patcher-btn secondary"
          :disabled="!ready || !file || detecting || busy"
          @click="detectKmi"
        >
          {{ t.detectKmi }}
        </button>
        <button type="button" class="patcher-btn" :disabled="patchDisabled" @click="patch">
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
