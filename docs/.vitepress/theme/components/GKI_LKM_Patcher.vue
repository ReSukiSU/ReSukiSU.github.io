<script setup>
import { computed, onMounted, ref } from "vue";
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
const fileInput = ref(null);
const detecting = ref(false);
const kmiRequired = ref(false);
const selectedKmi = ref("");
let dragDepth = 0;

function stage(value) {
  return t.value.stages[value] ?? value;
}

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

const { ready, busy, progress, status, logs, i18n, addLog, setStatus, start, post } =
  usePatcherWorker(() => new GkiLkmWorker(), {
    onProgress: (data, { addLog: log, setStatus }) => {
      const msg = stage(data.message);
      setStatus(msg);
      log(`${data.percent}% ${msg}`);
    },
    onCustom,
  });

onMounted(() => start());

function onFilePicked(f) {
  if (!f || busy.value) return;
  file.value = f;
  selectedKmi.value = "";
  kmiRequired.value = false;
  addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
  if (ready.value) detectKmi();
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
  selectedKmi.value = "";
  kmiRequired.value = false;
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
  const name = file.value.name;
  file.value.arrayBuffer().then((buf) => {
    addLog(`${i18n().started} ${name}`);
    post({ type: "patch", image: buf, kmi: selectedKmi.value }, [buf]);
  });
}

const patchDisabled = computed(
  () => !ready.value || !file.value || !selectedKmi.value || detecting.value || busy.value,
);

const isError = computed(() => status.value.startsWith(i18n().failed));
const isDone = computed(() => progress.value === 100 && !isError.value);
</script>

<template>
  <div class="pt">
    <p class="pt-title">{{ t.summary }}</p>
    <p class="pt-desc">{{ t.intro }}</p>

    <label
      class="pt-drop"
      :class="{ dragging, disabled: busy }"
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
        accept=".img"
        :disabled="busy"
        tabindex="-1"
        @change="onInputChange"
      />
    </label>

    <div v-if="kmiRequired || selectedKmi" class="pt-field">
      <span>{{ t.selectKmi }}</span>
      <select v-model="selectedKmi" :disabled="busy">
        <option value="" disabled>{{ t.selectKmiPlaceholder }}</option>
        <option v-for="kmi in SUPPORTED_KMIS" :key="kmi" :value="kmi">
          {{ kmi }}
        </option>
      </select>
    </div>

    <div class="pt-actions">
      <button
        v-if="kmiRequired"
        type="button"
        class="pt-btn secondary"
        :disabled="!ready || !file || detecting || busy"
        @click="detectKmi"
      >
        {{ t.detectKmi }}
      </button>
      <button type="button" class="pt-btn" :disabled="patchDisabled" @click="patch">
        {{ busy ? i18n().processing : i18n().patch }}
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
