<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { useData } from "vitepress";
import { usePatcherWorker, formatBytes } from "../composables/usePatcherWorker.js";
import GkiLkmWorker from "../workers/gki-lkm-patcher.worker.js?worker";
import { gkiLkmI18n, SUPPORTED_ARCHS, SUPPORTED_KMIS } from "../composables/patcher-i18n.js";
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
const selectedArch = ref("");
let dragDepth = 0;
let pendingDetect = false;

function stage(value) {
  return t.value.stages[value] ?? value;
}

const onCustom = (data) => {
  if (data.type === "kmi") {
    setStatus(`KMI: ${data.kmi}`);
    addLog(`KMI: ${data.kmi}`);
  } else if (data.type === "arch") {
    setStatus(`Arch: ${data.arch}`);
    addLog(`Arch: ${data.arch}`);
  } else if (data.type === "kmi_detected") {
    detecting.value = false;
    busy.value = false;
    selectedKmi.value = data.kmi;
    kmiRequired.value = false;
    progress.value = 0;
    setStatus(`${i18n().kmiDetected}: ${data.kmi}`);
    addLog(`${i18n().kmiDetected}: ${data.kmi}`);
    // No button — patch as soon as KMI is known.
    patch();
  } else if (data.type === "kmi_required") {
    detecting.value = false;
    busy.value = false;
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
  selectedArch.value = "";
  kmiRequired.value = false;
  addLog(`${i18n().selected} ${f.name} (${formatBytes(f.size)})`);
  if (ready.value) detectKmi();
  else pendingDetect = true;
}

watch(ready, (ok) => {
  if (ok && pendingDetect && file.value) {
    pendingDetect = false;
    detectKmi();
  }
});

// Manual KMI choice — patch starts as soon as a KMI is selected.
watch([selectedKmi, selectedArch], ([kmi, arch]) => {
  if (kmi && arch && file.value && !busy.value) patch();
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
  selectedKmi.value = "";
  selectedArch.value = "";
  kmiRequired.value = false;
  pendingDetect = false;
  progress.value = 0;
  setStatus("");
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
    post({ type: "patch", image: buf, kmi: selectedKmi.value, arch: selectedArch.value }, [buf]);
    addLog(`${i18n().started} ${name}`);
  });
}

const isError = computed(() => (status.value ?? "").startsWith(i18n().failed));
const isDone = computed(() => progress.value === 100 && !isError.value);
const dropHint = computed(() => {
  if (dragging.value) return i18n().drop;
  if (busy.value) return t.value.working;
  if (detecting.value) return i18n().detecting;
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
      :class="{ dragging, disabled: busy, 'has-file': !!file }"
      tabindex="0"
      @keydown="onKeydown"
      @dragenter="onDragEnter"
      @dragover="onDragOver"
      @dragleave="onDragLeave"
      @drop="onDrop"
    >
      <span class="pt-drop-icon" aria-hidden="true">
        <i v-if="isDone" class="ri-checkbox-circle-line ok"></i>
        <i v-else-if="busy || detecting" class="ri-loader-4-line pt-spin-icon"></i>
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
        accept=".img"
        :disabled="busy"
        tabindex="-1"
        @change="onInputChange"
      />
    </label>

    <div v-if="kmiRequired" class="pt-field">
      <span>{{ t.selectKmi }}</span>
      <select v-model="selectedKmi" :disabled="busy">
        <option value="" disabled>{{ t.selectKmiPlaceholder }}</option>
        <option v-for="kmi in SUPPORTED_KMIS" :key="kmi" :value="kmi">
          {{ kmi }}
        </option>
      </select>
    </div>

    <div v-if="file" class="pt-field">
      <span>{{ t.selectArch }}</span>
      <select v-model="selectedArch" :disabled="busy">
        <option value="" disabled>{{ t.selectArchPlaceholder }}</option>
        <option v-for="arch in SUPPORTED_ARCHS" :key="arch" :value="arch">
          {{ arch }}
        </option>
      </select>
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
