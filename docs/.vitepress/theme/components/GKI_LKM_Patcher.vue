<script setup>
import { computed, ref } from "vue";
import { useData } from "vitepress";
const { lang } = useData(),
  zh = computed(() => lang.value?.startsWith("zh"));
const ready = ref(false),
  busy = ref(false),
  detecting = ref(false),
  kmiRequired = ref(false),
  progress = ref(0),
  status = ref(""),
  logs = ref([]),
  image = ref(),
  selectedKmi = ref("");
let worker;
const supportedKmis = [
  "android12-5.10",
  "android13-5.10",
  "android13-5.15",
  "android14-5.15",
  "android14-6.1",
  "android15-6.6",
  "android16-6.12",
];
const s = (cn, en) => (zh.value ? cn : en);
const log = (m) => logs.value.push(`[${new Date().toLocaleTimeString()}] ${m}`);
const stages = {
  detect_kmi: ["正在识别 KMI", "Detecting KMI"],
  download_assets: [
    "正在下载 ksuinit 和匹配的 LKM",
    "Downloading ksuinit and the matching LKM",
  ],
  parse_image: ["正在解析启动镜像", "Parsing boot image"],
  inject_lkm: [
    "正在注入 ksuinit 和 kernelsu.ko",
    "Injecting ksuinit and kernelsu.ko",
  ],
  repack_image: ["正在重打包启动镜像", "Repacking boot image"],
  complete: ["修补完成", "Patch complete"],
};
const stage = (value) => (stages[value] ? s(...stages[value]) : value);
function open(e) {
  if (!e.currentTarget.open || worker) return;
  status.value = s("正在加载 LKM 修补工具…", "Loading LKM patching tool…");
  log(status.value);
  worker = new Worker("/tools/gki-lkm-patcher-worker.js?v=20260723-2", {
    type: "module",
  });
  worker.onmessage = ({ data }) => {
    if (data.type === "ready") {
      ready.value = true;
      status.value = s("工具已就绪", "Tool ready");
      log(status.value);
      if (image.value) detectKmi();
    } else if (data.type === "progress") {
      progress.value = data.percent;
      const message = stage(data.message);
      status.value = message;
      log(`${data.percent}% ${message}`);
    } else if (data.type === "kmi") {
      status.value = `KMI: ${data.kmi}`;
      log(status.value);
    } else if (data.type === "kmi_detected") {
      detecting.value = false;
      selectedKmi.value = data.kmi;
      kmiRequired.value = false;
      progress.value = 0;
      status.value = `${s("已识别 KMI", "Detected KMI")}: ${data.kmi}`;
      log(status.value);
    } else if (data.type === "kmi_required") {
      detecting.value = false;
      kmiRequired.value = true;
      progress.value = 0;
      status.value = s(
        "镜像中未检测到 kernel，请选择 KMI",
        "No kernel was detected in the image. Select a KMI.",
      );
      log(status.value);
    } else if (data.type === "error") {
      busy.value = false;
      detecting.value = false;
      status.value = `${s("失败", "Failed")}: ${data.message}`;
      log(status.value);
    } else if (data.type === "done") {
      const u = URL.createObjectURL(new Blob([data.buffer]));
      const a = document.createElement("a");
      a.href = u;
      a.download = "kernelsu_patched.img";
      a.click();
      URL.revokeObjectURL(u);
      busy.value = false;
      progress.value = 100;
      status.value = s(
        "修补完成，已请求下载修补后的映像文件",
        "Patching complete. The patched image download has been requested.",
      );
      log(status.value);
    }
  };
}
async function pickImage(e) {
  image.value = e.target.files?.[0];
  selectedKmi.value = "";
  kmiRequired.value = false;
  progress.value = 0;
  if (image.value && ready.value) await detectKmi();
}
async function detectKmi() {
  if (!image.value || !worker || detecting.value) return;
  detecting.value = true;
  status.value = s("正在识别 KMI…", "Detecting KMI…");
  log(status.value);
  const imageBuffer = await image.value.arrayBuffer();
  worker.postMessage({ type: "detect_kmi", image: imageBuffer }, [imageBuffer]);
}
async function patch() {
  if (!image.value || !worker || !selectedKmi.value) return;
  busy.value = true;
  progress.value = 0;
  logs.value = [];
  const imageBuffer = await image.value.arrayBuffer();
  const message = {
    type: "patch",
    image: imageBuffer,
    kmi: selectedKmi.value || undefined,
  };
  const transfers = [imageBuffer];
  worker.postMessage(message, transfers);
}
</script>
<template>
  <details class="gki-tool" @toggle="open">
    <summary>
      {{ s("在线修补 LKM", "Online LKM patching") }}
    </summary>
    <div class="body">
      <p>
        {{
          s(
            "镜像在本地处理；ksuinit 和匹配的 LKM 仅在开始修补后从 ReSukiSU CI 下载。",
            "Images are processed locally. ksuinit and the matching LKM are downloaded from ReSukiSU CI only after patching starts.",
          )
        }}
      </p>
      <label
        >{{ s("待修补镜像", "Image to patch") }}
        <input type="file" accept=".img" :disabled="busy" @change="pickImage"
      /></label>
      <label v-if="kmiRequired" class="kmi-field">
        {{ s("选择 KMI", "Select KMI") }}
        <select v-model="selectedKmi" :disabled="busy">
          <option value="" disabled>
            {{ s("请选择 KMI", "Select a KMI") }}
          </option>
          <option v-for="kmi in supportedKmis" :key="kmi" :value="kmi">
            {{ kmi }}
          </option>
        </select>
      </label>
      <button
        :disabled="!ready || !image || !selectedKmi || detecting || busy"
        @click="patch"
      >
        {{
          busy
            ? s("处理中…", "Processing…")
            : s("修补并下载", "Patch and download")
        }}</button
      ><progress :value="progress" max="100"></progress
      ><span>{{ progress }}%</span>
      <p>{{ status }}</p>
      <pre
        v-if="logs.length"
        class="logs"
        :aria-label="s('修补日志', 'Patch log')"
      ><code>{{logs.join('\n')}}</code></pre>
    </div>
  </details>
</template>
<style scoped>
.gki-tool {
  margin: 24px 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg-soft);
}
summary {
  padding: 16px;
  cursor: pointer;
  font-weight: 600;
  color: var(--vp-c-brand-1);
}
.body {
  padding: 0 16px 16px;
}
label {
  display: block;
  margin: 12px 0;
}
button {
  padding: 10px 14px;
  border: 0;
  border-radius: 8px;
  background: var(--vp-c-brand-3);
  color: #fff;
  font-weight: 600;
}
button:disabled {
  opacity: 0.5;
}
progress {
  width: calc(100% - 4em);
  margin: 16px 8px 0 0;
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
.kmi-field select {
  display: block;
  width: 100%;
  margin-top: 8px;
  padding: 10px 12px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
}
</style>
