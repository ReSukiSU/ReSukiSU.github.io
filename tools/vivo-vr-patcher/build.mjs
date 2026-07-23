import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const toolDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(toolDir, "pkg");
const output = resolve(toolDir, "../../docs/public/tools/vivo-vr-patcher.wasm");
const glueOutput = resolve(
  toolDir,
  "../../docs/public/tools/vivo-vr-patcher.js",
);
const wasmPack = process.platform === "win32" ? "wasm-pack.exe" : "wasm-pack";
const zigCc = resolve(
  toolDir,
  process.platform === "win32" ? "../zig-cc.cmd" : "../zig-cc",
);
const zigAr = resolve(
  toolDir,
  process.platform === "win32" ? "../zig-ar.cmd" : "../zig-ar",
);
if (process.platform !== "win32") {
  if (existsSync(zigCc)) chmodSync(zigCc, 0o755);
  if (existsSync(zigAr)) chmodSync(zigAr, 0o755);
}
const buildEnvironment = { ...process.env };
if (!buildEnvironment.CC_wasm32_unknown_unknown && existsSync(zigCc)) {
  buildEnvironment.CC_wasm32_unknown_unknown = zigCc;
  buildEnvironment.CFLAGS_wasm32_unknown_unknown =
    "--target=wasm32-freestanding";
}
if (!buildEnvironment.AR_wasm32_unknown_unknown && existsSync(zigAr)) {
  buildEnvironment.AR_wasm32_unknown_unknown = zigAr;
}

const build = spawnSync(
  wasmPack,
  [
    "build",
    toolDir,
    "--target",
    "web",
    "--release",
    "--out-dir",
    packageDir,
    "--out-name",
    "vivo-vr-patcher",
    "--no-typescript",
  ],
  {
    env: buildEnvironment,
    stdio: "inherit",
  },
);

if (build.status !== 0) process.exit(build.status ?? 1);

mkdirSync(dirname(output), { recursive: true });
copyFileSync(resolve(packageDir, "vivo-vr-patcher_bg.wasm"), output);
copyFileSync(resolve(packageDir, "vivo-vr-patcher.js"), glueOutput);
console.log(`WASM written to ${output}`);
console.log(`JavaScript glue written to ${glueOutput}`);
