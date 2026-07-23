import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const toolDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(toolDir, "pkg");
const output = resolve(toolDir, "../../docs/public/tools/gki-lkm-patcher.wasm");
const glueOutput = resolve(
  toolDir,
  "../../docs/public/tools/gki-lkm-patcher.js",
);
const wasmPack = process.platform === "win32" ? "wasm-pack.exe" : "wasm-pack";

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
    "gki-lkm-patcher",
    "--no-typescript",
  ],
  {
    stdio: "inherit",
  },
);

if (build.status !== 0) process.exit(build.status ?? 1);

mkdirSync(dirname(output), { recursive: true });
copyFileSync(resolve(packageDir, "gki-lkm-patcher_bg.wasm"), output);
copyFileSync(resolve(packageDir, "gki-lkm-patcher.js"), glueOutput);
console.log(`WASM written to ${output}`);
console.log(`JavaScript glue written to ${glueOutput}`);
