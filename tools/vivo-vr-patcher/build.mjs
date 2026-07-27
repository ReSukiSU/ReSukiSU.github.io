import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NAME = "vivo-vr-patcher";
const PKG_NAME = "vivo_vr_patcher";
const toolDir = dirname(fileURLToPath(import.meta.url));
const pkgDir = resolve(toolDir, "pkg");
const outDir = resolve(toolDir, "../../docs/.vitepress/theme/wasm", NAME);
const wasmPack = process.platform === "win32" ? "wasm-pack.exe" : "wasm-pack";

rmSync(pkgDir, { recursive: true, force: true });

const build = spawnSync(
  wasmPack,
  ["build", toolDir, "--target", "bundler", "--release", "--out-dir", "pkg"],
  { stdio: "inherit" },
);

if (build.status !== 0) process.exit(build.status ?? 1);

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
for (const f of [`${PKG_NAME}.js`, `${PKG_NAME}_bg.js`, `${PKG_NAME}_bg.wasm`]) {
  copyFileSync(resolve(pkgDir, f), resolve(outDir, f));
}
console.log(`bundler pkg written to ${outDir}`);
