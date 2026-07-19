import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const toolDir = dirname(fileURLToPath(import.meta.url));
const manifest = resolve(toolDir, "Cargo.toml");
const output = resolve(toolDir, "../../docs/public/tools/vivo-vr-patcher.wasm");
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";

const build = spawnSync(cargo, [
  "build",
  "--manifest-path", manifest,
  "--target", "wasm32-unknown-unknown",
  "--release",
], { stdio: "inherit", shell: process.platform === "win32" });

if (build.status !== 0) process.exit(build.status ?? 1);

mkdirSync(dirname(output), { recursive: true });
copyFileSync(
  resolve(toolDir, "target/wasm32-unknown-unknown/release/vivo_vr_patcher.wasm"),
  output,
);
console.log(`WASM written to ${output}`);
