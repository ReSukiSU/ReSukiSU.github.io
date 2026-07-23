@echo off
setlocal

if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
  set "ZIG=%~dp0..\node_modules\@oven\zig-win32-arm64\zig.exe"
) else (
  set "ZIG=%~dp0..\node_modules\@oven\zig-win32-x64\zig.exe"
)

"%ZIG%" cc %*

