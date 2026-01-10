# How to intregate ReSukiSU {#introduction}

::: info Notes
This document modified from [KernelSU Official Documentation](https://kernelsu.org)
:::

ReSukiSU can be integrated into non-GKI kernels and was <mark>backported to 4.9 and earlier</mark> versions.

Due to the fragmentation of non-GKI kernels, we don't have a universal way to build them; therefore, we cannot provide a non-GKI boot.img. However, you can build the kernel with ReSukiSU integrated on your own.

First, you should be able to build a bootable kernel from kernel source code. If the kernel isn't open source, then it is difficult to run ReSukiSU for your device.

If you're able to build a bootable kernel, you can add ReSukiSU into your kernel by following this guide.

## Building Kernel

::: warning
This part is for GKI devices
:::

### Sync the kernel source code

```sh
repo init -u https://android.googlesource.com/kernel/manifest
mv <kernel_manifest.xml> .repo/manifests
repo init -m manifest.xml
repo sync
```

The `<kernel_manifest.xml>` file is a manifest that uniquely identifies a build, allowing you to make it reproducible. To do this, you should download the manifest file from [GKI release builds](https://source.android.com/docs/core/architecture/kernel/gki-release-builds).

### Build

Please check the [Building kernels](https://source.android.com/docs/setup/build/building-kernels) first.

For example, to build an `aarch64` kernel image:

```sh
LTO=thin BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh
```

Don't forget to add the `LTO=thin` flag; otherwise, the build may fail if your computer has less than 24 GB of memory.

Starting from Android 13, the kernel is built by `bazel`:

```sh
tools/bazel build --config=fast //common:kernel_aarch64_dist
```

## Build kernel with ReSukiSU

First, add ReSukiSU to your kernel source tree:：

```sh
curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash -s builtin
```
::: tip
Keep in mind that, on some devices, your defconfig may be located at `arch/arm64/configs` or in other cases, it may be at `arch/arm64/configs/vendor/your_defconfig`. Regardless of the defconfig you're using, make sure to enable `CONFIG_KSU` with `y` to enable or `n` to disable it. For example, if you choose to enable it, your defconfig should contain the following string：

`arch/arm64/configs/...` 
```diff
+# ReSukiSU
+CONFIG_KSU=y
+CONFIG_KSU_MANUAL_HOOK=y
```
:::

Then,add [ReSukiSU's hooks](manual-hooks.md) into your kernel, and build your kernel again, and ReSukiSU should work correctly.

