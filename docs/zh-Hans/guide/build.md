# 如何为内核集成 ReSukiSU {#introduction}

::: info Notes
这个文档修改自 [KernelSU官方文档](https://kernelsu.org)
:::

ReSukiSU 可以被集成到GKI/非 GKI 内核中，现在它<mark>最低支持到内核 3.4 版本</mark>；理论上也可以支持更低的版本。

由于非 GKI 内核的碎片化**极其严重**，因此通常没有统一的方法来编译它。但你完全可以自己集成 ReSukiSU 然后编译内核使用。

首先，你必须有能力从你设备的内核源码编译出一个可以开机并且能正常使用的内核，如果内核不开源，这通常难以做到。

如果你已经做好了上述准备，可以通过这个教程来集成 ReSukiSU 到你的内核之中。

## 构建内核

::: warning
本部分仅适用于 GKI 设备
:::

### 同步内核源码

```sh
repo init -u https://android.googlesource.com/kernel/manifest
mv <kernel_manifest.xml> .repo/manifests
repo init -m manifest.xml
repo sync
```

`<kernel_manifest.xml>` 是一个可以唯一确定构建的清单文件，您可以使用该清单进行可重新预测的构建。 您应该从 [通用内核映像 (GKI) 发布构建](https://source.android.com/docs/core/architecture/kernel/gki-release-builds) 下载清单文件 

### 构建

请先查看 [官方文档](https://source.android.com/docs/setup/build/building-kernels)。

例如，我们需要构建 aarch64 内核镜像：

```sh
LTO=thin BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh
```

不要忘记添加 `LTO=thin`, 否则，如果您的计算机内存小于 24GB，构建可能会失败.

从 Android 13 开始，内核由 `bazel` 构建:

```sh
tools/bazel build --config=fast //common:kernel_aarch64_dist
```

## 使用 ReSukiSU 构建内核

把 ReSukiSU 添加到你的内核源码树，在内核的根目录执行以下命令：

```sh
curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash
```

### 手动钩子

::: tip
请注意，某些设备的 defconfig 文件可能在`arch/arm64/configs/设备代号_defconfig`或位于`arch/arm64/configs/vendor/设备代号_defconfig`。在您的 defconfig 文件中，将`CONFIG_KSU`设置为`y`以启用 ReSukiSU，或设置为`n`以禁用。比如在某个 defconfig 中：
`arch/arm64/configs/...` 
```diff
+# ReSukiSU
+CONFIG_KSU=y
+CONFIG_KSU_MANUAL_HOOK=y
```
:::

然后，将 [ReSukiSU 调用添加到内核源代码](manual-integrate.md) 中，改完之后重新编译内核即可。

### SUSFS

::: tip
请注意，某些设备的 defconfig 文件可能在`arch/arm64/configs/设备代号_defconfig`或位于`arch/arm64/configs/vendor/设备代号_defconfig`。在您的 defconfig 文件中，将`CONFIG_KSU`设置为`y`以启用 ReSukiSU，或设置为`n`以禁用。比如在某个 defconfig 中：
`arch/arm64/configs/...` 
```diff
+# ReSukiSU
+CONFIG_KSU=y
+CONFIG_KSU_SUSFS=y
```
:::

然后，在[SUSFS仓库](https://gitlab.com/simonpunk/susfs4ksu)中**根据你的内核版本选择分支**并按照指导打**内核侧**补丁，改完之后重新编译内核即可。

::: warning
NonGKI 的分支处于弃置状态，如果需要使用SUSFS,请自行backport移植
:::