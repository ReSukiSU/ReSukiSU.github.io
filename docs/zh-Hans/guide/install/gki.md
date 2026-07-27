# 一般 GKI 设备

本页用于介绍一般 GKI 设备的 ReSukiSU 安装流程。

开始前请确认设备的内核版本与 KMI，并参阅[通用安装说明](/zh-Hans/guide/install)。

## LKM 安装 {#lkm}

安装 ReSukiSU 管理器后，点击`未安装`进入安装界面，然后选择 **LKM 修补/安装**。

根据管理器提示选择与当前系统版本匹配的 `boot`、`init_boot` 或 `vendor_boot` 镜像。管理器会根据系统 KMI 选择 LKM 文件，修补镜像，并将 `KernelSU_patched_*.img` 输出到下载目录。

::: info tips
需要修补`vendor_boot`的设备相当少见，所以一般只需要修补`init_boot`文件即可
:::

将修补后的镜像刷入对应分区，重启后再打开管理器确认安装状态。

:::info 提示
我们也同时提供了在线工具来在线修补 `init_boot` / `boot` / `vendor_boot`
:::
<ClientOnly>
<GKI_LKM_Patcher />
</ClientOnly>

::: warning
镜像及目标分区必须匹配。刷写前请备份重要数据，并准备原厂镜像和救砖工具。
:::

## GKI 安装 {#built-in}

请参阅 [Google 文档](https://source.android.com/docs/setup/build/building-kernels?hl=zh-cn) 和 [ReSukiSU 构建指南](../build#introduction) 了解详情。
