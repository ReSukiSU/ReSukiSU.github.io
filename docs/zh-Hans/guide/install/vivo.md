# vivo 设备

本页用于介绍 vivo 设备的 ReSukiSU 安装流程。

::: warning
刷写前请备份重要数据，并准备好与当前系统版本匹配的原厂镜像。
:::

## LKM 安装

LKM 安装与正常 GKI 设备无任何区别，请参见：[一般 GKI 设备的 LKM 安装](./gki#lkm)。

## vivo 安全策略兼容

::: danger 警告
vivo 设备由于[安全策略](https://github.com/tiann/KernelSU/issues/1289#issuecomment-2709964742),
需要使 `vr.ko` 失效才可正常使用 `ksud` 和 `su`
:::

你可以使用其他方法来阻止其生效，例如自行编译内核并拉黑 `vr` 模块或 `hook` 其击杀进程的路径来使其崩溃等。
