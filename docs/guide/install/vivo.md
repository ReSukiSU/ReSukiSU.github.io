# vivo Devices

This page covers the ReSukiSU installation process for vivo devices.

::: warning
Back up important data and prepare the stock images matching your current system version before flashing.
:::

## LKM Installation

LKM installation is identical to that on a standard GKI device. See [LKM installation for generic GKI devices](./gki#lkm).

## vivo Security Policy Compatibility

::: danger Warning
Due to vivo's [security policy](https://github.com/tiann/KernelSU/issues/1289#issuecomment-2709964742), `vr.ko` must be disabled before `ksud` and `su` can work correctly.
:::

You can prevent it from taking effect by other means, such as compiling the kernel yourself and blacklisting the `vr` module, or hooking the process-killing path and causing it to crash.
