# Generic GKI Devices

This page covers the ReSukiSU installation process for generic GKI devices.

Before starting, identify the device kernel version and KMI, then read the [general installation guide](/guide/install).

## LKM Installation {#lkm}

After installing ReSukiSU Manager, tap `Not Installed` to open the installation screen, then select **LKM patching/installation**.

Select the `boot`, `init_boot`, or `vendor_boot` image matching the installed firmware. The Manager selects the LKM file from the system KMI, patches the image, and writes `KernelSU_patched_*.img` to the download directory.

::: info Tips
Devices that require `vendor_boot` patching are quite rare, so normally only the `init_boot` file needs to be patched.
:::

Flash the patched image to its corresponding partition, reboot, and open the Manager again to confirm the installation status.

::: info Tip
We also provide an online tool for patching `init_boot`, `boot`, or `vendor_boot`.
:::

<ClientOnly>
  <GKI_LKM_Patcher />
</ClientOnly>

::: warning
The image and target partition must match. Back up important data and prepare stock images and recovery tools before flashing.
:::

## GKI Installation {#built-in}

See the [Google documentation](https://source.android.com/docs/setup/build/building-kernels) and the [ReSukiSU build guide](../build#introduction) for details.
