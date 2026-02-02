# Installing ReSukiSU {#install}
 
::: tip
We assume you already have basic firmware flashing skills and bricking recovery knowledge, so this section of the documentation will not be overly detailed.
:::
 
## Get Manager {#Get-manager}

::: tip Still Work in Progress...
Before the [`new-manager`](https://github.com/ReSukiSU/ReSukiSU/tree/new-manager) branch is merged, ReSukiSU will not be released on GitHub Release. However, you can obtain the manager currently under development via [nightly.link](https://nightly.link/ReSukiSU/ReSukiSU/workflows/build-manager/new-manager/Manager-release.zip) or [GitHub Action](https://github.com/ReSukiSU/ReSukiSU/actions/workflows/build-manager.yml).

(Nightly.link allows downloading files without logging into a GitHub account.)
:::

## Install {#Installzation}

ReSukiSU provides the following two installation methods:
 
### LKM Installation {#LKM}
 
After installing the ReSukiSU Manager, if your kernel version is ≥ `5.10`, clicking `Not Installed` will redirect you to the installation interface and display the `LKM patching/installation` option.
 
Follow the prompts in the Manager to select the  `boot` / `init_boot` / `vendor_boot` file, then click Next.
 
::: info tips
Devices requiring `vendor_boot` patching are quite rare, so you generally only need to patch the `init_boot` file.
:::
 
The Manager will quickly determine the LKM file based on the system's KMI, patch the provided image file, and output the patched file as  `KernelSU_patched_*.img`  to the download directory.
 
After that, you need to flash the patched image file to the corresponding partition using appropriate methods, and you’re all set.
 
### GKI2/GKI1/Non-GKI Kernel (AnyKernel3) Installation {#builtin}
 
Although the ReSukiSU Manager has a built-in AnyKernel3 installation method, this option will not be displayed if the Manager does not have ROOT access. You may need to perform the following steps to enable it

1. Flash AnyKernel3 after LKM installzaiton to grant root.

2. Using `magiskboot` to manual patch boot.img.

#### Patch boot.img manually {#manual-patch-boot}

::: info Note
This part picked from [KernelSU official Documentation](https://kernelsu.org)
:::

1. [magiskboot](https://github.com/topjohnwu/Magisk/releases)
2. [magiskboot_build](https://github.com/ookiineko/magiskboot_build/releases/tag/last-ci)

he official build of `magiskboot` can only run on Android devices, if you want to run it on PC, you can try the second option.


##### Preparation

1. Get your device's stock boot.img. You can get it from your device manufacturers. You may need [payload-dumper-go](https://github.com/ssut/payload-dumper-go).
2. Unpack the AnyKernel3 package and get the `Image` file, which is the kernel file of KernelSU.

##### Using magiskboot on Android devices {#using-magiskboot-on-Android-devices}

1. Download latest Magisk from [GitHub Releases](https://github.com/topjohnwu/Magisk/releases).
2. Rename `Magisk-*(version).apk` to `Magisk-*.zip` and unzip it.
3. Push `Magisk-*/lib/arm64-v8a/libmagiskboot.so` to your device by ADB: `adb push Magisk-*/lib/arm64-v8a/libmagiskboot.so /data/local/tmp/magiskboot`
4. Push stock boot.img and Image in AnyKernel3 to your device.
5. Enter ADB shell and run `cd /data/local/tmp/` directory, then `chmod +x magiskboot`
6. Enter ADB shell and run `cd /data/local/tmp/` directory, execute `./magiskboot unpack boot.img` to unpack `boot.img`, you will get a `kernel` file, this is your stock kernel.
7. Replace `kernel` with `Image` by running the command: `mv -f Image kernel`.
8. Execute `./magiskboot repack boot.img` to repack boot image, and you will get a `new-boot.img` file, flash this file to device by fastboot.

##### Using magiskboot on Windows/macOS/Linux PC {#using-magiskboot-on-PC}

1. Download the corresponding `magiskboot` binary for your OS from [magiskboot_build](https://github.com/ookiineko/magiskboot_build/releases/tag/last-ci).
2. Prepare stock `boot.img` and `Image` in your PC.
3. Run `chmod +x magiskboot`.
4. Enter the corresponding directory, execute `./magiskboot unpack boot.img` to unpack `boot.img`, you will get a `kernel` file, this is your stock kernel.
5. Replace `kernel` with `Image` by running the command: `mv -f Image kernel`.
6. Execute `./magiskboot repack boot.img` to repack the boot image, and you will get a `new-boot.img` file, flash this file to device by fastboot.

::: info
Official `magiskboot` can run in `Linux` environments normally, if you're a Linux user, you can use the official build.
:::