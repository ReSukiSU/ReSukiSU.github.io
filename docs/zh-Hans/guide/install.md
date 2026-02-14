# 安装 ReSukiSU {#install}

::: tip 
我们默认你已经拥有一定的刷机基础能力，和基本的救砖知识，所以这一部分的文档并不会写得很详细
:::

## 下载ReSukiSU管理器 {#Get-manager}

::: tip 仍在开发中...
因为 ReSukiSU 的管理器还有很多未完成的东西，所以ReSukiSU暂时不会发布至Github Release，但你可以通过[`nightly.link`](https://nightly.link/ReSukiSU/ReSukiSU/workflows/build-manager/main/Manager-release.zip) 或者 [`Github Action`](https://github.com/ReSukiSU/ReSukiSU/actions/workflows/build-manager.yml)来获取目前仍在开发中的管理器。

(Nightly.link无需登录Github账号即可下载文件)
:::

## 安装 {#Installzation}

ReSukiSU 提供了以下两种方式来安装 ReSukiSU

### LKM 安装 {#LKM}

在安装好 ReSukiSU 管理器后，如果内核版本 >= 5.10 ，点击`未安装`后会跳转到安装界面并显示LKM修补/安装。

根据管理器的提示，选择好boot/init_boot/vendor_boot文件，点击`下一步`。

::: info tips
需要修补`vendor_boot`的设备相当少见，所以一般只需要修补`init_boot`文件即可
:::


管理器会快速地将根据系统的KMI决定LKM文件，并将其提供的镜像文件进行修补，并以`KernelSU_patched_*.img`输出至下载目录

之后需要通过一些方法，把修补后的镜像文件**刷入**进对应分区，便大功告成了

### GKI2/GKI1/非GKI内核（Anykernel3）安装 {#builtin}

ReSukiSU管理器虽然内置了Anykernel3的安装方式，但是在管理器未获得**ROOT权限**时，这个安装方法不会被显示出来。您可能需要以下操作才可使用

1.通过 [LKM安装](install#LKM) 获取root后再进行刷入AnyKernel3包

2.使用`magiskboot`手动修改boot镜像

#### 手动修改boot镜像 {#manual-patch-boot}

::: info Note
这一部分取自 [KernelSU官方文档](https://kernelsu.org)
:::

1. [magiskboot](https://github.com/topjohnwu/Magisk/releases)
2. [magiskboot_build](https://github.com/ookiineko/magiskboot_build/releases/tag/last-ci)

Magisk 官方提供的 `magiskboot` 只能运行在 Android/Linux 设备上，如果你想在 macOS/Windows 上使用 `magiskboot` 可以使用第二个方法。

##### 准备 {#patch-preparation}

1. 获取你手机的原厂 boot.img；你可以通过你手机的线刷包解压后之间获取，如果你是卡刷包，那你也许需要 [payload-dumper-go](https://github.com/ssut/payload-dumper-go)
2. 下载你所获取到的 AnyKernel3 刷机包
3. 解压缩 AnyKernel3 刷机包，获取其中的 `Image` 文件，此文件为 KernelSU 的内核文件。

##### 在 Android 设备上使用 magiskboot {#using-magiskboot-on-Android-devices}

1. 在 Magisk 的 [Release 页面](https://github.com/topjohnwu/Magisk/releases) 下载最新的 Magisk 安装包。
2. 将 `Magisk-*(version).apk` 重命名为 `Magisk-*.zip` 然后解压缩。
3. 将解压后的 `Magisk-*/lib/arm64-v8a/libmagiskboot.so` 文件，使用 adb push 到手机：`adb push Magisk-*/lib/arm64-v8a/libmagiskboot.so /data/local/tmp/magiskboot`
4. 使用 adb 将原厂 boot.img 和 AnyKernel3 中的 Image 推送到手机
5. adb shell 进入 /data/local/tmp/ 目录，然后赋予刚 push 文件的可执行权限 `chmod +x magiskboot`
6. adb shell 进入 /data/local/tmp/ 目录，执行 `./magiskboot unpack boot.img` 此时会解包 `boot.img` 得到一个叫做 `kernel` 的文件，这个文件为你原厂的 kernel
7. 使用 `Image` 替换 `kernel`: `mv -f Image kernel`
8. 执行 `./magiskboot repack boot.img` 打包 img，此时你会得到一个 `new-boot.img` 的文件，使用这个文件 fastboot 刷入设备即可。

##### 在 macOS/Windows/Linux 上使用 magiskboot {#using-magiskboot-on-PC}

1. 在 [magiskboot_build](https://github.com/ookiineko/magiskboot_build/releases/tag/last-ci) 下载适合你操作系统的 `magiskboot` 二进制文件。
2. 在你的 PC 上准备好设备原厂的 boot.img 和 KernelSU 的 Image。
3. `chmod +x magiskboot`
4. 在你 PC 上合适的目录执行 `./magiskboot unpack boot.img` 来解包 `boot.img`, 你会得到一个 `kernel` 文件，这个文件是你设备原厂的 kernel。
5. 使用 `Image` 替换 `kernel`: `mv -f Image kernel`
6. 执行 `./magiskboot repack boot.img` 打包 img，此时你会得到一个 `new-boot.img` 的文件，使用这个文件 fastboot 刷入设备即可。

:::info
Magisk 官方的 `magiskboot` 可以在 Linux 设备上执行，如果你是 Linux 用户，可以直接用官方版本。
:::


