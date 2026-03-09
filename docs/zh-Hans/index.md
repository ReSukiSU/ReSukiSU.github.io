---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "ReSukiSU"
  text: "一个更加稳定的SukiSU分支"
  tagline: "让SukiSU再次伟大！"
  image:
    src: /logo.svg
    alt: ReSukiSU Logo
  actions:
    - theme: brand
      text: 快速上手
      link: ./guide/install
    - theme: alt
      text: GitHub
      link: https://github.com/ReSukiSU/ReSukiSU
    - theme: alt
      text: 关于项目
      link: ./guide/introduce

features:
  - title: 基于 KernelSU 的 ROOT 方案
    details: ReSukiSU 是一个 KernelSU 下游项目，由 SukiSU Ultra 分支而来，拥有更好的稳定性。
    icon: <i class="ri-android-fill"></i>
  - title: Non-GKI 内核支持
    details: 更专注于 Non-GKI 内核的兼容支持，确保旧设备稳定运行不会出问题。
    icon: <i class="ri-smartphone-fill"></i>
  - title: 最小化钩子兼容
    details: 兼容当前最新的最小化钩子方案，无需手动选择 hook。
    icon: <i class="ri-flashlight-fill"></i>
    link: ./guide/manual-integrate.md
  - title: KPM 支持
    details: 基于 SukiSU Ultra 分支，理论上支持内核补丁模块 (KPM)。注意此功能仍在开发中。
    icon: <i class="ri-puzzle-2-fill"></i>
  - title: 增强安全性
    details: 改进的安全措施，更好的模块隔离和权限处理机制。
    icon: <i class="ri-shield-check-fill"></i>
  - title: 活跃的社区
    details: 加入我们在 Telegram 上不断壮大的社区，获取支持、更新和讨论。
    icon: <i class="ri-telegram-fill"></i>
    link: https://t.me/ReSukiSU
---

