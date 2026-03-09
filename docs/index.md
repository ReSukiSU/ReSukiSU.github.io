---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "ReSukiSU"
  text: "A more stable fork of SukiSU"
  tagline: "Make SukiSU Great Again!"
  image:
    src: /logo.svg
    alt: ReSukiSU Logo
  actions:
    - theme: brand
      text: Get Started
      link: /guide/install
    - theme: alt
      text: GitHub
      link: https://github.com/ReSukiSU/ReSukiSU
    - theme: alt
      text: About
      link: /guide/introduce

features:
  - title: KernelSU-based ROOT
    details: ReSukiSU is a KernelSU downstream project, derived from the SukiSU Ultra branch with enhanced stability.
    icon: <i class="ri-android-fill"></i>
  - title: Non-GKI Support
    details: Focused on Non-GKI kernel compatibility, ensuring older devices work flawlessly without breaking.
    icon: <i class="ri-smartphone-fill"></i>
  - title: Minimal Hooks
    details: Compatible with the latest scope-minimized hooks. No need to manually select hooks anymore.
    icon: <i class="ri-flashlight-fill"></i>
    link: ./guide/manual-integrate.md
  - title: KPM Support
    details: Based on SukiSU Ultra, theoretically supports Kernel Patch Modules (KPM). Note that this feature is experimental.
    icon: <i class="ri-puzzle-2-fill"></i>
  - title: Enhanced Security
    details: Improved security measures with better module isolation and permission handling.
    icon: <i class="ri-shield-check-fill"></i>
  - title: Active Community
    details: Join our growing community on Telegram for support, updates, and discussions.
    icon: <i class="ri-telegram-fill"></i>
    link: https://t.me/ReSukiSU
---

