<script setup>
import { computed } from 'vue'
import { useData } from 'vitepress'
import { VPTeamPageTitle } from 'vitepress/theme'

const { lang } = useData()
const chinese = computed(() => lang.value === 'zh-CN')
</script>

<template>
  <main class="sponsors-page">
    <VPTeamPageTitle>
      <template #title>{{ chinese ? '感谢支持' : 'Our sponsors' }}</template>
      <template #lead>{{ chinese ? '感谢帮助 ReSukiSU 持续发展的每一位朋友。' : 'Thank you to the people helping ReSukiSU grow.' }}</template>
    </VPTeamPageTitle>

    <section class="sponsor-section" aria-labelledby="domain-sponsors">
      <h2 id="domain-sponsors" class="tier-label">{{ chinese ? '域名赞助者' : 'Domain sponsor' }}</h2>
      <a class="sponsor-card" href="https://github.com/originalFactor" target="_blank" rel="noopener noreferrer">
        <img src="https://github.com/originalFactor.png" alt="" width="56" height="56" />
        <h3>喵喵机</h3>
      </a>
      <p class="donation-credit">{{ chinese ? '捐赠了 resukisu.org 域名' : 'Donated the resukisu.org domain' }}</p>
    </section>

    <section class="support" aria-labelledby="support-title">
      <h2 id="support-title">{{ chinese ? '支持 ReSukiSU' : 'Support ReSukiSU' }}</h2>
      <p>{{ chinese ? '喜欢这个项目？欢迎赞助，支持后续开发。' : 'Enjoy the project? Become a sponsor and support continued development.' }}</p>
      <a class="sponsor-link" href="https://github.com/sponsors/ShiinaSaku" target="_blank" rel="noopener noreferrer">
        <span class="vpi-heart" aria-hidden="true" />
        {{ chinese ? '成为赞助者' : 'Become a sponsor' }}
        <span aria-hidden="true">↗</span>
      </a>
      <p class="thanks">{{ chinese ? '分享项目、报告问题和贡献代码，同样是宝贵的支持。' : 'Sharing the project, reporting issues, and contributing code matter too.' }}</p>
    </section>
  </main>
</template>

<style scoped>
.sponsors-page {
  max-width: 960px;
  margin: 0 auto;
  padding: 0 24px 80px;
}
.sponsors-page :deep(.VPTeamPageTitle) {
  padding-right: 0;
  padding-left: 0;
}
.sponsor-section {
  max-width: 760px;
  margin: 0 auto;
  border: 1px solid var(--vp-c-divider);
}
.tier-label {
  padding: 20px 28px;
  border-bottom: 1px solid var(--vp-c-divider);
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  font-weight: 400;
  color: var(--vp-c-text-2);
  letter-spacing: .04em;
  text-transform: uppercase;
}
.sponsor-card {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 24px;
  width: 100%;
  min-height: 240px;
  padding: 40px 24px;
  background: var(--vp-c-bg);
  transition: background .2s;
}
.sponsor-card:hover { background: var(--vp-c-bg-soft); }
.sponsor-card:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: -3px; }
.sponsor-card img {
  flex: none;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  object-fit: cover;
  filter: grayscale(1);
  transition: filter .2s;
}
.sponsor-card:hover img, .sponsor-card:focus-visible img { filter: none; }
.sponsor-card h3 {
  font-size: clamp(28px, 5vw, 40px);
  font-weight: 600;
  line-height: 1.2;
  color: var(--vp-c-text-1);
}
.donation-credit {
  padding: 12px 24px;
  border-top: 1px solid var(--vp-c-divider);
  font-size: 12px;
  color: var(--vp-c-text-2);
  text-align: center;
}

.support {
  max-width: 640px;
  margin: 48px auto 0;
  padding-top: 32px;
  border-top: 1px solid var(--vp-c-divider);
  text-align: center;
}
h2 {
  font-size: 20px;
  font-weight: 600;
  line-height: 1.5;
}
.support p {
  margin-top: 12px;
  color: var(--vp-c-text-2);
  line-height: 1.7;
}
.sponsor-link {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin-top: 24px;
  padding: 10px 20px;
  border-radius: 8px;
  background: var(--vp-button-brand-bg);
  color: var(--vp-button-brand-text);
  font-size: 14px;
  font-weight: 600;
  transition: background .2s;
}
.sponsor-link:hover { background: var(--vp-button-brand-hover-bg); }
.sponsor-link:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 4px; }
.support .thanks {
  margin-top: 24px;
  font-size: 13px;
}
@media (max-width: 640px) {
  .sponsors-page { padding-bottom: 48px; }
  .support { margin-top: 32px; }
  .tier-label { padding: 16px 20px; }
  .sponsor-card { min-height: 180px; gap: 20px; padding: 32px 20px; }
  .sponsor-card img { width: 52px; height: 52px; }
}
</style>
