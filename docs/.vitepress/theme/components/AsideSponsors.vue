<script setup>
import { computed } from 'vue'
import { useData, withBase } from 'vitepress'
import VPDocAsideSponsors from '@voidzero-dev/vitepress-theme/src/components/vitepress-default/VPDocAsideSponsors.vue'
import '@voidzero-dev/vitepress-theme/src/styles/vitepress-default/components/vp-sponsor.css'

const { lang } = useData()
const chinese = computed(() => lang.value === 'zh-CN')
const sponsors = [{
  name: '喵喵机',
  img: 'https://github.com/originalFactor.png',
  url: 'https://github.com/originalFactor',
}]
</script>

<template>
  <section class="aside-sponsors" :aria-label="chinese ? '赞助者' : 'Sponsors'">
    <VPDocAsideSponsors :tier="chinese ? '域名赞助者' : 'Domain sponsor'" size="small" :data="sponsors" />
    <a class="sponsor-name" href="https://github.com/originalFactor" target="_blank" rel="noopener noreferrer">喵喵机</a>
    <a class="all-sponsors" :href="withBase(chinese ? '/zh-Hans/sponsors' : '/sponsors')">{{ chinese ? '查看赞助者' : 'Meet our sponsors' }} <span aria-hidden="true">→</span></a>
    <a class="sponsor-button" href="https://github.com/sponsors/ShiinaSaku" target="_blank" rel="noopener noreferrer">
      <span class="vpi-heart" aria-hidden="true" />
      {{ chinese ? '成为赞助者' : 'Become a sponsor' }}
    </a>
  </section>
</template>

<style scoped>
 .aside-sponsors {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--vp-c-divider);
  text-align: center;
}
.aside-sponsors :deep(.vp-sponsor-grid-link) { height: 64px; }
.aside-sponsors :deep(.vp-sponsor-tier) { letter-spacing: 0; }

.aside-sponsors :deep(.vp-sponsor-grid-image) {
  width: 48px;
  height: 48px;
  max-height: 48px;
  border-radius: 50%;
  filter: none;
}
.aside-sponsors :deep(.vp-sponsor-grid-link:focus-visible) {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: -2px;
}
.sponsor-name { display: block; margin-top: 8px; font-size: 13px; font-weight: 600; }
.all-sponsors { display: block; margin-top: 8px; font-size: 12px; color: var(--vp-c-text-2); }
.sponsor-name:hover, .all-sponsors:hover { color: var(--vp-c-brand-1); }
.sponsor-button {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  margin-top: 16px;
  padding: 8px 12px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  color: var(--vp-c-sponsor);
  font-size: 12px;
  font-weight: 600;
  transition: background .2s;
}
.sponsor-button:hover { background: var(--vp-c-bg-soft); }
.sponsor-button:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 3px; }
</style>
