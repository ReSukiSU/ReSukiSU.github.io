import { defineConfig } from 'vitepress'
import Font from 'vite-plugin-font'
import { GitChangelog, GitChangelogMarkdownSection } from '@nolebase/vitepress-plugin-git-changelog/vite'
import { BiDirectionalLinks } from '@nolebase/markdown-it-bi-directional-links'
import { InlineLinkPreviewElementTransform } from '@nolebase/vitepress-plugin-inline-link-preview/markdown-it'
import { chineseSearchOptimize, pagefindPlugin } from 'vitepress-plugin-pagefind'
import mdAutoSpacing from 'markdown-it-autospace'
import locale from './locale/index.mjs'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "ReSukiSU",
  description: "Make SukiSU Great Again!",
  
  sitemap: {
    hostname: 'https://ReSukiSU.github.io' 
  },

  locales: locale.locales,
  
  head: [
    ['link', { rel: "icon", href: '/favicon.svg' }],
    ['link', { rel: "preconnect", href: 'https://s4.zstatic.net/' }],
    ['link', { rel: "stylesheet", href: 'https://s4.zstatic.net/npm/jetbrains-mono-webfont@latest/jetbrains-mono.css' }],
    
    ['meta', { name: 'google-site-verification', content: 'PFExExHEiCGSrImS-yWoSnddXHrVHFmejD_kcS1g6AY' }],
    
    ['meta', { name: 'robots', content: 'index, follow' }],
    
    ['meta', { name: 'keywords', content: 'ReSukiSU, SukiSU, Android, Documentation, Root, Custom ROM, Kernel' }],
    ['meta', { name: 'author', content: 'ReSukiSU Development' }],
    
    ['meta', { property: 'og:title', content: 'ReSukiSU Documentation' }],
    ['meta', { property: 'og:description', content: 'Make SukiSU Great Again! The official documentation.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'ReSukiSU' }],
    
  ],

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: '/logo-mini.svg',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/ReSukiSU' },
      { icon: 'telegram', link: 'https://t.me/ReSukiSU'}
    ],
    footer: {
      message: "Documented with by ReSukiSU Development",
      copyright: "Copyright © 2025-2026 ReSukiSU, under MIT License"
    },

    outline: {
      level: [2, 4]
    },
    externalLinkIcon: true
  },
  
  markdown: {
    config: (md) => {
      md.use(BiDirectionalLinks())
      md.use(InlineLinkPreviewElementTransform)
      md.use(mdAutoSpacing, {
        pangu: true,
        mojikumi: true,
        spacingItems: ["code_inline"],
      })
    }
  },
  
  vite: {
    plugins: [
      Font.vite({}),
      GitChangelog({
        repoURL: () => 'https://github.com/ReSukiSU/ReSukiSU.github.io'
      }),
      GitChangelogMarkdownSection({
        exclude: (id) => id.endsWith('index.md'),
        sections: {
          disableContributors: true
        }
      }),
      pagefindPlugin({
        customSearchQuery: chineseSearchOptimize
      }),
    ],
    optimizeDeps: {
      exclude: [
        '@nolebase/vitepress-plugin-enhanced-readabilities/client',
        '@nolebase/vitepress-plugin-inline-link-preview/client',
        'vitepress',
        '@nolebase/ui',
      ],
    },
    ssr: {
      noExternal: [
        '@nolebase/vitepress-plugin-enhanced-readabilities',
        '@nolebase/vitepress-plugin-highlight-targeted-heading',
        '@nolebase/vitepress-plugin-inline-link-preview',
        '@nolebase/ui',
      ],
    },
  }
})
