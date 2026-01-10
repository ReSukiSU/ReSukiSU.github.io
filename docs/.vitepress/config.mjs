import { defineConfig } from 'vitepress'
import Font from 'vite-plugin-font'
import { GitChangelog,GitChangelogMarkdownSection } from '@nolebase/vitepress-plugin-git-changelog/vite'
import { BiDirectionalLinks } from '@nolebase/markdown-it-bi-directional-links'
import { InlineLinkPreviewElementTransform } from '@nolebase/vitepress-plugin-inline-link-preview/markdown-it'
import { chineseSearchOptimize,pagefindPlugin } from 'vitepress-plugin-pagefind'
import mdAutoSpacing from 'markdown-it-autospace'
import locale from './locale/index.mjs'


// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "ReSukiSU",
  description: "Make SukiSU Great Again!",
  locales: locale.locales,
  head: [
    ['link',{rel:"icon",href:'/favicon.svg'}],
    ['link',{rel:"preconnect",href:'https://s4.zstatic.net/'}],
    ['link',{rel:"stylesheet",href:'https://s4.zstatic.net/npm/jetbrains-mono-webfont@latest/jetbrains-mono.css'}]
  ],
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    socialLinks: [
      { icon: 'github', link: 'https://github.com/ReSukiSU' },
      { icon: 'telegram', link: 'https://t.me/ReSukiSU'}
    ],
    footer: {
      message: "Documented by ReSukiSU Devloperment"
    },

    outline: {
      level: [2,4]
    },
    externalLinkIcon: true
  },
  markdown: {
    config: (md) => {
      md.use(BiDirectionalLinks())
      md.use(InlineLinkPreviewElementTransform)
      md.use(mdAutoSpacing,{
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
