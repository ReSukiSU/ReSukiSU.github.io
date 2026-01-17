// https://vitepress.dev/guide/custom-theme
import { h } from 'vue'
import DefaultTheme from 'vitepress/theme-without-fonts'
import { useData,useRoute } from 'vitepress'
import { NolebaseGitChangelogPlugin } from '@nolebase/vitepress-plugin-git-changelog/client'
import { NolebaseHighlightTargetedHeading } from '@nolebase/vitepress-plugin-highlight-targeted-heading/client'
import { NolebaseInlineLinkPreviewPlugin } from '@nolebase/vitepress-plugin-inline-link-preview/client'
import codeblocksFold from 'vitepress-plugin-codeblocks-fold'

/ plugin css /
import '@nolebase/vitepress-plugin-highlight-targeted-heading/client/style.css'
import '@nolebase/vitepress-plugin-git-changelog/client/style.css'
import '@nolebase/vitepress-plugin-enhanced-mark/client/style.css'
import '@nolebase/vitepress-plugin-inline-link-preview/client/style.css'
import 'vitepress-plugin-codeblocks-fold/style/index.css'
import 'markdown-it-autospace/spacing.css'

/ font & style css /
import { css } from './MisansVF.ttf'
import 'remixicon/fonts/remixicon.css'
import './style.css'
import './fonts.css'

/** @type {import('vitepress').Theme} */
export default {
  extends: DefaultTheme,
  Layout: () => {
    return h(DefaultTheme.Layout, null, {
      // https://vitepress.dev/guide/extending-default-theme#layout-slots
      'layout-top': () => [h(NolebaseHighlightTargetedHeading)]
    })
  },
  enhanceApp({ app, router, siteData }) {
    // ...
    app.use(css),
    app.use(NolebaseGitChangelogPlugin),
    app.use(NolebaseInlineLinkPreviewPlugin)
  },
  setup() {
    const { frontmatter } = useData();
    const route = useRoute();
    codeblocksFold({frontmatter,route});
  }
}
