// https://vitepress.dev/guide/custom-theme
import { defineComponent, h } from "vue";
import DefaultTheme from "vitepress/theme-without-fonts";
import { useData, useRoute } from "vitepress";
import { NolebaseGitChangelogPlugin } from "@nolebase/vitepress-plugin-git-changelog/client";
import { NolebaseHighlightTargetedHeading } from "@nolebase/vitepress-plugin-highlight-targeted-heading/client";
import { NolebaseInlineLinkPreviewPlugin } from "@nolebase/vitepress-plugin-inline-link-preview/client";
import codeblocksFold from "vitepress-plugin-codeblocks-fold";
import CopyOrDownloadAsMarkdownButtons from "vitepress-plugin-llms/vitepress-components/CopyOrDownloadAsMarkdownButtons.vue";
import { render as render_cf_error_page } from 'cloudflare-error-page';

/* plugin css */
import "@nolebase/vitepress-plugin-highlight-targeted-heading/client/style.css";
import "@nolebase/vitepress-plugin-git-changelog/client/style.css";
import "@nolebase/vitepress-plugin-enhanced-mark/client/style.css";
import "@nolebase/vitepress-plugin-inline-link-preview/client/style.css";
import "vitepress-plugin-codeblocks-fold/style/index.css";
import "markdown-it-autospace/spacing.css";

/* font & style css */
import "misans-vf-4web/dist/result.css";
import "remixicon/fonts/remixicon.css";
import "./style.css";
import "./fonts.css";

const FullScreen404 = defineComponent({
  setup() {
    const html = render_cf_error_page({
    title: "Page not found",
    error_code: "404",
    error_source: "Cloudflare",
    cloudflare_status: {
      location: "Vitepress",
      name: "Somebody",
      status: "error",
      status_text: "Set up us the bomb.",
    },
    what_happened: "The page you requested does not exist.",
    what_can_i_do: "Check the URL or <a href=\"/\">return to the homepage</a>.",
    perf_sec_by: {
      text: "ReSukiSU Development Team",
      link: "https://github.com/ReSukiSU",
    },
    more_information:{
      text: "ReSukiSU Development Team Issue Tracker",
      link: "https://github.com/ReSukiSU/ReSukiSU.github.io/issues",
    }
  })
    return () => h("div", {
      innerHTML: html,
      style: {
        width: "100%",
        minHeight: "100vh",
        position: "absolute",
        overflow: "auto",
      },
    });
  },
});

/** @type {import('vitepress').Theme} */
export default {
  extends: DefaultTheme,
  Layout: () => {
    if (useData().page.value.isNotFound) {
      return h(FullScreen404);
    }
    
    return h(DefaultTheme.Layout, null, {
      // https://vitepress.dev/guide/extending-default-theme#layout-slots
      "layout-top": () => [h(NolebaseHighlightTargetedHeading)],
    });
  },
  enhanceApp({ app, router, siteData }) {
    // ...

    app.use(NolebaseGitChangelogPlugin);
    app.use(NolebaseInlineLinkPreviewPlugin);
    app.component(
      "CopyOrDownloadAsMarkdownButtons",
      CopyOrDownloadAsMarkdownButtons,
    );
  },
  setup() {
    const { frontmatter } = useData();
    const route = useRoute();
    codeblocksFold({ frontmatter, route });
  },
};
