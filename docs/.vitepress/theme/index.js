// https://vitepress.dev/guide/custom-theme
import { defineComponent, h, onErrorCaptured,ref } from "vue";
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
    
    what_happened: "The page you requested does not exist.",
    what_can_i_do: "Check the URL or return to the homepage."
  })
    return () => h("div", {
      innerHTML: html,
      style: {
        width: "100%",
        minheight: "100vh",
        position: "absolute",
        overflow: "auto",
      },
    });
  },
});

const FullScreen500 = defineComponent({
  props: ['error'],
  setup(props) {
    const html = render_cf_error_page({
    title: "Internal Server Error",
    error_code: "500",
    what_happened: props.error?.toString() || "An unexpected error occurred on the server.",
    what_can_i_do: "Try refreshing the page or come back later."
  })
    return () => h("div", {
      innerHTML: html,
      style: {
        width: "100%",
        height: "100%",
        position: "fixed",
        inset: 0,
      },
    });
  },
});

/** @type {import('vitepress').Theme} */
export default {
  extends: DefaultTheme,
  Layout: () => {
    const error = ref(null);
    onErrorCaptured((err) => {
      console.error("Captured error in layout:", err);
      error.value = err;
      return false; // prevent further propagation
    });

    if (error.value) {
      return h(FullScreen500, { error: error.value });
    }

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
