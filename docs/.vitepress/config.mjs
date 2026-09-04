import { defineConfig } from "vitepress";

import llmstxt from "vitepress-plugin-llms";
import { copyOrDownloadAsMarkdownButtons } from "vitepress-plugin-llms";
import {
  GitChangelog,
  GitChangelogMarkdownSection,
} from "@nolebase/vitepress-plugin-git-changelog/vite";
import { BiDirectionalLinks } from "@nolebase/markdown-it-bi-directional-links";
import { InlineLinkPreviewElementTransform } from "@nolebase/vitepress-plugin-inline-link-preview/markdown-it";
import { chineseSearchOptimize, pagefindPlugin } from "vitepress-plugin-pagefind";
import mdAutoSpacing from "markdown-it-autospace";
import locale from "./locale/index.mjs";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "ReSukiSU",
  description: "A more stable fork of SukiSU — KernelSU-based ROOT with enhanced Non-GKI compatibility.",

  sitemap: {
    hostname: "https://resukisu.org",
  },

  locales: locale.locales,

  head: [
    ["link", { rel: "icon", href: "/favicon.svg" }],
    ["link", { rel: "canonical", href: "https://resukisu.org/" }],
    ["link", { rel: "alternate", hreflang: "en", href: "https://resukisu.org/" }],
    ["link", { rel: "alternate", hreflang: "zh-CN", href: "https://resukisu.org/zh-Hans/" }],
    ["link", { rel: "alternate", hreflang: "x-default", href: "https://resukisu.org/" }],
    ["link", { rel: "preconnect", href: "https://cdn.jsdelivr.net/" }],
    [
      "link",
      {
        rel: "stylesheet",
        href: "https://cdn.jsdelivr.net/npm/jetbrains-mono-webfont@latest/jetbrains-mono.css",
      },
    ],

    [
      "meta",
      {
        name: "google-site-verification",
        content: "PFExExHEiCGSrImS-yWoSnddXHrVHFmejD_kcS1g6AY",
      },
    ],

    ["meta", { name: "robots", content: "index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" }],
    [
      "meta",
      {
        name: "description",
        content: "A more stable fork of SukiSU. KernelSU-based ROOT with enhanced Non-GKI compatibility, minimal hooks, and multi-manager support.",
      },
    ],
    ["meta", { name: "theme-color", content: "#ec4899", media: "(prefers-color-scheme: light)" }],
    ["meta", { name: "theme-color", content: "#f472b6", media: "(prefers-color-scheme: dark)" }],
    ["meta", { name: "color-scheme", content: "light dark" }],

    [
      "meta",
      {
        name: "keywords",
        content: "ReSukiSU, SukiSU, KernelSU, Android, ROOT, Custom Kernel, GKI, Non-GKI, SukiSU Ultra, Android Root, KernelSU Modules",
      },
    ],
    ["meta", { name: "author", content: "ReSukiSU Development" }],
    ["meta", { name: "application-name", content: "ReSukiSU" }],
    ["meta", { name: "apple-mobile-web-app-title", content: "ReSukiSU" }],
    ["meta", { name: "apple-mobile-web-app-status-bar-style", content: "default" }],

    ["meta", { property: "og:title", content: "ReSukiSU — Make SukiSU Great Again" }],
    [
      "meta",
      {
        property: "og:description",
        content: "A more stable fork of SukiSU. KernelSU-based ROOT with enhanced Non-GKI compatibility, minimal hooks, and multi-manager support.",
      },
    ],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "ReSukiSU" }],
    ["meta", { property: "og:url", content: "https://resukisu.org/" }],
    ["meta", { property: "og:image", content: "https://resukisu.org/logo.svg" }],
    ["meta", { property: "og:image:alt", content: "ReSukiSU Logo" }],
    ["meta", { property: "og:image:width", content: "512" }],
    ["meta", { property: "og:image:height", content: "512" }],
    ["meta", { property: "og:locale", content: "en_US" }],
    ["meta", { property: "og:locale:alternate", content: "zh_CN" }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:title", content: "ReSukiSU — Make SukiSU Great Again" }],
    [
      "meta",
      {
        name: "twitter:description",
        content: "A more stable fork of SukiSU. KernelSU-based ROOT with enhanced Non-GKI compatibility, minimal hooks, and multi-manager support.",
      },
    ],
    ["meta", { name: "twitter:image", content: "https://resukisu.org/logo.svg" }],
    ["meta", { name: "twitter:image:alt", content: "ReSukiSU Logo" }],
    [
      "script",
      { type: "application/ld+json" },
      JSON.stringify({
        "@context": "https://schema.org",
        "@graph": [
          {
            "@type": "Organization",
            name: "ReSukiSU",
            url: "https://resukisu.org/",
            logo: "https://resukisu.org/logo.svg",
            sameAs: ["https://github.com/ReSukiSU", "https://t.me/ReSukiSU"],
          },
          {
            "@type": "WebSite",
            name: "ReSukiSU",
            url: "https://resukisu.org/",
            inLanguage: ["en", "zh-CN"],
          },
        ],
      }),
    ],
  ],

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: "/favicon.svg",
    socialLinks: [
      { icon: "github", link: "https://github.com/ReSukiSU" },
      { icon: "telegram", link: "https://t.me/ReSukiSU" },
    ],
    footer: {
      message: "Documented with ❤️ by ReSukiSU Development",
      copyright: "Copyright © 2025-2026 ReSukiSU, under MIT License",
    },

    outline: {
      level: [2, 4],
    },
    externalLinkIcon: true,
  },

  markdown: {
    config: (md) => {
      md.use(BiDirectionalLinks());
      md.use(copyOrDownloadAsMarkdownButtons);
      md.use(InlineLinkPreviewElementTransform);
      md.use(mdAutoSpacing, {
        pangu: true,
        mojikumi: true,
        spacingItems: ["code_inline"],
      });
    },
  },

  vite: {
    plugins: [
      llmstxt(),
      GitChangelog({
        repoURL: () => "https://github.com/ReSukiSU/ReSukiSU.github.io",
      }),
      GitChangelogMarkdownSection({
        exclude: (id) => id.endsWith("index.md"),
        sections: {
          disableContributors: true,
        },
      }),
      pagefindPlugin({
        customSearchQuery: chineseSearchOptimize,
      }),
    ],
    worker: {
      format: "es",
    },
    optimizeDeps: {
      exclude: [
        "@nolebase/vitepress-plugin-enhanced-readabilities/client",
        "@nolebase/vitepress-plugin-inline-link-preview/client",
        "vitepress",
        "@nolebase/ui",
      ],
    },
    ssr: {
      noExternal: [
        "@nolebase/vitepress-plugin-enhanced-readabilities",
        "@nolebase/vitepress-plugin-highlight-targeted-heading",
        "@nolebase/vitepress-plugin-inline-link-preview",
        "@nolebase/ui",
      ],
    },
  },
});
