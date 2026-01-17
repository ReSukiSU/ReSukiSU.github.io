import { defineConfig } from 'vitepress'

export default defineConfig ({
    lang: "zh-CN",
    themeConfig: {
        description: "让SukiSU再次伟大！",
        nav: [
        { text: '<i class="ri-home-2-fill"></i> 主页', link: '/zh_CN/' },
        { text: '<i class="ri-book-2-fill"></i> 指导', link: '/zh_CN/guide/install' },
        { text: '<i class="ri-links-line"></i> 常用链接',items: [
            { text: 'KernelSU 文档', link: 'https://kernelsu.org/' },
            { text: 'KernelSU 模块仓库', link: 'https://modules.kernelsu.org/'}
        ]}
        ],

        sidebar: [
        {
            text: '开始使用',
            items: [
            { text: '安装', link: '/zh_CN/guide/install' },
            { text: '构建内核', link: '/zh_CN/guide/build',collapsed: true,items: [
                { text: '参考钩子', link: '/zh_CN/guide/manual-hooks' }
            ]},
            { text: '常见问题', link: '/zh_CN/guide/faq' }
            ]
        },
        {text: '关于 ReSukiSU',link:'/zh_CN/guide/introduce'}
        ],
        editLink:{
            text: "在 Github 上编辑此页面",
            pattern: "https://github.com/ReSukiSU/ReSukiSU.github.io/edit/main/docs/:path"
        }
    }
    }
)
