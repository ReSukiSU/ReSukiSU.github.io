import { defineConfig } from 'vitepress'

export default defineConfig ({
    lang: "zh-CN",
    themeConfig: {
        description: "让SukiSU再次伟大！",
        nav: [
        { text: '<i class="ri-home-2-fill"></i> 主页', link: '/zh_CN/' },
        { text: '<i class="ri-book-2-fill"></i> 指导', link: '/zh_CN/guide/install' }
        ],

        sidebar: [
        {
            text: '开始使用',
            collapsed: true,
            items: [
            { text: '安装', link: '/zh_CN/guide/install' },
            { text: '构建内核', link: '/zh_CN/guide/build',collapsed: true,items: [
                { text: '参考钩子', link: '/zh_CN/guide/manual-hooks' }
            ]},
            ]
        },
        {text: '关于 ReSukiSU',link:'/zh_CN/guide/introduce'}
        ],
        editLink:{
            text: "在 Github 上编辑此页面"
        }
    }
    }
)