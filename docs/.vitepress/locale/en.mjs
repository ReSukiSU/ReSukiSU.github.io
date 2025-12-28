import { defineConfig } from 'vitepress'

export default defineConfig ({
    lang: "en",
    themeConfig: {
        description: "Make SukiSU Great Again!",
        nav: [
        { text: '<i class="ri-home-2-fill"></i> Home', link: '/' },
        { text: '<i class="ri-book-2-fill"></i> Guide', link: '/guide/install' }
        ],
        sidebar: [
        {
            text: 'Get started',
            collapsed: true,
            items: [
            { text: 'Install', link: '/guide/install' },
            { text: 'Building Kernel', link: '/guide/build',collapsed:true, items: [
                { text: 'Manual Hooks', link: '/guide/manual-hooks' }
            ]},
            ]
        },
        { text:"About ReSukiSU",link: "/guide/introduce"}
        ],
        editLink: {
            text: "Edit on Github"
        }
    }
    }
)