export default {
    lang: "zh-CN",
    description: "让SukiSU再次伟大！",
    themeConfig: {
        nav: [
        { text: '<i class="ri-home-2-fill"></i> 主页', link: '/zh-Hans/' },
        { text: '<i class="ri-book-2-fill"></i> 指导', link: '/zh-Hans/guide/install' },
        { text: '<i class="ri-links-line"></i> 常用链接',items: [
            { text: 'KernelSU 文档', link: 'https://kernelsu.org/' },
            { text: 'KernelSU 模块仓库', link: 'https://modules.kernelsu.org/'}
        ]}
        ],

        sidebar: [
        {
            text: '开始使用',
            items: [
            { text: '安装', link: '/zh-Hans/guide/install' },
            { text: '构建内核', link: '/zh-Hans/guide/build',collapsed: true,items: [
                { text: '参考钩子', link: '/zh-Hans/guide/manual-integrate' }
            ]},
            { text: '非官方支持设备', link: '/zh-Hans/guide/unofficial-devices' },
            { text: '常见问题', link: '/zh-Hans/guide/faq' }
            ]
        },
        {text: '关于 ReSukiSU',link:'/zh-Hans/guide/introduce'}
        ],
        editLink: {
            text: "在 GitHub 上编辑此页面",
            pattern: "https://github.com/ReSukiSU/ReSukiSU.github.io/edit/main/docs/:path"
        },
        docFooter: {
            prev: '上一页',
            next: '下一页'
        },
        lastUpdated: {
            text: '最后更新于'
        },
        returnToTopLabel: '返回顶部',
        sidebarMenuLabel: '菜单',
        darkModeSwitchLabel: '外观',
        langMenuLabel: '切换语言',
        outline: {
            label: '本页目录'
        }
    }
}
