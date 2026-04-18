export default {
    lang: "en",
    description: "Make SukiSU Great Again!",
    themeConfig: {
        nav: [
        { text: '<i class="ri-home-2-fill"></i> Home', link: '/' },
        { text: '<i class="ri-book-2-fill"></i> Guide', link: '/guide/install' },
        { text: '<i class="ri-links-line"></i> Links',items: [
            { text: 'KernelSU Documentation', link: 'https://kernelsu.org/' },
            { text: 'KernelSU Modules Repository', link: 'https://modules.kernelsu.org/'}
        ]}
        ],
        sidebar: [
        {
            text: 'Get started',
            items: [
            { text: 'Install', link: '/guide/install' },
            { text: 'Building Kernel', link: '/guide/build',collapsed:true, items: [
                { text: 'Manual Hooks', link: '/guide/manual-integrate' }
            ]},
            { text: 'Unofficial Supported Devices', link: '/guide/unofficial-devices' },
            { text: 'FAQ', link: '/guide/faq' }
            ]
        },
        { text:"About ReSukiSU",link: "/guide/introduce"}
        ],
        editLink: {
            text: "Edit page on GitHub",
            pattern: "https://github.com/ReSukiSU/ReSukiSU.github.io/edit/main/docs/:path"
        },
        docFooter: {
            prev: 'Previous page',
            next: 'Next page'
        },
        lastUpdated: {
            text: 'Last updated'
        },
        returnToTopLabel: 'Return to top',
        sidebarMenuLabel: 'Menu',
        darkModeSwitchLabel: 'Appearance',
        langMenuLabel: 'Change language'
    }
}
