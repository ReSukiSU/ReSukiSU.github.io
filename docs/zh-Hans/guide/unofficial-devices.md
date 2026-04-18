---
gitChangelog: false
---

# 非官方支持设备/项目

::: warning
本文档列出由其他开发者维护的支持 ReSukiSU 的GKI/非 GKI 设备的内核源码/项目
:::

::: warning
本文档仅方便查找设备对应源码/项目，这并不意味该源码/项目**被** ReSukiSU 开发者**审查**，你应自行承担使用风险。
:::

::: info
请通过 [向文档创建issue](https://github.com/ReSukiSU/ReSukiSU.github.io/issues) 来添加设备
:::

<script setup>
import data from '../../repos.json'
</script>

<table>
   <thead>
      <tr>
         <th>维护者</th>
         <th>仓库地址</th>
         <th>支持设备</th>
      </tr>
   </thead>
   <tbody>
    <tr v-for="repo in data" :key="repo.devices">
        <td><a :href="repo.maintainer_link" target="_blank" rel="noreferrer">{{ repo.maintainer }}</a></td>
        <td><a :href="repo.kernel_link" target="_blank" rel="noreferrer">{{ repo.kernel_name }}</a></td>
        <td>{{ repo.devices }}</td>
    </tr>
   </tbody>
</table>
