---
gitChangelog: false
---

# Unofficially supported devices/project

::: warning
In this page, there are kernels/projects for GKI/non-GKI devices supporting ReSukiSU maintained by other developers.
:::

::: warning
This page is intended only to help you find the source code/project corresponding to your device. It **DOES NOT** mean that the source code/project has been reviewed by ReSukiSU developers. You should use it at your own risk.
:::

::: info
You can [submit a issue](https://github.com/ReSukiSU/ReSukiSU.github.io/issues) to the document repo to add devices you maintaining.
:::

<script setup>
import data from '../repos.json'
</script>

<table>
   <thead>
      <tr>
         <th>Maintainer</th>
         <th>Repository</th>
         <th>Support devices</th>
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
