# OPPO Devices

This page covers the ReSukiSU installation process for OPPO devices.

::: warning
Back up important data and prepare the stock images matching your current system version before flashing.
:::

## LKM Installation

LKM installation is identical to that on a standard GKI device. See [LKM installation for generic GKI devices](./gki#lkm).

## GKI Installation

Due to OPPO's modifications to `f2fs`, generic GKI images cannot be used. You need to compile a kernel yourself from OPPO's open-source code. See the [GKI device kernel build guide](./gki#built-in).

The following projects also use `GitHub Actions` to quickly build kernel images with `ReSukiSU`.

<script setup>
import data from '../../oppo_kernel_action_build.json'
</script>

<table>
   <thead>
      <tr>
         <th>Maintainer</th>
         <th>Repository</th>
         <th>Supported devices</th>
      </tr>
   </thead>
   <tbody>
    <tr v-for="repo in data" :key="repo.devices">
        <td><a :href="repo.maintainer_link" target="_blank" rel="noreferrer">{{ repo.maintainer }}</a></td>
        <td><a :href="repo.repo_link" target="_blank" rel="noreferrer">{{ repo.repo_name }}</a></td>
        <td>{{ repo.devices }}</td>
    </tr>
   </tbody>
</table>
