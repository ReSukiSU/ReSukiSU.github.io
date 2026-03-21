# 常见问题

## `MODULE_DEVICE_TABLE` 宏调用编译报错 {#MODULE-DEVICE-TABLE}
出现该报错的原因是内核源码中的 `input handler` 已损坏，导致宏调用时参数类型校验、语法解析等环节无法正常执行。

跟随[文档](manual-integrate.md#input-hooks)内容对内核源码增加对应调用即可

## 模块不工作  {#MODULE-NOT-WORKING}

::: info Notes
这部分仅针对需要修改sepolicy的模块进行解答。如 LSPosed/ZygiskNext 模块会出现此问题。
:::

自 ReSukiSU commit [`436d333`](https://github.com/ReSukiSU/ReSukiSU/commit/436d333) 起，由于该 commit 跟随上游KernelSU重构了sepolicy部分，因此在内核/管理器**其中一个 低于 34634 或者在此commit之前的版本**会出现模块不工作的情况

请将<mark>内核/管理器**全部**升级到 34634 或者在此commit之后的版本</mark>即可解决问题。

