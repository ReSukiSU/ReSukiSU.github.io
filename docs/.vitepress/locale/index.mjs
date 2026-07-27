import en from "./en.mjs";
import zh_cn from "./zh-cn.mjs";

export default {
  locales: {
    root: {
      label: "English",
      lang: en.lang,
      themeConfig: en.themeConfig,
      description: en.description,
    },
    "zh-Hans": {
      label: "简体中文",
      lang: zh_cn.lang,
      themeConfig: zh_cn.themeConfig,
      description: zh_cn.description,
    },
  },
};
