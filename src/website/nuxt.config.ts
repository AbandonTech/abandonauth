import tailwindcss from "@tailwindcss/vite";

import { apiAddress, apiForwardTarget } from "./server/utils/apiProxy";
import { siteCallbackUri } from "./server/utils/siteCallback";

const loginQuery = new URLSearchParams({
  application_id: process.env.ABANDON_AUTH_DEVELOPER_APP_ID ?? "",
  callback_uri: siteCallbackUri(process.env.ABANDON_AUTH_SITE_URL ?? ""),
});

const apiTarget = apiAddress(process.env.ABANDON_AUTH_API_ADDRESS, process.env.ABANDON_AUTH_URL);

export default defineNuxtConfig({
  compatibilityDate: "2026-08-30",
  nitro: {
    devProxy: {
      "/api": apiForwardTarget(apiTarget),
    },
  },
  devtools: {
    enabled: true,
  },
  css: ["~/assets/css/main.css", "@fortawesome/fontawesome-svg-core/styles.css"],
  vite: {
    plugins: [tailwindcss()],
  },
  app: {
    head: {
      title: "AbandonAuth",
    },
  },
  runtimeConfig: {
    // Private and top-level, so a container start can move it with
    // NUXT_API_ADDRESS without the site being rebuilt.
    apiAddress: apiTarget,
    public: {
      abandonAuthUrl: process.env.ABANDON_AUTH_URL,
      abandonAuthApplicationId: process.env.ABANDON_AUTH_DEVELOPER_APP_ID,
      loginPath: `/login?${loginQuery}`,
    },
  },
});
