import tailwindcss from "@tailwindcss/vite";

const loginQuery = new URLSearchParams({
  application_id: process.env.ABANDON_AUTH_DEVELOPER_APP_ID ?? "",
  callback_uri: `${process.env.ABANDON_AUTH_URL}/api/ui`,
});

export default defineNuxtConfig({
  compatibilityDate: "2026-08-30",
  nitro: {
    devProxy: {
      "/api": process.env.ABANDON_AUTH_URL,
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
    public: {
      abandonAuthUrl: process.env.ABANDON_AUTH_URL,
      abandonAuthApplicationId: process.env.ABANDON_AUTH_DEVELOPER_APP_ID,
      loginPath: `/login?${loginQuery}`,
    },
  },
});
