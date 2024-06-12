// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: {
    enabled: true,

    timeline: {
      enabled: true
    }
  },
  css: ["/assets/css/main.css", "@fortawesome/fontawesome-svg-core/styles.css"],

  modules: ["@nuxtjs/tailwindcss"],
  tailwindcss: {
    exposeConfig: true,
  },
  app: {
    head: {
      title: "AbandonAuth",
    }
  },
  runtimeConfig: {
    public: {
        abandonAuthUrl: process.env.ABANDON_AUTH_URL,
        abandonAuthApplicationId: process.env.ABANDON_AUTH_DEVELOPER_APP_ID,
    }
  }
})
