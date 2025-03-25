// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  nitro: {
    devProxy: {
      '/api': process.env.ABANDON_AUTH_URL,
    },
  },
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
        githubRedirect: process.env.GITHUB_REDIRECT,
        discordRedirect: process.env.DISCORD_REDIRECT,
        loginPath: `/login?application_id=${process.env.ABANDON_AUTH_DEVELOPER_APP_ID}&callback_uri=${process.env.ABANDON_AUTH_URL}/api/ui`
    }
  }
})
