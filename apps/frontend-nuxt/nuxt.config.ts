// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
    compatibilityDate: "2025-07-15",
    devtools: { enabled: true },

    css: [
        "~/assets/scss/global/_global.scss",
        "~/assets/scss/global/_fonts.scss",
        "~/assets/scss/global/_transitions.scss",
    ],

    vite: {
        css: {
            preprocessorOptions: {
                scss: {
                    additionalData: `@use "@/assets/scss/global/_variables.scss" as * ;`,
                },
            },
        },
    },

    app: {
        pageTransition: {
            name: "page",
            mode: "out-in",
        },
    },

    components: [
        {
            path: "components",
            pathPrefix: false,
        },
    ],

    modules: ["@nuxt/icon"],

    runtimeConfig: {
        public: {
            apiBase: "http://localhost:5284",
        },
    },
});
