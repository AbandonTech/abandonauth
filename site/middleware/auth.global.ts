export default defineNuxtRouteMiddleware((to, from) => {
    if (to.path === "/login" ) return

    const auth = useCookie("Authorization");
    if (!auth.value) {
        const config = useRuntimeConfig();
        const abandonAuthApplicationId = config.public.abandonAuthApplicationId;

        console.log("redirecting to login")
        return navigateTo(`/login?application_id=${abandonAuthApplicationId}&callback_uri=/login/abandonauth-callback`)
    }
})
