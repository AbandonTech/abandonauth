export default defineNuxtRouteMiddleware((to, from) => {
    if (to.path === "/login" ) return

    const auth = useCookie("Authorization");
    if (!auth.value) {
        const config = useRuntimeConfig();
        const { loginPath }  = config.public;

        return navigateTo(loginPath)
    }
})
