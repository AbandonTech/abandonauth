export default defineNuxtRouteMiddleware(async (to) => {
    if (to.path === "/login") return

    if (await signedIn(useRequestFetch())) return

    const { loginPath } = useRuntimeConfig().public

    return navigateTo(loginPath)
})
