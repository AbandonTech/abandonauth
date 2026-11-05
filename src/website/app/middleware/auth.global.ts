// The authorization and consent pages are reached by a person a public client
// sent here, who need not be signed in to this site; every dashboard page stays
// gated.
const publicPaths = new Set(["/login", "/authorize", "/consent"])

export default defineNuxtRouteMiddleware(async (to) => {
    if (publicPaths.has(to.path)) return

    if (await signedIn(useRequestFetch())) return

    const { loginPath } = useRuntimeConfig().public

    return navigateTo(loginPath)
})
