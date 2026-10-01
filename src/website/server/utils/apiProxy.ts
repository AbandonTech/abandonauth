import { joinURL } from "ufo";

/** The route root the API serves everything under, which this site preserves. */
export const apiRoot = "/api";

/**
 * apiAddress is where this site's own server sends a call to the API.
 *
 * The public origin is the one a browser uses and the one baked into the
 * registered callback URIs, and it does not resolve to the API from inside the
 * deployment, so the address the server dials is configured separately and
 * falls back to the public one.
 */
export function apiAddress(configured: string | undefined, publicOrigin: string | undefined): string {
  return configured?.trim() ? configured : (publicOrigin ?? "");
}

/**
 * apiForwardTarget is what the development forwarder is pointed at.
 *
 * That forwarder is mounted on the route root and hands on the path with the
 * root already removed, so the root has to be part of the address it dials for
 * the API to receive the path the browser asked for.
 */
export function apiForwardTarget(address: string): string {
  return joinURL(address, apiRoot);
}

/**
 * apiProxyRequest describes how a call the browser makes reaches the API.
 *
 * The path is passed on whole: it is the API's own address, not something this
 * site adds. A redirect is handed back to the browser rather than followed
 * here, because the sign-in callbacks answer with a redirect that also carries
 * the session cookie, and following it on the server would swallow both.
 */
export function apiProxyRequest(baseUrl: string, path: string) {
  return {
    target: joinURL(baseUrl, path),
    options: { fetchOptions: { redirect: "manual" as const } },
  };
}
