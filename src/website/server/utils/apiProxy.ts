import { joinURL, withoutBase } from "ufo";

/** Where this site serves the API. The API answers at /me, not at /api/me. */
export const apiPrefix = "/api";

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
 * apiProxyRequest describes how a call the browser makes to /api reaches the
 * API.
 *
 * A redirect is handed back to the browser rather than followed here. The
 * sign-in callbacks answer with a redirect that also carries the session
 * cookie, and following it on the server would swallow both.
 */
export function apiProxyRequest(baseUrl: string, path: string) {
  return {
    target: joinURL(baseUrl, withoutBase(path, apiPrefix)),
    options: { fetchOptions: { redirect: "manual" as const } },
  };
}
