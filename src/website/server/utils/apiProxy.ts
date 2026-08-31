import { joinURL } from "ufo";

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
    target: joinURL(baseUrl, path),
    options: { fetchOptions: { redirect: "manual" as const } },
  };
}
