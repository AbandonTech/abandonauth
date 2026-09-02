import { joinURL } from "ufo";

import { apiPrefix } from "./apiProxy";

/**
 * siteCallbackUri is where the site's own sign-in returns the browser.
 *
 * It is built on the site's origin rather than the API's: the session cookie is
 * set on the site's origin by the provider callback, and a browser returned to
 * the API directly would send none of it. The prefix comes from the proxy so
 * that the two cannot drift apart.
 */
export function siteCallbackUri(siteOrigin: string): string {
  return joinURL(siteOrigin, apiPrefix, "/ui");
}
