const authorizationPagePaths = new Set(["/authorize", "/authorize/", "/consent", "/consent/"]);

/**
 * authorizationPageHeaders are the headers the authorization and consent pages
 * are served with, or none for any other page. They are never cached, framed or
 * disclosed as a cross-origin referrer, because what they lead to carries a
 * handle or a code; `same-origin` rather than `no-referrer` keeps their form POSTs
 * from carrying the `Origin: null` the API's exact site-Origin check refuses.
 */
export function authorizationPageHeaders(pathname: string): Record<string, string> | undefined {
  if (!authorizationPagePaths.has(pathname)) {
    return undefined;
  }

  return {
    "Cache-Control": "no-store",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
  };
}
