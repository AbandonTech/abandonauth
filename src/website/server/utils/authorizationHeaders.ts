const authorizationPagePaths = new Set(["/authorize", "/authorize/"]);

/**
 * authorizationPageHeaders are the headers the authorization page is served
 * with, or none for any other page. It is never cached, framed or used as a
 * referrer, because what it leads to carries a handle or a code.
 */
export function authorizationPageHeaders(pathname: string): Record<string, string> | undefined {
  if (!authorizationPagePaths.has(pathname)) {
    return undefined;
  }

  return {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
  };
}
