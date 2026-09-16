/** The header this site echoes the readable half of its session in. */
export const csrfHeader = "X-CSRF-Token";

/** Where the API says who the browser is signed in as. */
export const currentUserPath = "/api/me";

/** Where the API ends a browser session. */
export const logoutPath = "/api/ui/logout";

// Over TLS the API prefixes its cookies with __Host-, which a browser returns
// only to the exact host that set them. Development runs without TLS, where a
// browser would never send such a cookie back, so both names are looked for.
const csrfCookieNames = ["__Host-abandonauth_csrf", "abandonauth_csrf"];

/** csrfToken reads the session's readable half out of a cookie header. */
export function csrfToken(cookies: string): string {
  const held = new Map<string, string>();

  for (const entry of cookies.split(";")) {
    const [name, ...value] = entry.split("=");

    if (name !== undefined && value.length > 0) {
      held.set(name.trim(), value.join("=").trim());
    }
  }

  for (const name of csrfCookieNames) {
    const value = held.get(name);

    if (value) {
      return value;
    }
  }

  return "";
}

/**
 * siteRequestHeaders marks a request as one this site meant to make.
 *
 * A page on another origin can cause the browser to send a cookie but cannot
 * read one, so copying the token out of a cookie and into a header is something
 * only this site can do. Requests that only read do not need it.
 */
export function siteRequestHeaders(cookies = browserCookies()): Record<string, string> {
  return { [csrfHeader]: csrfToken(cookies) };
}

/**
 * signedIn reports whether the browser behind a request holds a session.
 *
 * The session cookie is unreadable by script, and a cookie that can be seen may
 * still have been revoked, so the API is asked rather than the browser.
 */
export async function signedIn(request: (path: string) => Promise<unknown>): Promise<boolean> {
  try {
    await request(currentUserPath);

    return true;
  } catch {
    return false;
  }
}

function browserCookies(): string {
  return typeof document === "undefined" ? "" : document.cookie;
}
