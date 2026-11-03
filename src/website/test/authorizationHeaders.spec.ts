import { describe, expect, it } from "vitest";

import { authorizationPageHeaders } from "../server/utils/authorizationHeaders";

describe("authorizationPageHeaders", () => {
  it("keeps the authorization page out of every cache, frame and referrer", () => {
    const expected = {
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    };

    expect(authorizationPageHeaders("/authorize")).toEqual(expected);
    expect(authorizationPageHeaders("/authorize/")).toEqual(expected);
  });

  it("leaves every other page as it is", () => {
    for (const pathname of ["/", "/login", "/developer-applications", "/authorized", "/authorize/other", "/api/oauth/authorize"]) {
      expect(authorizationPageHeaders(pathname)).toBeUndefined();
    }
  });
});
