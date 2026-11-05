import { describe, expect, it } from "vitest";

import { authorizationPageHeaders } from "../server/utils/authorizationHeaders";

describe("authorizationPageHeaders", () => {
  it("keeps the authorization and consent pages out of every cache, frame and cross-origin referrer", () => {
    const expected = {
      "Cache-Control": "no-store",
      "Referrer-Policy": "same-origin",
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    };

    for (const pathname of ["/authorize", "/authorize/", "/consent", "/consent/"]) {
      expect(authorizationPageHeaders(pathname), pathname).toEqual(expected);
    }
  });

  it("leaves every other page as it is", () => {
    for (const pathname of [
      "/",
      "/login",
      "/developer-applications",
      "/authorized",
      "/authorize/other",
      "/api/oauth/authorize",
      "/consents",
      "/consent/other",
      "/consent//",
      "/Consent",
      "/api/oauth/consent",
    ]) {
      expect(authorizationPageHeaders(pathname), pathname).toBeUndefined();
    }
  });
});
