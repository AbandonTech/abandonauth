import { describe, expect, it } from "vitest";

import { apiProxyRequest } from "../server/utils/apiProxy";

describe("apiProxyRequest", () => {
  it("addresses the API the site is configured against", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/me").target).toBe("https://abandonauth.test/api/me");
  });

  it("keeps the query a caller sent", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord/authorize?application_id=one").target).toBe(
      "https://abandonauth.test/api/ui/discord/authorize?application_id=one",
    );
  });

  it("returns a redirect to the browser instead of following it", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord-callback").options.fetchOptions.redirect).toBe(
      "manual",
    );
  });
});
