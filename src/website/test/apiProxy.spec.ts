import { describe, expect, it } from "vitest";

import { apiAddress, apiProxyRequest } from "../server/utils/apiProxy";

describe("apiProxyRequest", () => {
  it("addresses the API the site is configured against", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/me").target).toBe("https://abandonauth.test/me");
  });

  it("keeps the query a caller sent", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord/authorize?application_id=one").target).toBe(
      "https://abandonauth.test/ui/discord/authorize?application_id=one",
    );
  });

  it("returns a redirect to the browser instead of following it", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord-callback").options.fetchOptions.redirect).toBe(
      "manual",
    );
  });
});

describe("apiAddress", () => {
  it("dials the address the site was given", () => {
    expect(apiAddress("http://abandonauth:8000", "https://abandonauth.test")).toBe("http://abandonauth:8000");
  });

  it("dials the public origin when it was given no other address", () => {
    expect(apiAddress(undefined, "https://abandonauth.test")).toBe("https://abandonauth.test");
    expect(apiAddress("", "https://abandonauth.test")).toBe("https://abandonauth.test");
  });
});
