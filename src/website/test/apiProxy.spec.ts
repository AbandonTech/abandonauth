import { describe, expect, it } from "vitest";

import { apiAddress, apiForwardTarget, apiProxyRequest } from "../server/utils/apiProxy";

describe("apiProxyRequest", () => {
  it("asks the API for the address the browser asked for", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/me").target).toBe("https://abandonauth.test/api/me");
  });

  it("keeps the query a caller sent", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord/authorize?application_id=one").target).toBe(
      "https://abandonauth.test/api/ui/discord/authorize?application_id=one",
    );
  });

  it("keeps a query value exactly as it was encoded", () => {
    expect(
      apiProxyRequest("https://abandonauth.test", "/api/ui/discord/authorize?callback_uri=https%3A%2F%2Fx.test%2Fr")
        .target,
    ).toBe("https://abandonauth.test/api/ui/discord/authorize?callback_uri=https%3A%2F%2Fx.test%2Fr");
  });

  it("returns a redirect to the browser instead of following it", () => {
    expect(apiProxyRequest("https://abandonauth.test", "/api/ui/discord-callback").options.fetchOptions.redirect).toBe(
      "manual",
    );
  });
});

describe("apiForwardTarget", () => {
  it("carries the route root, which the forwarder removes before dialling", () => {
    expect(apiForwardTarget("http://abandonauth:8000")).toBe("http://abandonauth:8000/api");
    expect(apiForwardTarget("http://abandonauth:8000/")).toBe("http://abandonauth:8000/api");
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
