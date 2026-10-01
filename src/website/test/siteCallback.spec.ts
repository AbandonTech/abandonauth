import { describe, expect, it } from "vitest";

import { apiProxyRequest } from "../server/utils/apiProxy";
import { siteCallbackUri } from "../server/utils/siteCallback";

describe("siteCallbackUri", () => {
  it("returns the browser to the origin it was given", () => {
    expect(siteCallbackUri("http://localhost:3000")).toBe("http://localhost:3000/api/ui");
    expect(siteCallbackUri("https://abandonauth.test")).toBe("https://abandonauth.test/api/ui");
  });

  it("names the API's own site entry, which the forwarder passes on unchanged", () => {
    const callback = new URL(siteCallbackUri("http://localhost:3000"));

    expect(apiProxyRequest("http://localhost:8001", callback.pathname).target).toBe("http://localhost:8001/api/ui");
  });

  it("spells one address whether or not the origin carries a trailing slash", () => {
    expect(siteCallbackUri("http://localhost:3000/")).toBe(siteCallbackUri("http://localhost:3000"));
  });

  // `abandonauth provision` registers the callback from the same setting, and
  // the two are matched exactly, so these are the spellings its tests expect.
  it.each([
    ["https://auth.example.test", "https://auth.example.test/api/ui"],
    ["https://auth.example.test/", "https://auth.example.test/api/ui"],
    ["HTTPS://Auth.Example.TEST/", "HTTPS://Auth.Example.TEST/api/ui"],
    ["https://auth.example.test:443", "https://auth.example.test:443/api/ui"],
    ["https://auth.example.test:8443", "https://auth.example.test:8443/api/ui"],
    ["http://localhost:3000", "http://localhost:3000/api/ui"],
  ])("keeps the spelling of %s and adds one slash before the path", (origin, callback) => {
    expect(siteCallbackUri(origin)).toBe(callback);
  });

  it("falls back to a path rather than an origin it invented", () => {
    expect(siteCallbackUri("")).toBe("/api/ui");
  });
});
