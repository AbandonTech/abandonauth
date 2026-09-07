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

  it("falls back to a path rather than an origin it invented", () => {
    expect(siteCallbackUri("")).toBe("/api/ui");
  });
});
