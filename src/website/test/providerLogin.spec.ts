import { describe, expect, it } from "vitest";

import { providerLoginUrl } from "../app/utils/providerLogin";

describe("providerLoginUrl", () => {
  it("sends the browser to the API to have a sign-in started", () => {
    expect(providerLoginUrl("discord", "00000000-0000-0000-0000-000000000001", "https://example.test/return")).toBe(
      "/api/ui/discord/authorize" +
        "?application_id=00000000-0000-0000-0000-000000000001" +
        "&callback_uri=https%3A%2F%2Fexample.test%2Freturn",
    );
  });

  it("names the provider in the path", () => {
    expect(providerLoginUrl("github", "an-application", "https://example.test/return")).toContain(
      "/api/ui/github/authorize",
    );
  });

  it("encodes a callback that carries a query of its own", () => {
    const url = providerLoginUrl("discord", "an-application", "https://example.test/return?tenant=one&next=two");

    expect(url).toContain("callback_uri=https%3A%2F%2Fexample.test%2Freturn%3Ftenant%3Done%26next%3Dtwo");
    expect(new URLSearchParams(url.split("?")[1]).get("callback_uri")).toBe(
      "https://example.test/return?tenant=one&next=two",
    );
  });

  it("keeps an application that needs encoding out of the neighbouring parameter", () => {
    const url = providerLoginUrl("github", "one&callback_uri=https://attacker.test", "https://example.test/return");

    expect(new URLSearchParams(url.split("?")[1]).get("callback_uri")).toBe("https://example.test/return");
  });

  it("builds no provider address of its own", () => {
    for (const provider of ["discord", "github", "google"] as const) {
      const url = providerLoginUrl(provider, "an-application", "https://example.test/return");

      expect(url.startsWith("/api/")).toBe(true);
      expect(url).not.toContain("discord.com");
      expect(url).not.toContain("github.com");
      expect(url).not.toContain("accounts.google.com");
      expect(url).not.toContain("state=");
    }
  });
});
