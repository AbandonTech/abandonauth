// @vitest-environment nuxt
import { mountSuspended } from "@nuxt/test-utils/runtime";
import { describe, expect, it } from "vitest";

import LoginPage from "../app/pages/login.vue";

const applicationId = "0e9a4c1e-1d0e-4f5e-8a3f-2b6c9d5e7a10";
const callbackUri = "https://example.test/return";

async function loginPageFor(query: string) {
  return mountSuspended(LoginPage, { route: `/login${query}` });
}

describe("the login page", () => {
  it("offers both providers", async () => {
    const page = await loginPageFor(`?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`);

    expect(page.text()).toContain("Login with Discord");
    expect(page.text()).toContain("Login with Github");
  });

  it("asks the API to start the sign-in, carrying the application and callback it was given", async () => {
    const page = await loginPageFor(`?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`);

    const addresses = page.findAll("a").map((link) => link.attributes("href"));

    expect(addresses).toContain(
      `/api/ui/discord/authorize?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`,
    );
    expect(addresses).toContain(
      `/api/ui/github/authorize?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`,
    );
    expect(addresses).toContain(
      `/api/ui/google/authorize?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`,
    );
  });

  it("sends nothing to a provider itself", async () => {
    const page = await loginPageFor(`?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`);

    for (const link of page.findAll("a")) {
      expect(link.attributes("href")?.startsWith("/api/ui/")).toBe(true);
    }
  });

  it("says what is missing when it was reached without an application or a callback", async () => {
    const page = await loginPageFor("");

    expect(page.text()).toContain("application_id is required");
    expect(page.text()).toContain("callback_uri is required");
  });
});
