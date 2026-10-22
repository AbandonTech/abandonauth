// @vitest-environment nuxt
import { mountSuspended, registerEndpoint } from "@nuxt/test-utils/runtime";
import { beforeEach, describe, expect, it } from "vitest";

import { csrfHeader } from "../app/utils/browserSession";
import Dashboard from "../app/layouts/dashboard.vue";

let received: { method: string; csrf: string | undefined }[] = [];

registerEndpoint("/api/ui/logout", {
  method: "POST",
  handler: (event) => {
    received.push({ method: event.method, csrf: event.headers.get(csrfHeader) ?? undefined });

    return "";
  },
});

async function pressLogout() {
  const page = await mountSuspended(Dashboard);

  await page.find("button").trigger("click");
  await new Promise((settle) => setTimeout(settle, 0));
}

describe("logging out", () => {
  beforeEach(() => {
    received = [];
    document.cookie = "abandonauth_csrf=a-token";
  });

  it("asks the API to delete the session rather than clearing a cookie", async () => {
    await pressLogout();

    expect(received).toHaveLength(1);
    expect(received[0]?.method).toBe("POST");
  });

  it("proves the request came from this site", async () => {
    await pressLogout();

    expect(received[0]?.csrf).toBe("a-token");
  });
});
