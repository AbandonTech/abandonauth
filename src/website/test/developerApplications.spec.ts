// @vitest-environment nuxt
import { mountSuspended, registerEndpoint } from "@nuxt/test-utils/runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ApplicationsPage from "../app/pages/developer-applications/index.vue";
import ApplicationPage from "../app/pages/developer-applications/[id].vue";
import { clientTypeLabels } from "../app/types/developerApplicationDto";

const applicationId = "00000000-0000-0000-0000-000000000001";
const ownerId = "00000000-0000-0000-0000-000000000002";

type Registration = { name: string; client_type: string };

let registrations: Registration[] = [];

registerEndpoint("/api/me", () => ({ id: ownerId, username: "the developer" }));
registerEndpoint("/api/user/applications", () => []);

// The test environment hands an endpoint the request body as the text the
// page sent.
registerEndpoint("/api/developer_application", {
  method: "POST",
  handler: (event) => {
    const sent = (event.node.req as unknown as { body: string }).body;
    const registration = JSON.parse(sent) as Registration;
    registrations.push(registration);

    const answer = { id: applicationId, name: registration.name, owner_id: ownerId, client_type: registration.client_type };

    return registration.client_type === "confidential" ? { ...answer, token: "a-placeholder-token" } : answer;
  },
});

registerEndpoint("/api/developer_application/public-client", () => ({
  id: applicationId,
  name: "an installed application",
  owner_id: ownerId,
  client_type: "public",
  callback_uris: ["http://127.0.0.1/oauth/callback"],
}));

registerEndpoint("/api/developer_application/confidential-client", () => ({
  id: applicationId,
  name: "a server-side application",
  owner_id: ownerId,
  client_type: "confidential",
  callback_uris: ["https://example.test/return"],
}));

async function register(name: string, clientType?: string) {
  const page = await mountSuspended(ApplicationsPage, { route: "/developer-applications" });

  if (clientType) {
    await page.find(`input[type="radio"][value="${clientType}"]`).setValue(true);
  }

  await page.find('input[type="text"]').setValue(name);
  await page.find('input[type="text"]').trigger("keydown.enter");

  return page;
}

describe("registering an application", () => {
  beforeEach(() => {
    registrations = [];
  });

  it("offers both client types with their explanations and chooses neither for the person", async () => {
    const page = await mountSuspended(ApplicationsPage, { route: "/developer-applications" });

    expect(clientTypeLabels.confidential).toBe(
      "Confidential client — server-side application that can protect a credential",
    );
    expect(clientTypeLabels.public).toBe(
      "Public client — installed application that cannot protect a shared credential",
    );
    expect(page.find('[data-test="client-type"]').text()).toContain(clientTypeLabels.confidential);
    expect(page.find('[data-test="client-type"]').text()).toContain(clientTypeLabels.public);

    for (const radio of page.findAll('input[type="radio"]')) {
      expect((radio.element as HTMLInputElement).checked).toBe(false);
    }
  });

  it("registers nothing until a client type is chosen", async () => {
    const page = await register("an application");

    await vi.waitFor(() => expect(page.text()).toContain("Choose a client type"));
    expect(registrations).toHaveLength(0);
  });

  it("sends exactly the chosen type and shows a confidential application its token once", async () => {
    const page = await register("a server-side application", "confidential");

    await vi.waitFor(() => expect(page.text()).toContain("a-placeholder-token"));
    expect(registrations).toEqual([{ name: "a server-side application", client_type: "confidential" }]);
    expect(page.text()).toContain("Your token will never be visible again!");
  });

  it("shows a public client no credential", async () => {
    const page = await register("an installed application", "public");

    await vi.waitFor(() => expect(page.find('[data-test="no-credential"]').exists()).toBe(true));
    expect(registrations).toEqual([{ name: "an installed application", client_type: "public" }]);
    expect(page.text()).not.toContain("Token:");
  });
});

describe("an application's page", () => {
  it("states a public client's type, offers no credential reset and explains loopback redirects", async () => {
    const page = await mountSuspended(ApplicationPage, { route: "/developer-applications/public-client" });

    await vi.waitFor(() => expect(page.find('[data-test="client-type"]').exists()).toBe(true));
    expect(page.find('[data-test="client-type"]').text()).toBe(clientTypeLabels.public);
    expect(page.findAll("button").some((button) => button.text() === "Reset Token")).toBe(false);
    expect(page.find('[data-test="loopback-help"]').text()).toContain("http://127.0.0.1/oauth/callback");
    expect(page.find('[data-test="loopback-help"]').text()).toContain("http://[::1]/oauth/callback");
    expect(page.text()).toContain("Delete Application");
  });

  it("keeps a confidential application's credential reset and says nothing about loopback", async () => {
    const page = await mountSuspended(ApplicationPage, { route: "/developer-applications/confidential-client" });

    await vi.waitFor(() => expect(page.find('[data-test="client-type"]').exists()).toBe(true));
    expect(page.find('[data-test="client-type"]').text()).toBe(clientTypeLabels.confidential);
    expect(page.findAll("button").some((button) => button.text() === "Reset Token")).toBe(true);
    expect(page.find('[data-test="loopback-help"]').exists()).toBe(false);
  });
});
