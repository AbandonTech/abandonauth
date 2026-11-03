// @vitest-environment nuxt
import { mountSuspended, registerEndpoint } from "@nuxt/test-utils/runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AuthorizePage from "../app/pages/authorize.vue";
import authGate from "../app/middleware/auth.global";

const handle = "A".repeat(42) + "Q";
const goneHandle = "B".repeat(42) + "A";
const unavailable = "This sign-in request is no longer available. Return to the application and start again.";
const hostileName = `<script>alert("x")</script><img src=x onerror=alert(1)>`;

let seenAt: { path: string; hash: string }[] = [];

registerEndpoint(`/api/oauth/authorization/${handle}`, () => {
  seenAt.push({ path: window.location.pathname, hash: window.location.hash });

  return {
    application_name: hostileName,
    scopes: ["openid", "profile", "offline_access"],
    expires_at: "2026-11-02T12:05:00Z",
    providers: ["discord", "github", "google", "steam"],
  };
});

registerEndpoint(`/api/oauth/authorization/${goneHandle}`, (event) => {
  event.node.res.statusCode = 404;

  return { detail: "Authorization request unavailable" };
});

let currentUserAsked = 0;

registerEndpoint("/api/me", (event) => {
  currentUserAsked++;
  event.node.res.statusCode = 403;

  return { detail: "Authentication required" };
});

// What a malformed fragment would name if the page read it carelessly. Each is
// an endpoint here, so asking for any of them is counted; one that names the
// genuine handle is counted by the genuine endpoint.
const malformed: [string, string][] = [
  ["no fragment", ""],
  ["an empty handle", "#request="],
  ["a short handle", `#request=${handle.slice(1)}`],
  ["a long handle", `#request=${handle}A`],
  ["an oversized fragment", `#request=${"A".repeat(4096)}`],
  ["a padded handle", `#request=${handle.slice(1)}=`],
  ["a repeated handle", `#request=${handle}&request=${handle}`],
  ["another name", `#handle=${handle}`],
  ["a query-shaped fragment", `#?request=${handle}`],
  ["a non-base64url handle", `#request=${handle.slice(1)}+`],
];

let carelessRequests = 0;

for (const [, fragment] of malformed) {
  const named = fragment.replace(/^#(\?)?(request|handle)=/, "");

  if (named !== "" && named !== handle && named.length < 200) {
    registerEndpoint(`/api/oauth/authorization/${named}`, () => {
      carelessRequests++;

      return {};
    });
  }
}

async function openWith(fragment: string) {
  window.history.replaceState(null, "", `/authorize${fragment}`);

  const page = await mountSuspended(AuthorizePage, { route: `/authorize${fragment}` });

  await vi.waitFor(() => expect(page.text()).not.toContain("Loading the request"));

  return page;
}

describe("the authorization page", () => {
  beforeEach(() => {
    seenAt = [];
    carelessRequests = 0;
  });

  it("takes the handle out of the address before asking for the request, and asks only by path", async () => {
    const page = await openWith(`#request=${handle}`);

    expect(seenAt).toEqual([{ path: "/authorize", hash: "" }]);
    expect(window.location.pathname + window.location.search + window.location.hash).toBe("/authorize");
    expect(page.text()).toContain("wants you to sign in");
  });

  it("renders the application name as text, never as markup", async () => {
    const page = await openWith(`#request=${handle}`);

    expect(page.find('[data-test="application-name"]').text()).toBe(hostileName);
    expect(page.find("script").exists()).toBe(false);
    expect(page.find("img").exists()).toBe(false);
  });

  it("describes every requested permission, the username's correlation and the offline session's limits", async () => {
    const page = await openWith(`#request=${handle}`);
    const permissions = page.find('[data-test="permissions"]').text();

    expect(permissions).toContain("only this application receives");
    expect(permissions).toContain("can be the same at every application");
    expect(permissions).toContain("up to 90 days");
    expect(permissions).toContain("ten active sessions");
    expect(permissions).toContain("ends the least recently created one");
  });

  it("offers each provider and cancellation as a form posting to exactly its own address", async () => {
    const page = await openWith(`#request=${handle}`);

    const forms = page.findAll("form").map((form) => [form.attributes("method"), form.attributes("action")]);

    expect(forms).toEqual([
      ["post", `/api/oauth/authorization/${handle}/discord`],
      ["post", `/api/oauth/authorization/${handle}/github`],
      ["post", `/api/oauth/authorization/${handle}/google`],
      ["post", `/api/oauth/authorization/${handle}/steam`],
      ["post", `/api/oauth/authorization/${handle}/cancel`],
    ]);

    for (const form of page.findAll("form")) {
      expect(form.findAll("input")).toHaveLength(0);
    }
  });

  it("says the request is gone when the API no longer holds it", async () => {
    const page = await openWith(`#request=${goneHandle}`);

    expect(page.find('[data-test="unavailable"]').text()).toBe(unavailable);
    expect(page.findAll("form")).toHaveLength(0);
  });

  for (const [name, fragment] of malformed) {
    it(`asks the API nothing for ${name}`, async () => {
      const page = await openWith(fragment);

      expect(seenAt).toHaveLength(0);
      expect(carelessRequests).toBe(0);
      expect(page.find('[data-test="unavailable"]').text()).toBe(unavailable);
      expect(window.location.hash).toBe("");
    });
  }
});

describe("the session gate", () => {
  beforeEach(() => {
    currentUserAsked = 0;
  });

  it("lets anyone reach the authorization page and the login page without asking who they are", async () => {
    for (const path of ["/authorize", "/login"]) {
      expect(await authGate({ path } as never, {} as never)).toBeUndefined();
    }

    expect(currentUserAsked).toBe(0);
  });

  it("still asks who the browser is before every dashboard page", async () => {
    for (const path of ["/", "/developer-applications", "/authorize/other"]) {
      const before = currentUserAsked;

      try {
        await authGate({ path } as never, {} as never);
      } catch {
        // A refused gate navigates away, which outside a page can throw.
      }

      expect(currentUserAsked, path).toBeGreaterThan(before);
    }
  });
});
