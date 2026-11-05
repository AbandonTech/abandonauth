// @vitest-environment nuxt
import { mountSuspended, registerEndpoint } from "@nuxt/test-utils/runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ConsentPage from "../app/pages/consent.vue";

const handle = "A".repeat(42) + "Q";
const goneHandle = "B".repeat(42) + "A";
const unavailable = "This sign-in request is no longer available. Return to the application and start again.";
const hostileName = `<script>alert("x")</script><img src=x onerror=alert(1)>`;
const applicationName = "an installed application";

const userID = "Identify you with your AbandonAuth user ID. This ID is the same for every application.";
const username = "See your AbandonAuth username.";
const staySignedIn = "Keep you signed in for up to 90 days.";

let seenAt: { path: string; hash: string }[] = [];
let model: Record<string, unknown> = {};
let held: Promise<void> = Promise.resolve();

function instantIn(milliseconds: number) {
  return new Date(Date.now() + milliseconds).toISOString().replace(/\.\d+Z$/, "Z");
}

function consentModel(overrides: Record<string, unknown> = {}) {
  return {
    application_name: applicationName,
    scopes: ["openid"],
    expires_at: instantIn(240_000),
    ...overrides,
  };
}

registerEndpoint(`/api/oauth/consent/${handle}`, async () => {
  seenAt.push({ path: window.location.pathname, hash: window.location.hash });

  await held;

  return model;
});

registerEndpoint(`/api/oauth/consent/${goneHandle}`, (event) => {
  event.node.res.statusCode = 404;

  return { detail: "Authorization request unavailable" };
});

const malformed: [string, string][] = [
  ["no fragment", ""],
  ["an empty handle", "#request="],
  ["a short handle", `#request=${handle.slice(1)}`],
  ["a long handle", `#request=${handle}A`],
  ["an oversized fragment", `#request=${"A".repeat(4096)}`],
  ["a padded handle", `#request=${handle.slice(1)}=`],
  ["a repeated handle", `#request=${handle}&request=${handle}`],
  ["another name", `#consent=${handle}`],
  ["a query-shaped fragment", `#?request=${handle}`],
  ["a non-base64url handle", `#request=${handle.slice(1)}+`],
  ["a handle with non-zero tail bits", `#request=${"A".repeat(42)}B`],
  ["extra fragment content", `#request=${handle}&extra=1`],
];

let carelessRequests = 0;

for (const [, fragment] of malformed) {
  const named = fragment.replace(/^#(\?)?(request|consent)=/, "");

  if (named !== "" && named !== handle && named.length < 200) {
    registerEndpoint(`/api/oauth/consent/${named}`, () => {
      carelessRequests++;

      return {};
    });
  }
}

async function openWith(address: string) {
  window.history.replaceState(null, "", `/consent${address}`);

  const page = await mountSuspended(ConsentPage, { route: `/consent${address}` });

  await vi.waitFor(() => expect(page.text()).not.toContain("Loading the request"));

  return page;
}

function permissionsOf(page: Awaited<ReturnType<typeof openWith>>) {
  return page.findAll('[data-test="permissions"] li').map((item) => item.text());
}

describe("the consent page", () => {
  beforeEach(() => {
    seenAt = [];
    carelessRequests = 0;
    model = consentModel();
    held = Promise.resolve();
  });

  it("takes the handle out of the address before asking for the consent, and asks only by path", async () => {
    await openWith(`#request=${handle}`);

    expect(seenAt).toEqual([{ path: "/consent", hash: "" }]);
    expect(window.location.pathname + window.location.search + window.location.hash).toBe("/consent");
  });

  it("names the application in the exact lead sentence", async () => {
    const page = await openWith(`#request=${handle}`);

    expect(page.find("p.mt-6").text()).toBe(`${applicationName} wants to use your AbandonAuth account to:`);
    expect(page.find("h1").text()).toBe("AbandonAuth");
    expect(page.find("img").attributes("src")).toBe("/img/atLogoColor.svg");
  });

  for (const [scopes, expected] of [
    [["openid"], [userID]],
    [["openid", "profile"], [userID, username]],
    [["openid", "offline_access"], [userID, staySignedIn]],
    [["openid", "profile", "offline_access"], [userID, username, staySignedIn]],
  ] as const) {
    it(`states exactly what ${scopes.join(" ")} releases`, async () => {
      model = consentModel({ scopes: [...scopes] });

      const page = await openWith(`#request=${handle}`);

      expect(permissionsOf(page)).toEqual([...expected]);
    });
  }

  for (const [name, scopes] of [
    ["an unknown scope", ["openid", "email"]],
    ["a duplicate scope", ["openid", "openid"]],
    ["an out-of-order scope", ["profile", "openid"]],
    ["a missing openid", ["profile"]],
    ["no scopes", []],
    ["scopes that are not a list", "openid"],
    ["absent scopes", undefined],
    ["a scope hidden in one member", ["openid profile"]],
  ] as const) {
    it(`offers no action for ${name}`, async () => {
      model = consentModel({ scopes });

      const page = await openWith(`#request=${handle}`);

      expect(page.find('[role="alert"]').text()).toBe(unavailable);
      expect(page.findAll("form")).toHaveLength(0);
      expect(page.text()).not.toContain(applicationName);
    });
  }

  it("offers exactly Allow and Cancel as empty forms posting to their own addresses", async () => {
    const page = await openWith(`#request=${handle}`);

    expect(page.findAll("form").map((form) => [form.attributes("method"), form.attributes("action"), form.text()])).toEqual([
      ["post", `/api/oauth/consent/${handle}/allow`, "Allow"],
      ["post", `/api/oauth/consent/${handle}/cancel`, "Cancel"],
    ]);

    expect(page.findAll("input")).toHaveLength(0);
    expect(page.findAll("a")).toHaveLength(0);
    expect(page.findAll("button").map((button) => button.attributes("type"))).toEqual(["submit", "submit"]);
  });

  it("shows no technical or person-specific detail", async () => {
    model = consentModel({
      scopes: ["openid", "profile", "offline_access"],
      user_id: "user-id-sentinel",
      username: "username-sentinel",
      redirect_uri: "redirect-sentinel",
      state: "state-sentinel",
      nonce: "nonce-sentinel",
      code_challenge: "challenge-sentinel",
      code: "code-sentinel",
      provider: "provider-sentinel",
    });

    const page = await openWith(`#request=${handle}`);
    const text = page.text();

    for (const absent of [
      "sentinel", "openid", "offline_access", "scope", "token", "refresh", "expires", "session", "minutes",
      model.expires_at as string, handle,
    ]) {
      expect(text).not.toContain(absent);
    }

    expect(page.html()).not.toContain("sentinel");

    for (const attribute of page.findAll("form").flatMap((form) => Object.entries(form.attributes()))) {
      if (attribute[0] !== "action") {
        expect(attribute[1]).not.toContain(handle);
      }
    }
  });

  it("renders the application name as text, never as markup", async () => {
    model = consentModel({ application_name: hostileName });

    const page = await openWith(`#request=${handle}`);

    expect(page.find("p.mt-6").text()).toBe(`${hostileName} wants to use your AbandonAuth account to:`);
    expect(page.find("script").exists()).toBe(false);
    expect(page.findAll("img").map((image) => image.attributes("src"))).toEqual(["/img/atLogoColor.svg"]);
  });

  it("shows the standard branding and no action while the consent loads", async () => {
    let answer: () => void = () => undefined;

    held = new Promise((resolve) => {
      answer = resolve;
    });

    window.history.replaceState(null, "", `/consent#request=${handle}`);

    const page = await mountSuspended(ConsentPage, { route: `/consent#request=${handle}` });

    expect(page.find('[data-test="status"]').text()).toBe("Loading the request...");
    expect(page.find("h1").text()).toBe("AbandonAuth");
    expect(page.find("img").attributes("src")).toBe("/img/atLogoColor.svg");
    expect(page.findAll("form")).toHaveLength(0);

    answer();

    await vi.waitFor(() => expect(page.findAll("form")).toHaveLength(2));

    expect(page.find('[data-test="status"]').exists()).toBe(false);
  });

  it("says the consent is gone when the API refuses it", async () => {
    const page = await openWith(`#request=${goneHandle}`);

    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(page.findAll("form")).toHaveLength(0);
  });

  for (const [name, expiresAt] of [
    ["an elapsed deadline", "2020-01-01T00:00:00Z"],
    ["an unparseable deadline", "soon"],
    ["an impossible instant", "9999-99-99T99:99:99Z"],
    ["a local-time deadline", "2999-01-01T00:00:00"],
    ["a missing deadline", undefined],
    ["a numeric deadline", 4102444800000],
  ] as const) {
    it(`offers no action for ${name}`, async () => {
      model = consentModel({ expires_at: expiresAt });

      const page = await openWith(`#request=${handle}`);

      expect(page.find('[role="alert"]').text()).toBe(unavailable);
      expect(page.findAll("form")).toHaveLength(0);
      expect(page.text()).not.toContain(applicationName);
    });
  }

  it("takes every action and all pending data away the moment the deadline arrives", async () => {
    model = consentModel({ scopes: ["openid", "profile"], expires_at: instantIn(3_000) });

    const page = await openWith(`#request=${handle}`);

    expect(page.findAll("form")).toHaveLength(2);

    await vi.waitFor(() => expect(page.find('[role="alert"]').exists()).toBe(true), { timeout: 5_000 });

    expect(page.findAll("form")).toHaveLength(0);
    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(page.text()).not.toContain(applicationName);
    expect(page.text()).not.toContain(username);
    expect(page.html()).not.toContain(handle);
  }, 10_000);

  it("clears the deadline when it is left", async () => {
    const clearing = vi.spyOn(globalThis, "clearTimeout");
    const page = await openWith(`#request=${handle}`);

    page.unmount();

    expect(clearing).toHaveBeenCalled();
    clearing.mockRestore();
  });

  it("accepts nothing from a query, and removes it", async () => {
    const page = await openWith(`?request=${handle}`);

    expect(seenAt).toHaveLength(0);
    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(window.location.search).toBe("");

    const both = await openWith(`?other=1#request=${handle}`);

    expect(seenAt).toHaveLength(0);
    expect(both.find('[role="alert"]').text()).toBe(unavailable);
    expect(window.location.search + window.location.hash).toBe("");
  });

  for (const [name, fragment] of malformed) {
    it(`asks the API nothing for ${name}`, async () => {
      const page = await openWith(fragment);

      expect(seenAt).toHaveLength(0);
      expect(carelessRequests).toBe(0);
      expect(page.find('[role="alert"]').text()).toBe(unavailable);
      expect(page.findAll("form")).toHaveLength(0);
      expect(window.location.hash).toBe("");
    });
  }
});
