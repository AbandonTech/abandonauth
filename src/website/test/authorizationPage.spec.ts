// @vitest-environment nuxt
import { mountSuspended, registerEndpoint } from "@nuxt/test-utils/runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AuthorizePage from "../app/pages/authorize.vue";
import LoginPage from "../app/pages/login.vue";
import authGate from "../app/middleware/auth.global";
import { providerMarks } from "../app/utils/providerMarks";

const handle = "A".repeat(42) + "Q";
const goneHandle = "B".repeat(42) + "A";
const unavailable = "This sign-in request is no longer available. Return to the application and start again.";
const hostileName = `<script>alert("x")</script><img src=x onerror=alert(1)>`;
const ordinaryName = "an installed application";

let seenAt: { path: string; hash: string }[] = [];
let model: Record<string, unknown> = {};
let held: Promise<void> = Promise.resolve();

function selectionModel(overrides: Record<string, unknown> = {}) {
  return {
    application_name: ordinaryName,
    expires_at: new Date(Date.now() + 240_000).toISOString().replace(/\.\d+Z$/, "Z"),
    providers: ["discord", "github", "google", "steam"],
    ...overrides,
  };
}

registerEndpoint(`/api/oauth/authorization/${handle}`, async () => {
  seenAt.push({ path: window.location.pathname, hash: window.location.hash });

  await held;

  return model;
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
  ["a handle with non-zero tail bits", `#request=${"A".repeat(42)}B`],
  ["extra fragment content", `#request=${handle}&extra=1`],
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

async function openWith(address: string) {
  window.history.replaceState(null, "", `/authorize${address}`);

  const page = await mountSuspended(AuthorizePage, { route: `/authorize${address}` });

  await vi.waitFor(() => expect(page.text()).not.toContain("Loading the request"));

  return page;
}

// Every control as a person sees it, leaving out only where it leads.
function controlsOf(page: Awaited<ReturnType<typeof openWith>>) {
  return page.findAll(".flex.flex-col.items-center.gap-4 > *").map((wrapper) => {
    const control = wrapper.element.tagName === "A" ? wrapper : wrapper.find("button");

    return {
      label: control.text(),
      color: control.classes().filter((name) => name.startsWith("bg-")),
      shape: control.classes().filter((name) => ["w-96", "py-2", "px-8", "rounded-lg"].includes(name)),
      content: control.find("div").attributes("class"),
      icon: control.find("svg").attributes(),
      path: control.find("path").attributes(),
      caption: control.find("span").attributes("class"),
    };
  });
}

describe("the authorization page", () => {
  beforeEach(() => {
    seenAt = [];
    carelessRequests = 0;
    model = selectionModel();
    held = Promise.resolve();
  });

  it("takes the handle out of the address before asking for the request, and asks only by path", async () => {
    const page = await openWith(`#request=${handle}`);

    expect(seenAt).toEqual([{ path: "/authorize", hash: "" }]);
    expect(window.location.pathname + window.location.search + window.location.hash).toBe("/authorize");
    expect(page.text()).toContain("wants you to login with AbandonAuth");
  });

  it("draws exactly what the login page draws, but for the application and where each control leads", async () => {
    const page = await openWith(`#request=${handle}`);
    const login = await mountSuspended(LoginPage, {
      route: `/login?application_id=${encodeURIComponent(ordinaryName)}&callback_uri=${encodeURIComponent("https://example.test/return")}`,
    });

    expect(page.find("h1").html()).toBe(login.find("h1").html());
    expect(page.find("img").html()).toBe(login.find("img").html());
    expect(page.find("p.mt-6").text()).toBe(login.find("p.mt-6").text());
    expect(page.find("p.mt-6").attributes("class")).toBe(login.find("p.mt-6").attributes("class"));
    expect(controlsOf(page)).toEqual(controlsOf(login));
    expect(controlsOf(page).map((control) => control.label)).toEqual(
      Object.values(providerMarks).map((mark) => `Login with ${mark.title}`),
    );

    for (const layout of [
      ".min-h-screen.min-w-screen.flex",
      ".flex.flex-col.text-center.px-8",
      ".my-2",
      ".flex.flex-col.items-center.gap-4",
    ]) {
      expect(page.find(layout).attributes("class"), layout).toBe(login.find(layout).attributes("class"));
    }

    const text = (wrapper: { text(): string }) => wrapper.text().replace(/\s+/g, " ");

    expect(text(page)).toBe(text(login));
  });

  it("says nothing about what is requested, how long it lasts or how to cancel", async () => {
    model = selectionModel({ scopes: ["openid", "profile", "offline_access"] });

    const page = await openWith(`#request=${handle}`);
    const text = page.text();

    for (const absent of [
      "openid", "profile", "offline_access", "username", "user ID", "90 days", "sessions", "expires", "Allow", "Cancel",
      model.expires_at as string,
    ]) {
      expect(text).not.toContain(absent);
    }

    expect(page.find("time").exists()).toBe(false);
  });

  it("renders the application name as text, never as markup", async () => {
    model = selectionModel({ application_name: hostileName });

    const page = await openWith(`#request=${handle}`);

    expect(page.find("p.mt-6").text()).toBe(`${hostileName} wants you to login with AbandonAuth`);
    expect(page.find("script").exists()).toBe(false);
    expect(page.findAll("img").map((image) => image.attributes("src"))).toEqual(["/img/atLogoColor.svg"]);
  });

  it("offers each provider as an empty form posting to exactly its own address", async () => {
    const page = await openWith(`#request=${handle}`);

    const forms = page.findAll("form").map((form) => [form.attributes("method"), form.attributes("action")]);

    expect(forms).toEqual([
      ["post", `/api/oauth/authorization/${handle}/discord`],
      ["post", `/api/oauth/authorization/${handle}/github`],
      ["post", `/api/oauth/authorization/${handle}/google`],
      ["post", `/api/oauth/authorization/${handle}/steam`],
    ]);

    for (const form of page.findAll("form")) {
      expect(form.findAll("input")).toHaveLength(0);
    }

    expect(page.findAll("a")).toHaveLength(0);
  });

  it("shows the standard branding and no action while the request loads", async () => {
    let answer: () => void = () => undefined;

    held = new Promise((resolve) => {
      answer = resolve;
    });

    window.history.replaceState(null, "", `/authorize#request=${handle}`);

    const page = await mountSuspended(AuthorizePage, { route: `/authorize#request=${handle}` });

    expect(page.find('[data-test="status"]').text()).toBe("Loading the request...");
    expect(page.find("h1").text()).toBe("AbandonAuth");
    expect(page.find("img").attributes("src")).toBe("/img/atLogoColor.svg");
    expect(page.findAll("form")).toHaveLength(0);

    answer();

    await vi.waitFor(() => expect(page.findAll("form")).toHaveLength(4));

    expect(page.find('[data-test="status"]').exists()).toBe(false);
  });

  it("says the request is gone when the API no longer holds it", async () => {
    const page = await openWith(`#request=${goneHandle}`);

    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(page.find('[role="alert"]').classes()).toEqual(expect.arrayContaining(["alert", "alert-error"]));
    expect(page.findAll("form")).toHaveLength(0);
    expect(page.find("h1").text()).toBe("AbandonAuth");
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
      model = selectionModel({ expires_at: expiresAt });

      const page = await openWith(`#request=${handle}`);

      expect(page.find('[role="alert"]').text()).toBe(unavailable);
      expect(page.findAll("form")).toHaveLength(0);
      expect(page.text()).not.toContain(ordinaryName);
    });
  }

  it("offers no action for a provider list it was not expecting", async () => {
    model = selectionModel({ providers: ["discord", "evil"] });

    const page = await openWith(`#request=${handle}`);

    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(page.findAll("form")).toHaveLength(0);
  });

  it("takes every action and the application away the moment the deadline arrives", async () => {
    model = selectionModel({ expires_at: new Date(Date.now() + 3_000).toISOString().replace(/\.\d+Z$/, "Z") });

    const page = await openWith(`#request=${handle}`);

    expect(page.findAll("form")).toHaveLength(4);

    await vi.waitFor(() => expect(page.find('[role="alert"]').exists()).toBe(true), { timeout: 5_000 });

    expect(page.findAll("form")).toHaveLength(0);
    expect(page.find('[role="alert"]').text()).toBe(unavailable);
    expect(page.text()).not.toContain(ordinaryName);
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

describe("the session gate", () => {
  beforeEach(() => {
    currentUserAsked = 0;
  });

  it("lets anyone reach the authorization, consent and login pages without asking who they are", async () => {
    for (const path of ["/authorize", "/consent", "/login"]) {
      expect(await authGate({ path } as never, {} as never)).toBeUndefined();
    }

    expect(currentUserAsked).toBe(0);
  });

  it("still asks who the browser is before every dashboard page and near match", async () => {
    for (const path of ["/", "/developer-applications", "/authorize/other", "/consent/other", "/consents", "/Consent"]) {
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
