// @vitest-environment nuxt
import { mountSuspended } from "@nuxt/test-utils/runtime";
import { describe, expect, it } from "vitest";

import LoginPage from "../app/pages/login.vue";
import { providerMarks } from "../app/utils/providerMarks";

const applicationId = "00000000-0000-0000-0000-000000000001";
const callbackUri = "https://example.test/return";
const complete = `?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`;

async function loginPageFor(query: string) {
  return mountSuspended(LoginPage, { route: `/login${query}` });
}

describe("the login page", () => {
  it("offers all four providers", async () => {
    const page = await loginPageFor(complete);

    expect(page.text()).toContain("Login with Discord");
    expect(page.text()).toContain("Login with Github");
    expect(page.text()).toContain("Login with Google");
    expect(page.text()).toContain("Login with Steam");
    expect(page.findAll("a")).toHaveLength(4);
  });

  it("draws the standard heading, sentence, image and responsive layout", async () => {
    const page = await loginPageFor(complete);

    const heading = page.find("h1");
    expect(heading.text()).toBe("AbandonAuth");
    expect(heading.classes()).toEqual(expect.arrayContaining([
      "select-none", "basis-1/4", "text-4xl", "font-bold", "text-gray-900", "dark:text-gray-100", "md:text-5xl", "lg:text-6xl",
    ]));

    const sentence = page.find("p.mt-6");
    expect(sentence.text()).toBe(`${applicationId} wants you to login with AbandonAuth`);

    const image = page.find("img");
    expect(image.attributes("src")).toBe("/img/atLogoColor.svg");
    expect(image.attributes("alt")).toBe("AbandonTech");
    expect(image.classes()).toEqual(expect.arrayContaining(["hidden", "lg:block", "w-full", "lg:w-[30rem]"]));

    expect(page.find(".min-h-screen.min-w-screen.flex.lg\\:items-center.lg\\:justify-center").exists()).toBe(true);
    expect(page.find(".flex.flex-col.text-center.px-8.lg\\:flex-row.lg\\:rounded-xl.lg\\:text-left").exists()).toBe(true);
    expect(page.find(".my-2.lg\\:mx-40.lg\\:my-auto").exists()).toBe(true);
    expect(page.find(".flex.flex-col.items-center.gap-4.mt-16.lg\\:mt-20").exists()).toBe(true);
  });

  it("draws each provider in order, with its own mark and colour", async () => {
    const page = await loginPageFor(complete);
    const links = page.findAll("a");

    Object.values(providerMarks).forEach((mark, index) => {
      const link = links[index]!;

      expect(link.text()).toBe(`Login with ${mark.title}`);
      expect(link.classes()).toContain(mark.bgColorClass);
      expect(link.classes()).toEqual(expect.arrayContaining(["w-96", "py-2", "px-8", "rounded-lg"]));
      expect(link.find("svg").attributes("viewBox")).toBe(mark.svgViewbox);
      expect(link.find("path").attributes("d")).toBe(mark.svgPathData);
    });
  });

  it("asks the API to start the sign-in, carrying the application and callback it was given", async () => {
    const page = await loginPageFor(complete);

    const addresses = page.findAll("a").map((link) => link.attributes("href"));

    expect(addresses).toEqual(["discord", "github", "google", "steam"].map((provider) =>
      `/api/ui/${provider}/authorize?application_id=${applicationId}&callback_uri=${encodeURIComponent(callbackUri)}`));
  });

  it("sends nothing to a provider itself", async () => {
    const page = await loginPageFor(complete);

    for (const link of page.findAll("a")) {
      expect(link.attributes("href")?.startsWith("/api/ui/")).toBe(true);
    }
  });

  it("says what is missing when it was reached without an application or a callback", async () => {
    const page = await loginPageFor("");
    const alerts = page.findAll('[role="alert"]').map((alert) => alert.text());

    expect(alerts).toEqual(["application_id is required", "callback_uri is required"]);
    expect(page.findAll('[role="alert"]')[0]!.classes()).toEqual(expect.arrayContaining(["alert", "alert-error", "mt-4"]));
  });
});
