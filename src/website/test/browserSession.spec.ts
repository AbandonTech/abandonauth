import { describe, expect, it } from "vitest";

import { csrfHeader, csrfToken, currentUserPath, signedIn, siteRequestHeaders } from "../app/utils/browserSession";

describe("csrfToken", () => {
  it("reads the cookie the API set", () => {
    expect(csrfToken("abandonauth_csrf=a-token")).toBe("a-token");
  });

  it("prefers the cookie a browser will only return to the host that set it", () => {
    expect(csrfToken("abandonauth_csrf=host-only; __Host-abandonauth_csrf=over-tls")).toBe("over-tls");
  });

  it("finds the cookie among others", () => {
    expect(csrfToken("theme=dark; abandonauth_csrf=a-token; other=value")).toBe("a-token");
  });

  it("keeps a value that contains the separator", () => {
    expect(csrfToken("abandonauth_csrf=YS9iPWM=")).toBe("YS9iPWM=");
  });

  it("ignores a cookie whose name merely ends the same way", () => {
    expect(csrfToken("not_abandonauth_csrf=someone-elses")).toBe("");
  });

  it("is empty when the browser holds no session", () => {
    expect(csrfToken("")).toBe("");
  });
});

describe("siteRequestHeaders", () => {
  it("echoes the readable half of the session, which only this site can read", () => {
    expect(siteRequestHeaders("__Host-abandonauth_csrf=a-token")).toEqual({ [csrfHeader]: "a-token" });
  });

  it("reads the browser's own cookies when none are given", () => {
    document.cookie = "abandonauth_csrf=from-the-browser";

    expect(siteRequestHeaders()).toEqual({ [csrfHeader]: "from-the-browser" });
  });
});

describe("signedIn", () => {
  it("asks the API rather than trusting a cookie it can see", async () => {
    const asked: string[] = [];

    await signedIn(async (path) => {
      asked.push(path);

      return {};
    });

    expect(asked).toEqual([currentUserPath]);
  });

  it("is true when the API recognises the session", async () => {
    await expect(signedIn(async () => ({ id: "a-user" }))).resolves.toBe(true);
  });

  it("is false when the API refuses", async () => {
    await expect(
      signedIn(async () => {
        throw new Error("403");
      }),
    ).resolves.toBe(false);
  });
});
