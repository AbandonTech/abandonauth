import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(resolve(__dirname, "../app/assets/css/main.css"), "utf8");

function themeBlock(name: string) {
  const block = [...stylesheet.matchAll(/@plugin\s+"daisyui\/theme"\s*\{([^}]*)\}/g)]
    .map((match) => match[1])
    .find((body) => new RegExp(`name:\\s*"${name}"\\s*;`).test(body));

  if (block === undefined) {
    throw new Error(`the stylesheet registers no ${name} theme`);
  }

  return block;
}

function declarations(block: string) {
  return Object.fromEntries(
    [...block.matchAll(/([\w-]+)\s*:\s*([^;]*?)\s*(?:\/\*[^*]*\*\/\s*)?;/g)].map((match) => [match[1], match[2]]),
  );
}

const light = {
  "--color-base-100": "oklch(100% 0 0)",
  "--color-base-200": "oklch(98% 0 0)",
  "--color-base-300": "oklch(95% 0 0)",
  "--color-base-content": "#1f2937",
  "--color-primary": "#1a67d7",
  "--color-primary-content": "#ffffff",
  "--color-neutral": "oklch(14% 0.005 285.823)",
  "--color-neutral-content": "oklch(92% 0.004 286.32)",
  "--color-warning": "oklch(82% 0.189 84.429)",
  "--color-warning-content": "oklch(41% 0.112 45.904)",
  "--color-error": "oklch(71% 0.194 13.428)",
  "--color-error-content": "oklch(27% 0.105 12.094)",
};

const dark = {
  "--color-base-100": "#1f2937",
  "--color-base-200": "#1c2531",
  "--color-base-300": "oklch(21.15% 0.012 254.09)",
  "--color-base-content": "#ffffff",
  "--color-primary": "#1a67d7",
  "--color-primary-content": "#ffffff",
  "--color-neutral": "oklch(14% 0.005 285.823)",
  "--color-neutral-content": "oklch(92% 0.004 286.32)",
  "--color-warning": "oklch(82% 0.189 84.429)",
  "--color-warning-content": "oklch(41% 0.112 45.904)",
  "--color-error": "oklch(71% 0.194 13.428)",
  "--color-error-content": "oklch(27% 0.105 12.094)",
};

describe("the site stylesheet", () => {
  it("selects the application's light theme for a document that asks for nothing", () => {
    expect(declarations(themeBlock("light"))["default"]).toBe("true");
    expect(declarations(themeBlock("light"))["color-scheme"]).toBe("light");
  });

  it("selects the application's dark theme for a browser that prefers dark", () => {
    expect(declarations(themeBlock("dark"))["prefersdark"]).toBe("true");
    expect(declarations(themeBlock("dark"))["color-scheme"]).toBe("dark");
  });

  it("registers no packaged theme that would take the root away from the application's themes", () => {
    expect(/@plugin\s+"daisyui"\s*\{\s*themes:\s*false;\s*\}/.test(stylesheet)).toBe(true);
    expect(stylesheet).not.toContain("--default");
    expect(stylesheet).not.toContain("--prefersdark");
  });

  it("states every color role the site's components read in light", () => {
    expect(declarations(themeBlock("light"))).toMatchObject(light);
  });

  it("states every color role the site's components read in dark", () => {
    expect(declarations(themeBlock("dark"))).toMatchObject(dark);
  });
});
