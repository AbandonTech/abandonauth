module.exports = {
    plugins: [require('daisyui')],
    theme: {
      extend: {
        fontFamily: {
          "sans": ["Lato", "sans-serif"],
          "header": ["Atkinson Hyperlegible", "sans-serif"],
        },
      },
    },
    daisyui: {
        themes: [
          {
            light: {
              ...require("daisyui/src/theming/themes")["light"],
              // "base-100": "#ffffff",  // backgrounds
              "base-content": "#1f2937",
              "primary-content": "#ffffff",  // text
              "primary": "#1A67D7" // AbandonTech Blue
            },
          },
          {
            dark: {
              ...require("daisyui/src/theming/themes")["dark"],
              "base-100": "#1f2937",  // backgrounds
              "base-200": "#1c2531",
              "base-content": "#ffffff",
              "primary-content": "#ffffff",  // text
              "primary": "#1A67D7"  // AbandonTech Blue
            },
          },
        ]
    }
  };
