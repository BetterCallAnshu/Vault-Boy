import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "target/**",
      ".toolchain/**",
      "src-tauri/**",
      "tools/**",
      "crates/**",
      "coverage/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}", "vite.config.ts"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...(reactHooks.configs.recommended?.rules ?? {}),
      // Two React-Compiler rules are off by project decision:
      // - set-state-in-effect flags every async data fetch (`void refresh()`)
      //   and state reset on id change; both are deliberate here.
      // - purity flags `Date.now()` used only to render relative labels
      //   (trash countdown, "x days ago"); re-renders are harmless.
      // exhaustive-deps and all other correctness rules stay on.
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/purity": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);
