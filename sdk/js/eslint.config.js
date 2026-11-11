import js from "@eslint/js";
import globals from "globals";

export default [
  { ignores: ["dist", "src/generated"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,mjs}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      // The SDK has browser and Node.js entry points.
      globals: { ...globals.browser, ...globals.node },
    },
  },
];
