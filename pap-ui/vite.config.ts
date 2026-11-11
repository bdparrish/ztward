import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(() => ({
  server: {
    host: "::",
    port: 3000,
    // Fail instead of drifting to another port: Keycloak redirects only allow this one
    strictPort: true,
    open: true,
  },
  build: {
    outDir: 'build',
    sourcemap: true,
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
