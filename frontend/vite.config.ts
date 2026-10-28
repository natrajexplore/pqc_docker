import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `make ui` runs this dev server against a backend reachable on localhost:8000
// (e.g. `docker compose port backend 8000` or an SSH tunnel). In the container
// build, nginx does the same proxying (see nginx.conf).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
