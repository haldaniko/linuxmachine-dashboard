import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: process.env.VITE_BASE_PATH || "/",
  plugins: [react()],
  server: {
    allowedHosts: true,
  },
  preview: {
    allowedHosts: true,
    proxy: {
      "/api": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/admin": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
    },
  },
});
