import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const basePath = process.env.VITE_BASE_PATH || "/";
const basePrefix = basePath === "/" ? "" : basePath.replace(/\/$/, "");

const backendProxy = {
  target: "http://backend:8000",
  changeOrigin: true,
};

const proxy = {
  "/api": backendProxy,
  "/admin": backendProxy,
};

if (basePrefix) {
  proxy[`${basePrefix}/api`] = {
    ...backendProxy,
    rewrite: (path) => path.slice(basePrefix.length),
  };
  proxy[`${basePrefix}/admin`] = {
    ...backendProxy,
    rewrite: (path) => path.slice(basePrefix.length),
  };
}

export default defineConfig({
  base: basePath,
  plugins: [react()],
  server: {
    allowedHosts: true,
  },
  preview: {
    allowedHosts: true,
    proxy,
  },
});
