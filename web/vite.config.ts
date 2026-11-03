import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const backend = 'http://127.0.0.1:8080'

const proxy = {
  '/api': {
    target: backend,
    changeOrigin: true,
  },
  // The OIDC provider routes and the discovery document are served by the
  // same backend; in dev the issuer is the Vite origin.
  '/oidc': {
    target: backend,
    changeOrigin: true,
  },
  '/.well-known': {
    target: backend,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    proxy,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
})
