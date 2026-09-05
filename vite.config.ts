import { resolve } from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Tauri-specific Vite config (replaces electron.vite.config.ts for Tauri builds)
export default defineConfig({
  root: '.',
  publicDir: 'public',
  resolve: {
    alias: {
      '@renderer': resolve(__dirname, 'src/renderer')
    }
  },
  plugins: [
    react(),
    tailwindcss()
  ],
  // Tauri expects a fixed port: devUrl (tauri.conf.json) points here. strictPort so a
  // taken 5173 fails loudly instead of silently bumping — a bumped port means the
  // shell webview loads whatever ELSE answers on 5173 (ros dev lives on 5174).
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  // Env variables prefixed with TAURI_ are available in the frontend
  envPrefix: ['VITE_', 'TAURI_'],
});
