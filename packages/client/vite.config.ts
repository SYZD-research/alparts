import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

const developmentCsp = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self' ws: wss:",
].join('; ');

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // Keep slower-moving framework and rendering dependencies out of the
        // application chunk. This improves cacheability and keeps each initial
        // asset below the warning threshold as the prototype UI grows.
        manualChunks(id) {
          if (!id.includes('/node_modules/')) return undefined;
          if (/\/(react|react-dom|react-router|react-router-dom|zustand)\//.test(id)) return 'react';
          if (/\/(react-markdown|remark-|rehype-|unified|micromark|mdast-|hast-|unist-)\//.test(id)) return 'markdown';
          if (/\/(socket\.io-client|engine\.io-client|@socket\.io)\//.test(id)) return 'realtime';
          return undefined;
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: 5173,
    headers: {
      'Content-Security-Policy': developmentCsp,
      'Permissions-Policy': 'camera=(), display-capture=(), geolocation=(), microphone=(self), speaker-selection=(self)',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
    proxy: {
      '/api': 'http://localhost:3000',
      '/socket.io': {
        target: 'http://localhost:3000',
        ws: true,
      },
    },
  },
});
