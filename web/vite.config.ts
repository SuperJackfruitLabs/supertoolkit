import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    // In development the API is the broker's own listener.
    proxy: { '/api': 'http://127.0.0.1:7420' },
  },
});
