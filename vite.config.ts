import { defineConfig } from 'vite-plus';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

// SINGLE=1 vp build → un seul fichier HTML autonome (publication en artefact)
const single = process.env.SINGLE === '1';

export default defineConfig({
  base: './',
  plugins: [react(), ...(single ? [viteSingleFile()] : [])],
  build: { outDir: single ? 'dist-single' : 'dist', chunkSizeWarningLimit: 4000 },
  test: { include: ['src/**/*.test.ts'], testTimeout: 60000 },
});
