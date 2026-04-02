import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry:    resolve(__dirname, 'src/index.ts'),
      name:     'QuorumSDK',
      fileName: (fmt) => `index.${fmt === 'es' ? 'mjs' : 'cjs'}`,
      formats:  ['es', 'cjs'],
    },
    rollupOptions: {
      external: ['argon2-browser', '@node-rs/argon2'],
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
