import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      'workers/sha256': 'src/workers/sha256.ts',
      'workers/pbkdf2': 'src/workers/pbkdf2.ts',
    },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
    target: 'es2022',
    outDir: 'dist',
  },
  {
    entry: { w: 'src/index.ts' },
    format: ['iife'],
    globalName: 'RGCheck',
    sourcemap: false,
    minify: true,
    clean: false,
    target: 'es2020',
    outDir: 'dist',
  },
])
