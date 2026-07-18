import { defineConfig, type Plugin } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'node:path'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { gzipSync } from 'node:zlib'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8')) as { version: string }

// Injects the real hashed asset filenames from this build into
// dist/sw.js's precache list (see public/sw.js). No new dependency: this
// is a small inline plugin, not a Workbox integration — the brief
// explicitly prefers a single self-contained sw.js over extra chunks.
function bullnymServiceWorkerPrecache(): Plugin {
  let distDir = resolve(__dirname, 'dist')
  return {
    name: 'bullnym-sw-precache',
    apply: 'build',
    configResolved(config) {
      distDir = resolve(__dirname, config.build.outDir)
    },
    writeBundle(_options, bundle) {
      const assetUrls = Object.keys(bundle)
        .filter((fileName) => fileName.startsWith('assets/'))
        .map((fileName) => `/pwa-assets/${fileName}`)

      const swPath = resolve(distDir, 'sw.js')
      if (!existsSync(swPath)) {
        throw new Error('dist/sw.js was not emitted; cannot inject PWA precache')
      }

      const content = readFileSync(swPath, 'utf-8')
      const patched = content.replace(
        /\/\*BULLNYM_PRECACHE_URLS\*\/\s*\[\]\s*\/\*END_BULLNYM_PRECACHE_URLS\*\//,
        JSON.stringify(assetUrls),
      )
      if (patched === content) {
        throw new Error('PWA precache marker was not found in dist/sw.js')
      }
      writeFileSync(swPath, patched)

      const gzipPaths = [
        ...Object.keys(bundle)
          .filter((fileName) => fileName.startsWith('assets/'))
          .map((fileName) => resolve(distDir, fileName)),
        swPath,
      ]
      for (const path of gzipPaths) {
        if (!existsSync(path)) {
          throw new Error(`Cannot gzip missing build output: ${path}`)
        }
        writeFileSync(`${path}.gz`, gzipSync(readFileSync(path), { level: 9 }))
      }
    },
  }
}

// Two entry points, one workspace. The Rust server picks the shell to
// serve based on donation_pages.kind and injects the config JSON in
// place of the <!-- BULLNYM_CONFIG --> placeholder.
//
// base is /pwa-assets/ so hashed assets resolve regardless of which
// /<nym> path the shell is served under. The Rust router mounts
// ServeDir("pwa/dist") at /pwa-assets.
export default defineConfig({
  base: '/pwa-assets/',
  plugins: [svelte(), tailwindcss(), bullnymServiceWorkerPrecache()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: { $lib: resolve(__dirname, 'lib') },
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      // The invoice template imports a named export from the non-HTML entry.
      // Vite's app default may otherwise rename or tree-shake that contract.
      preserveEntrySignatures: 'strict',
      input: {
        donation: resolve(__dirname, 'apps/donation/index.html'),
        pos: resolve(__dirname, 'apps/pos/index.html'),
        invoiceQr: resolve(__dirname, 'lib/invoiceQr.ts'),
      },
      output: {
        // The server-rendered invoice template needs a stable module URL.
        // Browser/SW caching is disabled for this entry; imported chunks keep
        // Vite's normal content hashes and immutable caching.
        entryFileNames: (chunk) =>
          chunk.name === 'invoiceQr' ? 'invoice-qr.js' : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/.well-known': 'http://127.0.0.1:8080',
      '^/[a-z0-9-]+/invoice$': 'http://127.0.0.1:8080',
    },
  },
})
