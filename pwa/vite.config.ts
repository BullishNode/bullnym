import { defineConfig, type Plugin } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'node:path'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8')) as { version: string }

// Injects the real hashed asset filenames from this build into
// dist/sw.js's precache list (see public/sw.js). No new dependency: this
// is a small inline plugin, not a Workbox integration — the brief
// explicitly prefers a single self-contained sw.js over extra chunks.
function bullnymServiceWorkerPrecache(): Plugin {
  return {
    name: 'bullnym-sw-precache',
    apply: 'build',
    writeBundle(_options, bundle) {
      const assetUrls = Object.keys(bundle)
        .filter((fileName) => fileName.startsWith('assets/'))
        .map((fileName) => `/pwa-assets/${fileName}`)

      const swPath = resolve(__dirname, 'dist/sw.js')
      if (!existsSync(swPath)) return

      const content = readFileSync(swPath, 'utf-8')
      const patched = content.replace(
        /\/\*BULLNYM_PRECACHE_URLS\*\/\s*\[\]\s*\/\*END_BULLNYM_PRECACHE_URLS\*\//,
        JSON.stringify(assetUrls),
      )
      writeFileSync(swPath, patched)
    },
  }
}

// Two entry points, one workspace. The Rust server picks the shell to
// serve based on donation_pages.pos_mode and injects the config JSON in
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
      input: {
        donation: resolve(__dirname, 'apps/donation/index.html'),
        pos: resolve(__dirname, 'apps/pos/index.html'),
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
