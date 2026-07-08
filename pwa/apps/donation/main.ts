import { mount } from 'svelte'
import '$lib/app.css'
import App from './App.svelte'

const target = document.getElementById('app')
if (!target) throw new Error('missing #app root')

mount(App, { target })

// Root-scoped service worker. Dev-gated because the Vite dev server does not
// serve the production /sw.js and hot reload does not work well under an active
// worker.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    /* offline install just won't be available — the app still works online */
  })
}
