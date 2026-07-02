import { mount } from 'svelte'
import '$lib/app.css'
import App from './App.svelte'

const target = document.getElementById('app')
if (!target) throw new Error('missing #app root')

mount(App, { target })

// PWA install + offline shell (plans/pos/08, Milestone 6). Root-scoped so
// it can control /<nym> pages; dev-gated since the dev server doesn't
// serve a real /sw.js and hot reload doesn't play well with an active SW.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    /* offline install just won't be available — the app still works online */
  })
}
