#!/usr/bin/env node
// Generates the two PWA manifest icons (icon-192.png, icon-512.png) as
// hand-rolled PNGs — no new runtime/dev dependency. Uses only Node's
// built-in zlib for DEFLATE compression; PNG chunk framing and CRC32 are
// implemented inline (a PNG encoder is ~80 lines, not worth a package).
//
// Design: cream (#F5F0E8) background, dark (#211F1A) lightning-bolt glyph —
// matches the nostr-pos-derived design system (see lib/app.css), palette
// referenced from bb-logo-light.png. Run with `node scripts/gen-icons.mjs`.
// Glyph is inset to the center ~60% of the canvas (maskable-safe padding).
// Output is committed to pwa/public/icons/ (Vite copies public/ verbatim to
// dist root, which the server's ServeDir mounts at /pwa-assets/, matching
// the manifest's expected /pwa-assets/icons/icon-*.png paths).

import { deflateSync } from 'node:zlib'
import { writeFileSync, mkdirSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = resolve(__dirname, '../public/icons')
mkdirSync(outDir, { recursive: true })

const BG = [0xf5, 0xf0, 0xe8, 0xff]
const FG = [0x21, 0x1f, 0x1a, 0xff]

// Classic lightning-bolt polygon, defined as fractions of a 0..1 canvas.
// Rescaled into the center 60% (maskable-safe inset) below.
const RAW_BOLT_POINTS = [
  [0.58, 0.04],
  [0.28, 0.56],
  [0.47, 0.56],
  [0.38, 0.96],
  [0.76, 0.42],
  [0.53, 0.42],
  [0.63, 0.04],
]

const SAFE_INSET = 0.2 // glyph occupies the center 1 - 2*0.2 = 60% of the canvas
const BOLT_POINTS = RAW_BOLT_POINTS.map(([fx, fy]) => [SAFE_INSET + fx * (1 - 2 * SAFE_INSET), SAFE_INSET + fy * (1 - 2 * SAFE_INSET)])

function pointInPolygon(x, y, points) {
  let inside = false
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const [xi, yi] = points[i]
    const [xj, yj] = points[j]
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi
    if (intersect) inside = !inside
  }
  return inside
}

function renderIcon(size) {
  const scaled = BOLT_POINTS.map(([fx, fy]) => [fx * size, fy * size])
  const pixels = new Uint8Array(size * size * 4)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4
      const inBolt = pointInPolygon(x + 0.5, y + 0.5, scaled)
      const [r, g, b, a] = inBolt ? FG : BG
      pixels[idx] = r
      pixels[idx + 1] = g
      pixels[idx + 2] = b
      pixels[idx + 3] = a
    }
  }
  return pixels
}

// --- Minimal PNG encoder (8-bit RGBA, filter type 0, single IDAT) ---

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[n] = c >>> 0
  }
  return table
})()

function crc32(buf) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  }
  return (c ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii')
  const lenBuf = Buffer.alloc(4)
  lenBuf.writeUInt32BE(data.length, 0)
  const crcBuf = Buffer.alloc(4)
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0)
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf])
}

function encodePng(pixels, size) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])

  const ihdrData = Buffer.alloc(13)
  ihdrData.writeUInt32BE(size, 0) // width
  ihdrData.writeUInt32BE(size, 4) // height
  ihdrData[8] = 8 // bit depth
  ihdrData[9] = 6 // color type: RGBA
  ihdrData[10] = 0 // compression
  ihdrData[11] = 0 // filter
  ihdrData[12] = 0 // interlace
  const ihdr = chunk('IHDR', ihdrData)

  // Raw scanlines: filter-type byte (0 = none) + RGBA row bytes.
  const stride = size * 4
  const raw = Buffer.alloc((stride + 1) * size)
  for (let y = 0; y < size; y++) {
    const rowStart = y * (stride + 1)
    raw[rowStart] = 0
    Buffer.from(pixels.buffer, y * stride, stride).copy(raw, rowStart + 1)
  }
  const idatData = deflateSync(raw)
  const idat = chunk('IDAT', idatData)

  const iend = chunk('IEND', Buffer.alloc(0))

  return Buffer.concat([signature, ihdr, idat, iend])
}

for (const size of [192, 512]) {
  const pixels = renderIcon(size)
  const png = encodePng(pixels, size)
  const outPath = resolve(outDir, `icon-${size}.png`)
  writeFileSync(outPath, png)
  console.log(`wrote ${outPath} (${png.length} bytes)`)
}
