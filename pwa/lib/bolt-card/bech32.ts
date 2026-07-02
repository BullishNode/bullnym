// Minimal BIP173 bech32 decoder — enough to pull the ASCII URL out of an
// `lnurl1...` string. No new dependency; this is ~60 lines of pure math.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod(values: number[]): number {
  let chk = 1
  for (const v of values) {
    const b = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i]!
    }
  }
  return chk
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = []
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5)
  out.push(0)
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31)
  return out
}

function verifyChecksum(hrp: string, data: number[]): boolean {
  return polymod(hrpExpand(hrp).concat(data)) === 1
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] | null {
  let acc = 0
  let bits = 0
  const ret: number[] = []
  const maxv = (1 << toBits) - 1
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) return null
    acc = (acc << fromBits) | value
    bits += fromBits
    while (bits >= toBits) {
      bits -= toBits
      ret.push((acc >> bits) & maxv)
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv)
  } else if (bits >= fromBits || (acc << (toBits - bits)) & maxv) {
    return null
  }
  return ret
}

/** Decodes a bech32 string (e.g. "lnurl1...") into its raw byte payload, then UTF-8 decodes it. */
export function decodeBech32ToString(input: string): string {
  const lowered = input.toLowerCase()
  if (lowered !== input && input.toUpperCase() !== input) {
    throw new Error('Mixed-case bech32 string')
  }
  const pos = lowered.lastIndexOf('1')
  if (pos < 1 || pos + 7 > lowered.length) throw new Error('Invalid bech32 string')
  const hrp = lowered.slice(0, pos)
  const dataPart = lowered.slice(pos + 1)
  const data: number[] = []
  for (const c of dataPart) {
    const d = CHARSET.indexOf(c)
    if (d === -1) throw new Error('Invalid bech32 character')
    data.push(d)
  }
  if (!verifyChecksum(hrp, data)) throw new Error('Invalid bech32 checksum')
  const payload = data.slice(0, -6)
  const bytes = convertBits(payload, 5, 8, false)
  if (!bytes) throw new Error('Invalid bech32 payload')
  return new TextDecoder().decode(new Uint8Array(bytes))
}
