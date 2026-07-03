// Payment-rail payload builders. Mirrors the server-rendered page's inline
// JS exactly (templates/invoice_payment.html:338-350) — same function
// names, same string shapes, so the QR payloads PaymentScreen renders are
// byte-for-byte what the old server-side page produced. liquidUri's shape
// is also asserted against the server's own test fixture
// (src/invoice/tests.rs:~311-318): `liquidnetwork:${address}?amount=${btc}&assetid=${liquid_btc_asset_id}`.

const SAT_PER_BTC = 100_000_000

/** Sats formatted as an 8-decimal-place BTC amount string, e.g. 10800 -> "0.00010800". */
export function btcAmount(sat: number): string {
  return (sat / SAT_PER_BTC).toFixed(8)
}

export function btcUri(address: string, sat: number): string {
  return `bitcoin:${address}?amount=${btcAmount(sat)}`
}

/** Prefers the server-issued bip21 URI (it can carry extra params like a label); falls back to a bare bitcoin: URI. */
export function bitcoinPayload(address: string, bip21: string | null, sat: number): string {
  return bip21 || btcUri(address, sat)
}

export function liquidUri(address: string, sat: number, assetId: string): string {
  return `liquidnetwork:${address}?amount=${btcAmount(sat)}&assetid=${assetId}`
}
