LUD-22: Currency negotiation for `payRequest`.
================================================

`author: BullishNode` `discussion: https://github.com/lnurl/luds/issues/XXX`

---

## Motivation

LNURL-pay (LUD-06) assumes the only payment method is a Lightning invoice. However, many services operate on multiple Bitcoin layers (mainchain, Liquid, etc.) and could settle payments more efficiently if the wallet indicated which networks it supports.

This document extends the `payRequest` flow to allow services to advertise supported currencies/networks and wallets to select their preferred payment method.

## Service response (extension to LUD-06 step 3)

The JSON response from `LN SERVICE` MAY include an additional `currencies` field:

```Typescript
{
    // ...existing LUD-06 fields (callback, maxSendable, minSendable, metadata, tag)...
    "currencies": [
        {
            "code": string,    // Currency code (e.g. "BTC")
            "name": string,    // Human-readable name (e.g. "Liquid Bitcoin")
            "network": string, // Network identifier (e.g. "bitcoin", "liquid")
            "symbol": string   // Display symbol (e.g. "L-BTC")
        }
    ]
}
```

If `currencies` is absent, the service only supports Lightning (the default LUD-06 behavior).

The `network` field uniquely identifies the payment rail. The following values are defined:

| `network` | Description |
|-----------|-------------|
| `bitcoin` | Lightning Network (default, LUD-06 behavior) |
| `liquid`  | Liquid Network (L-BTC on-chain) |

Additional network values MAY be defined in the future.

## Wallet callback (extension to LUD-06 step 4)

When the wallet calls the callback URL, it MAY include a `network` query parameter:

```
<callback><?|&>amount=<milliSatoshi>&network=<network>
```

- If `network` is absent, the service MUST return a Lightning invoice as per LUD-06 (backwards compatible).
- If `network` is present but not supported by the service, the service SHOULD return a standard LNURL error response: `{"status": "ERROR", "reason": "unsupported network"}`.
- The `amount` parameter is always in millisatoshi regardless of the selected network, for consistency with LUD-06.

## Service callback response

### When `network` is absent or `network=bitcoin`

Standard LUD-06 response:

```json
{
    "pr": string,
    "routes": []
}
```

### When `network=liquid`

```json
{
    "onchain": {
        "network": "liquid",
        "address": string,   // Confidential Liquid address
        "amount_sat": number, // Amount in satoshi
        "bip21": string      // Full BIP-21 URI with amount and asset ID
    }
}
```

The `bip21` field contains a complete payment URI that the wallet can use directly:
```
liquidnetwork:<address>?amount=<btc_decimal>&assetid=<lbtc_asset_id>
```

## Wallet behavior

1. `WALLET` receives the initial `payRequest` response and checks for the `currencies` field.
2. If `currencies` is present and contains a `network` the wallet supports natively (e.g., `liquid`), the wallet SHOULD prefer that network to avoid unnecessary swap fees.
3. The wallet includes `&network=<preferred>` in the callback request.
4. If the wallet does not understand the `currencies` field, it ignores it and proceeds with the standard Lightning flow. This ensures full backwards compatibility.

## Implementation notes

- Services SHOULD always include `"network": "bitcoin"` in the `currencies` array to explicitly indicate Lightning support.
- The `onchain` response object is designed to be extensible for future networks. Each network defines its own fields within the object.
- For Liquid, the `address` SHOULD be a confidential address (starting with `lq1qq`) to preserve transaction privacy.
- The `amount_sat` field is provided for convenience; the `bip21` URI is the canonical payment instruction.
