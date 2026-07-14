# Glossary

| Term | Meaning |
|---|---|
| nym | Permanent Bullnym namespace and Lightning Address local part; exactly one is owned by an authentication `npub` |
| alias | Optional permanent web name in the shared nym/alias namespace; exactly one may be owned by an npub and is shared by Page/POS |
| Payment Page | Public payer-entered checkout at `/:nym` or `/a/:alias`; legacy code/table names use “donation page” |
| POS | Public cashier-entered checkout at `/:nym/pos` or `/a/:alias/pos`, backed by a separate surface descriptor |
| wallet invoice | Merchant-created receivable with concrete settlement addresses |
| checkout invoice | Payer-created Payment Page or POS session |
| CT descriptor | Confidential Transactions descriptor from which Bullnym derives blinded Liquid receive addresses but not merchant spending keys |
| reverse swap | Payer pays Lightning; Bullnym claims provider-locked LBTC to the merchant destination |
| chain swap | Payer locks BTC; Bullnym claims provider LBTC to the merchant destination |
| claim | Transaction spending the provider Liquid lockup to the committed merchant destination |
| recovery/refund | Chain-swap transaction returning payer BTC to the merchant-configured emergency address when settlement cannot complete |
| payment status | Invoice accounting state from the payer/product perspective |
| settlement status | State of asynchronous merchant-side settlement |
| payment event | Idempotent evidence counted toward invoice value |
| observation | Non-accounting evidence, currently used for direct Bitcoin before confirmation |
