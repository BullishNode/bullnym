# 01 Evidence Index

This is a factual index of recorded test runs used for the server improvement review.

## Run Summary

| Run report | Command | Records | Pass | Fail | Skip | Evidence value |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `bullnym-run-1779063985-ars-command-runreliability-profile-broad-cool_down-70-ln_storm_count-10-ln_storm.json` | ARS broad reliability | 189 | 25 | 10 | 154 | Broad product coverage; heavily contaminated by rate-limit/precondition skips. |
| `bullnym-run-1779114324-ars-command-certifyprod-i_understand_production-true-cool_down-70.json` | ARS certify production | 189 | 25 | 12 | 152 | Broad product coverage; same contamination pattern plus Lightning address failures. |
| `bullnym-run-1779123488-livepaymentmatrix-iterations-1-include_btc-false.json` | Live payment matrix | 8 | 7 | 1 | 0 | Valid live-money evidence; Liquid underpay failed. |
| `bullnym-run-1779124249-livepaymentmatrix-iterations-1-include_btc-false.json` | Live payment matrix | 8 | 7 | 1 | 0 | Repeat of Liquid underpay failure. |
| `bullnym-run-1779124949-livepaymentmatrix-iterations-1-include_btc-false.json` | Live payment matrix | 8 | 8 | 0 | 0 | Clean live-money invoice matrix. |
| `bullnym-run-1779127191-lnstorm-count-20-concurrency-1-amount_msat-100000-prefix-jungle20seq.json` | LN storm 20 sequential | 1 | 0 | 1 | 0 | Failed volume run; later contradicted by successful rerun. |
| `bullnym-run-1779127807-lnstorm-count-20-concurrency-1-amount_msat-100000-prefix-jungle20seqb.json` | LN storm 20 sequential | 1 | 1 | 0 | 0 | Clean repeated Lightning payment evidence. |
| `bullnym-run-1779128114-lnstorm-count-90-concurrency-1-amount_msat-100000-prefix-jungle90seq.json` | LN storm 90 sequential | 1 | 1 | 0 | 0 | Strong clean repeated Lightning payment evidence. |
| `bullnym-run-1779135713-livepaymentmatrix-iterations-1-include_btc-false.json` | Live payment matrix | 8 | 8 | 0 | 0 | Clean live-money invoice matrix. |
| `bullnym-run-1779139541-bitcoinv2.json` | Bitcoin V2 | 1 | 0 | 1 | 0 | BTC blocked by BDK sender funding. |
| `bullnym-run-1779140155-bitcoinv2.json` | Bitcoin V2 | 1 | 0 | 1 | 0 | BTC broadcast/unconfirmed then terminal status timeout. |
| `bullnym-run-1779150598-livepaymentmatrix-iterations-1-include_btc-false.json` | Live payment matrix | 8 | 6 | 0 | 2 | Jungle balance exhaustion; not server correctness evidence. |
| `bullnym-run-1779151124-liquidv2.json` | Liquid V2 | 22 | 20 | 1 | 1 | Strong Liquid server evidence; donation-page underpay failed, restart skipped. |
| `bullnym-run-1779153353-liquidv2.json` | Liquid V2 targeted | 1 | 1 | 0 | 0 | `LQ-21` passed with force-terminal support. |
| `bullnym-run-1779153481-liquidv2.json` | Liquid V2 targeted | 1 | 1 | 0 | 0 | `LQ-11` restart/watcher resume passed once restart hook was configured. |
| `bullnym-run-1779153846-liquidv2.json` | Liquid V2 | 22 | 0 | 22 | 0 | Invalid run from stale/incompatible deploy; release provenance evidence only. |
| `bullnym-run-1779153895-liquidv2.json` | Liquid smoke | 1 | 1 | 0 | 0 | `LQ-01` smoke passed after rollback. |
| `bullnym-run-1779154122-liquidv2.json` | Liquid smoke | 1 | 1 | 0 | 0 | `LQ-01` smoke passed after correct `bullnym/main` deploy. |

## High-Signal Evidence

### Valid clean passes

- Live matrix `1779124949`: 8/8.
- Live matrix `1779135713`: 8/8.
- LN storm `1779127807`: 20 sequential real Lightning payments passed.
- LN storm `1779128114`: 90 sequential real Lightning payments passed.
- Liquid V2 `1779151124`: 20/22 passed.
- Liquid targeted `1779153481`: restart/watcher resume passed after operator restart hook was configured.

### Valid server/correctness signals

- `LQ-21` donation-page Liquid underpay did not reach terminal status within 180 seconds before force-terminal support.
- BTC V2 exposed that broadcast/unconfirmed payments are not represented well enough for unattended testing or user status.
- Broad ARS registration/NIP-05/LNURL failures expose either server issues or server rate-limit behavior that blocks production certification.

### Invalid or contaminated signals

- Liquid `1779153846` is invalid as product evidence because the server was running a stale/incompatible binary.
- Broad ARS skipped cases are not proof of product failure. Most were blocked by rate limiting, missing Jungle configuration, or missing operator controls.
- Live matrix `1779150598` skips were caused by Jungle balance exhaustion.

