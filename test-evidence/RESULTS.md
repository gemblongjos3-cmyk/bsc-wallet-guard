# Local test evidence — 15 Nov 2026

Server: `node src/server.js` (Node v24.22.1), zero dependencies.
All requests below were made against the locally running server.

## GET /health
```json
{"status":"ok","agent":"bsc-wallet-guard","version":"0.1.0","chainId":56,"uptimeSeconds":1}
```

## POST /audit — full responses saved next to this file
| File | Contract | Block | Verdict | Key evidence |
|---|---|---|---|---|
| `audit-usdt.json` | USDT (BSC) `0x55d398326f99059fF775485246999027B3197955` | 133599577 | CAUTION 68 | Sourcify partial match; live owner; mint power; deep V2 pool (29,571 BNB); 0% tax, not a honeypot |
| `audit-bolt-real.json` | BOLT (real) `0xBbDd8C7720d1EEB1d63738eaABB584a4b72C7777` | 133599643 | CAUTION 70 | Source not verified; owner renounced; live pair `0x0d2f626bc333870d7162b2e4ccc0110b18ba18ab` with fair depth |
| `audit-bolt-clone.json` | BOLT clone `0x378afee1ce6c88f0fdc568518140b9a0ab794da5` | 133599698 | CAUTION 60 | Source not verified AND no live market at all — no observable exit. Scores below the real token, as it should |

## POST /check-tx
| File | Input | Verdict |
|---|---|---|
| `check-tx-unlimited-approve.json` | `approve(spender=0x378a…4da5, amount=2²⁵⁶−1)` on USDT | **DANGER** — `unlimited_approval` flag with plain-language explanation |
| `check-tx-plain-transfer.json` | standard `transfer(address,uint256)` on USDT | CAUTION (only because USDT itself screens CAUTION — central mint/owner) |

## POST /task — Agent Games envelope (second instance, port 8788, HMAC secret set)
- Valid `x-agent-games-signature` → `200 {"id":"task-001","status":"completed",...}` and the response itself carried an `x-agent-games-signature` header.
- Wrong signature → `401 {"status":"rejected","reason":"bad_signature"}`.
- Same idempotency key replayed → cached response returned (no duplicate work).

## Processes started during testing (all stopped after testing)
- node server, main instance — PID 17871 (port 8787)
- node server, HMAC instance — PID 17940 (port 8788)
