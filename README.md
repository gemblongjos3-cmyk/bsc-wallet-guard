# 🛡️ BSC Wallet & Transaction Guard

**An autonomous screening agent for BNB Smart Chain.** Paste a contract address
*before* you buy, mint, stake, or approve — the agent returns a plain-language
risk verdict with the on-chain evidence behind it. It also screens a pending
transaction's calldata before you sign, and its specialty is the single most
abused permission in wallet drains: the **unlimited token approval**.

Built during the zkVerify **Agent Games** (Security — "Wallet & transaction
guard"). This repository is the **public code release**: the full source plus
the recorded test evidence (`test-evidence/`). There is **no hosted live
endpoint** — run it locally (see *Run it*) and replay the evidence against
the chain yourself.

---

## The problem

Retail users on BSC sign transactions against contracts they cannot read.
The losses rarely come from exotic exploits; they come from a short list of
boring, checkable facts that nobody checks in the 10 seconds before signing:

- the contract's source was never verified, so nobody knows what it does;
- the owner can still mint, pause, blacklist wallets, change the tax, or
  upgrade the logic entirely;
- the token "has a price" only because someone opened a permissionless dust
  pool with a few dollars in it;
- selling is taxed 40% — or blocked outright (honeypot);
- a dApp asks for an **unlimited approval**, and one signature hands over
  every token in the wallet, forever, until revoked.

Every one of these is visible in public on-chain data. This agent checks all
of them, in seconds, and answers in language a non-developer can act on.

## Who it helps

- **Retail BSC users** deciding whether to interact with a token, mint, or dApp.
- **Wallet / dApp developers** who want a pre-signing gate: the agent returns a
  machine-readable `SAFE / CAUTION / DANGER` verdict plus a score, so a wallet
  can block, warn, or proceed deterministically (see *Gate usage* below).
- **Agent builders** whose agents transact autonomously and need a "should I
  even touch this contract?" check before risking funds.

## What it does

### `POST /audit` — contract audit
Give it `{ "address": "0x…" }`. It runs, in order:

1. **Existence & proxy resolution** — is there code at all? If the address is
   an EIP-1967 proxy, the audit targets the *implementation* (auditing proxy
   bytecode is a classic misread).
2. **Source verification (Sourcify)** — `exact_match`, `partial_match`, or
   *not verified*. Unverified code can never receive a SAFE verdict.
3. **Privilege inventory** — the implementation bytecode is scanned for owner
   powers: mint, pause, blacklist/bot-list, upgrade, fee setters, trading
   on/off switches, max-tx setters, withdraw/rescue, metadata setters. Every
   hit is cross-checked against the verified ABI (a selector in bytecode may
   be dead code; the ABI confirms it is reachable) and against live state:
   `owner()`, `pendingOwner()`, `paused()`, `tradingEnabled()`.
4. **Exit simulation (honeypot.is)** — is it a honeypot? Buy/sell/transfer
   taxes, with hard flags for sell tax > 25% or sell tax > 3× buy tax.
5. **Market reality** — the PancakeSwap V2 pair's real WBNB reserve (depth in
   BNB: dust < 1, thin < 5, fair < 50, deep ≥ 50) and the share of LP tokens
   actually burned. A price quoted from a dust pool is reported as *not a
   real price*. Falls back to DexScreener when there is no V2 pair.

Scoring is transparent and reproducible: start at 100, every deduction names
its evidence in the `flags` array, and the response pins the block number so
anyone can replay the same state.

### `POST /check-tx` — pre-signing calldata screen
Give it `{ "to": "0x…", "data": "0x…", "value": "0" }` — the transaction you
are *about to* sign. It decodes the call and flags, in plain language:

- `approve(spender, 2²⁵⁶−1)` → **DANGER**: unlimited approval, the drain vector;
- `setApprovalForAll(operator, true)` → **DANGER**: operator can move every NFT
  in the collection;
- sending BNB to an unverified contract;
- and it embeds the destination contract's own audit verdict.

### `POST /task` — Agent Games envelope
Accepts the platform's signed task envelope: the HMAC signature
(`x-agent-games-signature`) is verified over the raw body before anything is
parsed, responses are signed the same way, and task ids act as idempotency
keys. Supported task types: `audit` (and aliases), `ping`. Anything else is
rejected — the agent fails closed.

### Verdicts
| Verdict | Score | Meaning |
|---|---|---|
| `SAFE` | 80–100 | No blocking risk found (verified source required) |
| `CAUTION` | 50–79 | Interact only after reading the flags |
| `DANGER` | < 50 | Blocking risk found — do not proceed |

## Example

```bash
curl -X POST http://localhost:8787/audit -H 'content-type: application/json' \
  -d '{"address":"0x378afee1ce6c88f0fdc568518140b9a0ab794da5"}'
```
```json
{
  "verdict": "CAUTION", "score": 60, "block": 133599698,
  "verification": { "sourcify": "not_verified" },
  "flags": [
    { "severity": "high",   "code": "unverified_source", "message": "Source code is NOT verified on Sourcify — nobody can read what this contract really does." },
    { "severity": "medium", "code": "no_market",         "message": "No live PancakeSwap V2 pair or DexScreener market found — there is no observable way to sell this token at any price." }
  ]
}
```
(This is a real response: a clone token squatting on a legitimate project's
name — unverified, and with no market at all.)

## Test evidence

`test-evidence/RESULTS.md` records the local test run (15 Nov 2026): full
`/audit` responses for BSC USDT, the real BOLT token, and its clone
(`audit-*.json`), plus `/check-tx` screens (`check-tx-*.json`) — including
the unlimited-approval calldata flagged **DANGER**. Every verdict is pinned
to its block number, so the checks can be replayed against the chain.

## Run it

```bash
cp .env.example .env   # defaults work; AGENT_GAMES_HMAC_SECRET is only needed
                       # if you wire POST /task to a platform that issues one
npm start              # node src/server.js, port 8787
```
Zero runtime dependencies — Node ≥ 18 standard library only. Configuration is
environment-only (`PORT`, `BSC_RPC_URLS`, `SOURCIFY_BASE`,
`AGENT_GAMES_HMAC_SECRET`); no secrets in code. The agent is **read-only**:
it never holds keys, signs, or broadcasts anything.

## Design choices

- **Evidence order, always:** on-chain state > verified source > simulation >
  third-party APIs. Aggregator risk scores are inputs, never the verdict.
- **No "safe" without proof:** unknown is reported as unknown; partial
  evidence scores partial.
- **Bytecode selectors are leads, not findings:** each is confirmed against
  the verified ABI and live state before it costs points.
- **Dust-pool rule:** a token whose only pool holds < 1 BNB has no price,
  whatever a chart website displays.

## Limits (honest list)

- BSC only (chain 56). The fee/liquidity norms do not transfer to other chains.
- Quick-triage layer, not a line-by-line source audit: it does not prove the
  *absence* of a backdoor inside verified-but-complex logic (e.g. pair-keyed
  tax tricks that simulations miss).
- Holder concentration is not reconstructed (needs archive log scans); a
  concentrated holder base will not lower the score in this version.
- Honeypot simulation is a third-party input; when it is unavailable the
  report says so instead of guessing.
- Non-EIP-1967 proxy patterns are reported as-is rather than resolved.

## zkVerify (optional verifiability note)

The verdict itself is a checkable claim: every response pins the chain block
and the exact inputs, so the audit result can be re-derived by anyone. A
natural next step is committing a hash of each verdict + block to zkVerify so
"this agent screened contract X at block N and returned DANGER" becomes a
third-party-verifiable statement without revealing user data. Not yet wired
in — the agent is fully functional without it.

---

*Reference only, not financial advice.*
