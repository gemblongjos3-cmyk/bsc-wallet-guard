// BSC Wallet & Transaction Guard — audit engine.
// Implements the quick-triage layer of the bsc-contract-audit playbook:
//   verification (Sourcify) -> proxy resolution -> privilege inventory
//   (bytecode selector scan cross-checked against the verified ABI + live
//   state probes) -> exit reality (honeypot.is simulation) -> liquidity
//   reality (PancakeSwap V2 pair reserves + LP burn share, DexScreener
//   fallback) -> a transparent, reproducible score and verdict.
// Read-only: this module never signs or sends a transaction.

import { CALLS, SENSITIVE, TRADING_ENABLED, TX_SELECTORS, ADDRESSES, SLOTS } from './selectors.js';

const CHAIN_ID = 56;
const RPC_URLS = (process.env.BSC_RPC_URLS ||
  'https://bsc-dataseed.binance.org,https://bsc-rpc.publicnode.com,https://1rpc.io/bnb')
  .split(',').map(s => s.trim()).filter(Boolean);
const SOURCIFY_BASE = process.env.SOURCIFY_BASE || 'https://sourcify.dev/server';
const TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 9000);

const isAddress = a => typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a);
const lc = a => a.toLowerCase();

async function fetchJson(url, opts = {}, timeout = TIMEOUT_MS) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, headers: { 'user-agent': 'bsc-wallet-guard/0.1', ...(opts.headers || {}) } });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* keep null */ }
    return { status: r.status, json, text };
  } finally { clearTimeout(t); }
}

let rpcIdx = 0;
async function rpc(method, params) {
  let lastErr;
  for (let i = 0; i < RPC_URLS.length; i++) {
    const url = RPC_URLS[(rpcIdx + i) % RPC_URLS.length];
    try {
      const { json } = await fetchJson(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
      });
      if (json && json.result !== undefined) { rpcIdx = (rpcIdx + i) % RPC_URLS.length; return json.result; }
      lastErr = new Error(json?.error?.message || 'rpc error');
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('all RPC endpoints failed');
}

const ethCall = (to, data, block = 'latest') => rpc('eth_call', [{ to, data }, block]);
const getCode = addr => rpc('eth_getCode', [addr, 'latest']);
const getStorage = (addr, slot) => rpc('eth_getStorageAt', [addr, slot, 'latest']);
const blockNumber = async () => Number(BigInt(await rpc('eth_blockNumber', [])));

const padAddr = a => lc(a).replace('0x', '').padStart(64, '0');
const wordToAddr = w => '0x' + String(w).slice(-40);
const wordToBig = w => BigInt(w);
const wordToBool = w => BigInt(w) !== 0n;
function decodeString(hex) {
  try {
    const h = hex.replace('0x', '');
    if (h.length <= 64) { // short string returned inline (bytes32-style)
      const bytes = Buffer.from(h.replace(/(00)+$/, ''), 'hex');
      return bytes.toString('utf8');
    }
    const len = Number(BigInt('0x' + h.slice(64, 128)));
    return Buffer.from(h.slice(128, 128 + len * 2), 'hex').toString('utf8');
  } catch { return null; }
}
async function tryCall(to, data, decode) {
  try { const r = await ethCall(to, data); return decode ? decode(r) : r; }
  catch { return null; }
}

// ---------- Sourcify ----------
async function sourcifyLookup(address) {
  try {
    const { status, json } = await fetchJson(
      `${SOURCIFY_BASE}/v2/contract/${CHAIN_ID}/${lc(address)}?fields=abi,runtimeMatch,creationMatch,compilation.name`);
    if (status === 404 || !json) return { status: 'not_verified', abiSignatures: null, contractName: null };
    const match = json.runtimeMatch || json.match || null;
    let abiSignatures = null;
    if (Array.isArray(json.abi)) {
      abiSignatures = new Set(json.abi.filter(e => e.type === 'function')
        .map(e => `${e.name}(${(e.inputs || []).map(i => i.type).join(',')})`));
    }
    return {
      status: match === 'exact_match' ? 'exact_match' : match ? 'partial_match' : 'not_verified',
      abiSignatures,
      contractName: json.compilation?.name || null
    };
  } catch { return { status: 'unknown', abiSignatures: null, contractName: null }; }
}

// ---------- Honeypot / tax simulation ----------
async function honeypotLookup(address) {
  try {
    const { json } = await fetchJson(`https://api.honeypot.is/v2/IsHoneypot?address=${lc(address)}&chainID=${CHAIN_ID}`);
    if (!json || !json.honeypotResult) return null;
    return {
      isHoneypot: !!json.honeypotResult.isHoneypot,
      buyTax: json.simulationResult?.buyTax ?? null,
      sellTax: json.simulationResult?.sellTax ?? null,
      transferTax: json.simulationResult?.transferTax ?? null,
      flags: json.flags ?? []
    };
  } catch { return null; }
}

// ---------- Liquidity reality ----------
async function liquidityLookup(address) {
  const out = { v2Pair: null, wbnbReserve: null, depthBnb: null, depthClass: null, lpBurnedPct: null, dexscreener: null };
  try {
    const pair = await tryCall(ADDRESSES.pancakeV2Factory, CALLS.getPair + padAddr(address) + padAddr(ADDRESSES.wbnb), wordToAddr);
    if (pair && lc(pair) !== ADDRESSES.zero.toLowerCase()) {
      out.v2Pair = pair;
      const t0 = await tryCall(pair, CALLS.token0, wordToAddr);
      const reserves = await tryCall(pair, CALLS.getReserves, r => r);
      if (reserves && t0) {
        const h = reserves.replace('0x', '');
        const r0 = BigInt('0x' + h.slice(0, 64));
        const r1 = BigInt('0x' + h.slice(64, 128));
        const wbnbReserve = lc(t0) === lc(ADDRESSES.wbnb) ? r0 : r1;
        out.wbnbReserve = wbnbReserve.toString();
        out.depthBnb = Number(wbnbReserve) / 1e18;
        out.depthClass = out.depthBnb < 1 ? 'dust' : out.depthBnb < 5 ? 'thin' : out.depthBnb < 50 ? 'fair' : 'deep';
      }
      const [supply, deadBal] = await Promise.all([
        tryCall(pair, CALLS.totalSupply, wordToBig),
        tryCall(pair, CALLS.balanceOf + padAddr(ADDRESSES.dead), wordToBig)
      ]);
      if (supply && supply > 0n && deadBal !== null) out.lpBurnedPct = Number((deadBal * 10000n) / supply) / 100;
    }
  } catch { /* leave nulls */ }
  if (!out.v2Pair) {
    try {
      const { json } = await fetchJson(`https://api.dexscreener.com/latest/dex/tokens/${lc(address)}`);
      const pairs = (json?.pairs || []).filter(p => p.chainId === 'bsc');
      if (pairs.length) {
        const best = pairs.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];
        out.dexscreener = { dex: best.dexId, pair: best.pairAddress, liquidityUsd: best.liquidity?.usd ?? null, url: best.url };
      }
    } catch { /* ignore */ }
  }
  return out;
}

// ---------- Main contract audit ----------
export async function auditContract(address) {
  const checkedAt = new Date().toISOString();
  if (!isAddress(address)) return { error: 'invalid_address', address, checkedAt };
  address = lc(address) === address ? address : address; // keep caller's casing for display
  const addr = address;

  const code = await getCode(addr).catch(() => null);
  if (code === null) return { error: 'rpc_unavailable', address: addr, checkedAt };
  if (code === '0x') {
    return { address: addr, chainId: CHAIN_ID, checkedAt, isContract: false,
      verdict: 'NOT_A_CONTRACT', score: null,
      summary: 'This address holds no deployed code — it is a wallet (EOA), not a contract.',
      flags: [{ severity: 'info', code: 'not_a_contract', message: 'No bytecode at this address.' }] };
  }
  const block = await blockNumber().catch(() => null);

  // Proxy resolution (EIP-1967)
  let impl = null, admin = null;
  try {
    const [i, a] = await Promise.all([getStorage(addr, SLOTS.implementation), getStorage(addr, SLOTS.admin)]);
    const ia = wordToAddr(i); const aa = wordToAddr(a);
    if (lc(ia) !== ADDRESSES.zero.toLowerCase()) impl = ia;
    if (lc(aa) !== ADDRESSES.zero.toLowerCase()) admin = aa;
  } catch { /* not a standard proxy */ }
  const target = impl || addr;
  const targetCode = impl ? await getCode(impl).catch(() => code) : code;

  const [src, honeypot, liquidity] = await Promise.all([
    sourcifyLookup(target), honeypotLookup(addr), liquidityLookup(addr)
  ]);

  // Live probes on the user-facing address
  const [owner, pendingOwner, paused, name, symbol, decimals, totalSupply, tradingEnabled] = await Promise.all([
    tryCall(addr, CALLS.owner, wordToAddr),
    tryCall(addr, CALLS.pendingOwner, wordToAddr),
    tryCall(addr, CALLS.paused, wordToBool),
    tryCall(addr, CALLS.name, decodeString),
    tryCall(addr, CALLS.symbol, decodeString),
    tryCall(addr, CALLS.decimals, r => Number(BigInt(r))),
    tryCall(addr, CALLS.totalSupply, r => BigInt(r).toString()),
    tryCall(addr, TRADING_ENABLED, wordToBool)
  ]);

  // Privilege inventory: bytecode scan, cross-checked with verified ABI.
  const codeHex = (targetCode || '').replace('0x', '').toLowerCase();
  const privileges = {};
  for (const entry of SENSITIVE) {
    const inBytecode = entry.selectors.filter(s => codeHex.includes(s.slice(2)));
    if (!inBytecode.length) continue;
    const inAbi = src.abiSignatures
      ? entry.signatures.filter(sig => src.abiSignatures.has(sig))
      : null;
    privileges[entry.category] = {
      functions: entry.signatures.filter((_, i) => inBytecode.includes(entry.selectors[i])),
      confirmedInAbi: inAbi === null ? null : inAbi.length > 0,
      abiFunctions: inAbi
    };
  }

  // ---- Scoring (transparent, every deduction lists its evidence) ----
  const flags = [];
  let score = 100;
  const hit = (severity, code, message, points) => { flags.push({ severity, code, message }); score -= points; };

  if (src.status === 'not_verified') hit('high', 'unverified_source',
    'Source code is NOT verified on Sourcify — nobody can read what this contract really does.', 30);
  else if (src.status === 'partial_match') hit('medium', 'partial_source_match',
    'Source is only a partial (metadata) match on Sourcify, not an exact bytecode match.', 12);
  else if (src.status === 'unknown') hit('low', 'verification_unknown',
    'Verification status could not be checked this run (Sourcify unreachable).', 5);

  const ownerLive = owner && lc(owner) !== ADDRESSES.zero.toLowerCase();
  if (ownerLive) hit('low', 'owner_live',
    `Contract still has a live owner (${owner}) — owner-only powers remain usable.`, 8);
  else if (owner) flags.push({ severity: 'info', code: 'owner_renounced', message: 'Ownership is renounced (owner = zero address); owner-only powers are inert.' });
  if (pendingOwner && lc(pendingOwner) !== ADDRESSES.zero.toLowerCase())
    hit('medium', 'pending_owner', `An ownership transfer is pending to ${pendingOwner} (Ownable2Step left hanging).`, 8);
  if (admin) {
    const adminCode = await getCode(admin).catch(() => null);
    const adminIsEoa = adminCode === '0x';
    hit(adminIsEoa ? 'high' : 'medium', 'proxy_admin',
      `Upgrade admin ${admin} is a ${adminIsEoa ? 'single wallet (EOA) — one key can replace the contract logic' : 'contract'}.`, adminIsEoa ? 15 : 10);
  }
  if (impl) flags.push({ severity: 'info', code: 'proxy', message: `Proxy contract — audited implementation ${impl} behind it.` });

  if (paused === true) hit('high', 'paused_now',
    'The contract is PAUSED right now — transfers can be blocked while paused.', 30);
  else if (privileges.pause) hit('low', 'can_pause',
    'Owner can pause the contract (pause function present, currently not paused).', privileges.pause.confirmedInAbi ? 8 : 4);

  if (tradingEnabled === false) hit('high', 'trading_disabled',
    'Trading is NOT enabled — buys may succeed while sells/transfers stay locked.', 30);
  else if (privileges['trading-gate']) flags.push({ severity: 'low', code: 'trading_gate_exists', message: 'A trading on/off switch exists in the code.' });

  if (privileges.blacklist) hit('medium', 'blacklist_power',
    `Blacklist/bot-list control present (${privileges.blacklist.functions.join(', ')}) — the team can freeze specific wallets.`,
    privileges.blacklist.confirmedInAbi ? 15 : 8);
  if (privileges.mint) hit('medium', 'mint_power',
    `Mint function present (${privileges.mint.functions.join(', ')}) — supply may be inflatable${ownerLive ? ' while an owner is live' : ''}.`,
    privileges.mint.confirmedInAbi ? (ownerLive ? 12 : 4) : 6);
  if (privileges.upgrade) hit('medium', 'upgrade_power',
    'Upgrade function present in the implementation — logic can be replaced after launch.', privileges.upgrade.confirmedInAbi ? 12 : 6);
  if (privileges['fee-setter']) hit('medium', 'fee_setter',
    `Owner can change taxes/fees after launch (${privileges['fee-setter'].functions.join(', ')}).`, privileges['fee-setter'].confirmedInAbi ? 10 : 5);
  if (privileges['max-tx']) hit('low', 'max_tx_setter',
    'Owner can set max-transaction / max-wallet limits (can trap large holders).', 5);
  if (privileges.withdraw) flags.push({ severity: 'low', code: 'withdraw_present', message: `Fund-withdraw functions present (${privileges.withdraw.functions.join(', ')}). Normal for mint proceeds; dangerous if it can reach user funds.` });
  if (privileges.metadata) flags.push({ severity: 'low', code: 'metadata_mutable', message: 'Metadata/baseURI setter present — NFT metadata can be changed after mint.' });

  if (honeypot) {
    if (honeypot.isHoneypot) { flags.push({ severity: 'critical', code: 'honeypot', message: 'Honeypot simulation: buying works but SELLING IS BLOCKED.' }); score = Math.min(score, 15); }
    if (honeypot.sellTax !== null && honeypot.sellTax > 25) hit('high', 'sell_tax_extreme', `Sell tax is ${honeypot.sellTax}% — above the 25% hard-cap line.`, 25);
    else if (honeypot.sellTax !== null && honeypot.sellTax > 10) hit('medium', 'sell_tax_high', `Sell tax is ${honeypot.sellTax}%.`, 12);
    if (honeypot.buyTax !== null && honeypot.sellTax !== null && honeypot.buyTax > 0 && honeypot.sellTax > 3 * honeypot.buyTax)
      hit('medium', 'tax_asymmetry', `Sell tax (${honeypot.sellTax}%) is more than 3x the buy tax (${honeypot.buyTax}%).`, 12);
  } else if (symbol) {
    flags.push({ severity: 'low', code: 'simulation_unavailable', message: 'Honeypot/tax simulation unavailable this run — exit path not proven by simulation.' });
  }

  if (symbol) { // looks like a token: judge its market reality
    if (liquidity.depthClass === 'dust') hit('medium', 'dust_pool',
      `The PancakeSwap V2 pool holds only ${liquidity.depthBnb?.toFixed(4)} BNB — a permissionless dust pool. Any displayed price is NOT a real market price.`, 10);
    else if (liquidity.depthClass === 'thin') hit('low', 'thin_pool',
      `Pool depth is thin (${liquidity.depthBnb?.toFixed(2)} BNB).`, 5);
    if (liquidity.v2Pair && liquidity.lpBurnedPct !== null && liquidity.lpBurnedPct < 50 && (liquidity.depthBnb ?? 0) < 5)
      hit('medium', 'lp_not_burned', `Only ${liquidity.lpBurnedPct}% of LP tokens are burned and depth is low — the LP can likely be pulled.`, 8);
    if (!liquidity.v2Pair && !liquidity.dexscreener)
      hit('medium', 'no_market', 'No live PancakeSwap V2 pair or DexScreener market found — there is no observable way to sell this token at any price.', 10);
  }

  score = Math.max(0, Math.min(100, score));
  let verdict = score >= 80 ? 'SAFE' : score >= 50 ? 'CAUTION' : 'DANGER';
  if (src.status === 'not_verified' && verdict === 'SAFE') verdict = 'CAUTION'; // never call unverified code SAFE

  const top = flags.filter(f => ['critical', 'high'].includes(f.severity)).map(f => f.message);
  const summary = verdict === 'SAFE'
    ? `No blocking risk found. Verified source, no live honeypot signal${top.length ? '' : ', no critical owner power detected'}. Reference only — not financial advice.`
    : `${verdict}: ${top[0] || flags[0]?.message || 'Review the flags before interacting.'} Reference only — not financial advice.`;

  return {
    agent: 'bsc-wallet-guard', version: '0.1.0', chainId: CHAIN_ID, block, checkedAt,
    address: addr, isContract: true,
    token: symbol || name ? { name, symbol, decimals, totalSupply } : null,
    verification: { sourcify: src.status, contractName: src.contractName, auditedTarget: target },
    proxy: impl ? { isProxy: true, implementation: impl, admin } : { isProxy: false },
    state: { owner, ownerLive: !!ownerLive, pendingOwner, paused, tradingEnabled },
    privileges,
    market: liquidity,
    simulation: honeypot,
    score, verdict, summary, flags
  };
}

// ---------- Pending-transaction / calldata screening ----------
export async function checkTx({ to, data = '0x', value = '0' } = {}) {
  const checkedAt = new Date().toISOString();
  if (!isAddress(to)) return { error: 'invalid_to_address', checkedAt };
  const flags = [];
  const selector = (data || '0x').slice(0, 10).toLowerCase();
  const fn = TX_SELECTORS[selector] || null;
  const body = (data || '0x').replace('0x', '');
  const word = i => '0x' + body.slice(8 + i * 64, 8 + (i + 1) * 64);
  let decoded = { selector, function: fn || 'unknown' };
  let worst = 'SAFE';

  const flag = (severity, code, message) => {
    flags.push({ severity, code, message });
    if (severity === 'critical' || severity === 'high') worst = 'DANGER';
    else if (worst === 'SAFE') worst = 'CAUTION';
  };

  let valueWei = 0n;
  try { valueWei = BigInt(value); } catch { /* treat as 0 */ }

  if (fn === 'approve(address,uint256)') {
    const spender = wordToAddr(word(0));
    const amount = BigInt(word(1));
    decoded.args = { spender, amount: amount.toString() };
    if (amount === 2n ** 256n - 1n)
      flag('high', 'unlimited_approval', `UNLIMITED approval: ${spender} will be able to move ALL of your tokens held in ${to}, at any time, until you revoke it. This is the single most abused permission in wallet drains.`);
    else if (amount > 0n)
      flag('medium', 'approval', `Approval: ${spender} may spend up to ${amount.toString()} units of the token at ${to} on your behalf.`);
    else flags.push({ severity: 'info', code: 'approval_revoke', message: 'Approval amount is 0 — this revokes a previous approval. Good hygiene.' });
  } else if (fn === 'setApprovalForAll(address,bool)') {
    const operator = wordToAddr(word(0));
    const approved = BigInt(word(1)) !== 0n;
    decoded.args = { operator, approved };
    if (approved) flag('high', 'approval_for_all', `setApprovalForAll: ${operator} will be able to transfer EVERY NFT you hold in the collection ${to}. Only grant this to marketplaces you trust.`);
    else flags.push({ severity: 'info', code: 'approval_for_all_off', message: 'This removes an operator approval for the collection. Good hygiene.' });
  } else if (fn) {
    flags.push({ severity: 'info', code: 'standard_call', message: `Standard token call: ${fn}.` });
  } else if (data && data !== '0x') {
    flags.push({ severity: 'low', code: 'unknown_calldata', message: `Unrecognized function selector ${selector} — the call is decoded by screening the destination contract below.` });
  } else {
    flags.push({ severity: 'info', code: 'plain_transfer', message: 'Plain BNB transfer (no calldata).' });
  }

  // Screen the destination contract itself.
  const targetAudit = await auditContract(to).catch(() => null);
  if (targetAudit && !targetAudit.error) {
    if (targetAudit.verdict === 'DANGER') flag('high', 'target_danger', `Destination contract screens as DANGER (score ${targetAudit.score}). ${targetAudit.summary}`);
    else if (targetAudit.verdict === 'CAUTION' && worst === 'SAFE') flag('medium', 'target_caution', `Destination contract screens as CAUTION (score ${targetAudit.score}).`);
    if (valueWei > 0n && targetAudit.verification?.sourcify === 'not_verified')
      flag('medium', 'value_to_unverified', 'This call sends BNB to an UNVERIFIED contract — its behavior cannot be read.');
  }

  return {
    agent: 'bsc-wallet-guard', version: '0.1.0', chainId: CHAIN_ID, checkedAt,
    to, valueWei: valueWei.toString(), decoded, flags,
    verdict: worst,
    targetAudit: targetAudit && !targetAudit.error
      ? { verdict: targetAudit.verdict, score: targetAudit.score, sourcify: targetAudit.verification?.sourcify }
      : null,
    summary: flags.filter(f => ['critical', 'high', 'medium'].includes(f.severity))[0]?.message ||
      'No blocking risk found in this call. Reference only — not financial advice.'
  };
}
