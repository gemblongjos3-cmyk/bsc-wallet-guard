// Function-selector tables for BSC (chain 56) contract screening.
// Selectors computed with Keccak-256 over the canonical signature.
// CALLS: view functions we actively probe with eth_call.
// SENSITIVE: owner-power functions whose *presence* in bytecode (and, when a
// verified ABI exists, in the ABI) is a risk signal. Presence alone is never
// treated as proof of a live feature — the audit cross-checks the ABI and
// live state (see audit.js and the bsc-contract-audit playbook's rule:
// "a selector in bytecode may be library or dead code").

export const CALLS = {
  owner: '0x8da5cb5b',          // owner()
  pendingOwner: '0xe30c3978',   // pendingOwner()
  paused: '0x5c975abb',         // paused()
  totalSupply: '0x18160ddd',    // totalSupply()
  name: '0x06fdde03',           // name()
  symbol: '0x95d89b41',         // symbol()
  decimals: '0x313ce567',       // decimals()
  balanceOf: '0x70a08231',      // balanceOf(address)
  getPair: '0xe6a43905',        // getPair(address,address)
  getReserves: '0x0902f1ac',    // getReserves()
  token0: '0x0dfe1681',         // token0()
  token1: '0xd21220a7'          // token1()
};

export const SENSITIVE = [
  // category, signatures present in deployed bytecode
  { category: 'mint', signatures: ['mint(address,uint256)', 'mint(uint256)', 'mintTo(address,uint256)', 'publicMint(uint256)', 'safeMint(address)'],
    selectors: ['0x40c10f19', '0xa0712d68', '0x449a52f8', '0x2db11544', '0x40d097c3'] },
  { category: 'pause', signatures: ['pause()', 'unpause()'],
    selectors: ['0x8456cb59', '0x3f4ba83a'] },
  { category: 'blacklist', signatures: ['blacklist(address)', 'blackList(address)', 'setBot(address,bool)', 'addBot(address)', 'setBlacklist(address,bool)', 'isBlacklisted(address)'],
    selectors: ['0xf9f92be4', '0x4838d165', '0x342aa8b5', '0xffecf516', '0x153b0d1e', '0xfe575a87'] },
  { category: 'upgrade', signatures: ['upgradeTo(address)', 'upgradeToAndCall(address,bytes)'],
    selectors: ['0x3659cfe6', '0x4f1ef286'] },
  { category: 'fee-setter', signatures: ['setTaxFeePercent(uint256)', 'setBuyFee(uint256)', 'setSellFee(uint256)', 'setFee(uint256)', 'setFees(uint256,uint256)', 'excludeFromFee(address,bool)'],
    selectors: ['0x061c82d0', '0x0cc835a3', '0x8b4cee08', '0x69fe0e2d', '0x0b78f9c0', '0xdf8408fe'] },
  { category: 'trading-gate', signatures: ['enableTrading()', 'setTradingEnabled(bool)', 'openTrading()'],
    selectors: ['0x8a8c523c', '0xc2e5ec04', '0xc9567bf9'] },
  { category: 'max-tx', signatures: ['setMaxTxAmount(uint256)', 'setMaxWallet(uint256)', 'setMaxWalletSize(uint256)'],
    selectors: ['0xec28438a', '0x5d0044ca', '0xea1644d5'] },
  { category: 'withdraw', signatures: ['withdraw()', 'withdrawAll()', 'rescueTokens(address,uint256)', 'emergencyWithdraw()'],
    selectors: ['0x3ccfd60b', '0x853828b6', '0x57376198', '0xdb2e21bc'] },
  { category: 'metadata', signatures: ['setBaseURI(string)', 'setBaseUri(string)'],
    selectors: ['0x55f804b3', '0xa0bcfc7f'] }
];

export const TRADING_ENABLED = '0x4ada218b'; // tradingEnabled()

export const TX_SELECTORS = {
  '0x095ea7b3': 'approve(address,uint256)',
  '0xa22cb465': 'setApprovalForAll(address,bool)',
  '0xa9059cbb': 'transfer(address,uint256)',
  '0x23b872dd': 'transferFrom(address,address,uint256)'
};

export const ADDRESSES = {
  wbnb: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
  pancakeV2Factory: '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73',
  dead: '0x000000000000000000000000000000000000dEaD',
  zero: '0x0000000000000000000000000000000000000000'
};

// EIP-1967 storage slots
export const SLOTS = {
  implementation: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
  admin: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103'
};
