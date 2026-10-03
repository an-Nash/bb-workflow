# Ultimate Crypto Audit & Hack Guideline
### Synthesized from 807 Audit / Hack Reports (~3,799 Individual Vulnerabilities) in `reports-summery/`

> **Purpose:** A single comprehensive field manual for **humans and AI agents** to hunt vulnerabilities in real-world crypto codebases (EVM/Solidity dominant, plus Starknet/Cairo, Cosmos, Solana-adjacent, L1/L2 bridges, ZK verifiers, Account Abstraction).
>
> **How it was built:** Batch-read all 807 files in 9 batches (1-100, 101-200, ..., 801-807). Extracted every `Vulnerability #N` header, severity, root-cause, PoC and remediation. Ran corpus-wide frequency analysis. Deep-dived ~30 landmark reports (TheDAO, Parity x2, Wormhole, Arbitrum DelayedInbox, Uniswap x ERC777, Enzyme/Idele oracle, Balancer ERC4626 rounding, Fei flashloan, Perpetual bad-debt, Notional double-count, MakerDSChief, Linea PLONK verifier, LayerZero gas-DoS, Gnosis Safe backdoor, ERC2771+Multicall spoof, 1inch AggregationRouter, ScopeLift voting, Linea bridge, Balancer boosted pools, etc.). This file distills them into huntable patterns.
>
> **Corpus frequency snapshot (case-insensitive hits across ~4MB corpus):**
> - Governance/voting: ~1350 | Input validation/zero-address: ~1000 | Access control/unauthorized/init: ~848 | Proxy/UUPS/delegatecall/storage: ~802 | Fee/interest/accounting/exchangeRate: ~688 | Bridge/cross-chain/messenger: ~649 | Approval/permit/allowance: ~626 | Integer overflow/unchecked: ~533 | Front-run/MEV/sandwich: ~459 | Reentrancy: ~448 | Centralization/owner-privilege/rug: ~365 | Timelock/multisig: ~334 | Signature/ECDSA/nonce/permit: ~318 | DoS/griefing/gas-limit/loop: ~303 | Oracle/price/TWAP/Chainlink: ~205 | Flashloan/flashmint/flashswap: ~205 | Rounding/precision/division: ~204 | ERC777/hooks: ~158 | AA/4337/paymaster/bundler: ~120 | ZK/PLONK/verifier/soundness: ~107 | ERC4626/inflation/donation: ~42 (low count but **critical severity per occurrence**)
>
> **Severity lesson:** Highest count ≠ highest loss. Most fund-loss-critical in corpus: reentrancy + oracle manipulation + ERC4626 inflation + uninitialized proxy + signature spoof + bridge accounting. Lowest count (ERC4626, ZK soundness) often = highest severity.

---

## Table of Contents

1. [How to Use This Guideline (Human vs AI)](#1-how-to-use-this-guideline-human-vs-ai)
2. [Universal Audit Methodology - 5 Phases](#2-universal-audit-methodology--5-phases)
3. [VULN-01: Reentrancy (Classic, Cross-Function, Read-Only, Cross-Protocol, ERC777/1155 Hooks)](#vuln-01-reentrancy-classic-cross-function-read-only-cross-protocol-erc7771155-hooks)
4. [VULN-02: Access Control & Authorization Bypass](#vuln-02-access-control--authorization-bypass)
5. [VULN-03: Proxy / Upgradeability / Initialization](#vuln-03-proxy--upgradeability--initialization)
6. [VULN-04: Price Oracle Manipulation](#vuln-04-price-oracle-manipulation)
7. [VULN-05: Flash Loan / Flash Mint / Economic & Bad-Debt Attacks](#vuln-05-flash-loan--flash-mint--economic--bad-debt-attacks)
8. [VULN-06: Precision, Rounding, and Accounting Errors](#vuln-06-precision-rounding-and-accounting-errors)
9. [VULN-07: ERC-4626 Inflation / Donation / First-Depositor Attack](#vuln-07-erc-4626-inflation--donation--first-depositor-attack)
10. [VULN-08: Signatures - Replay, Malleability, EIP-712, Permit, ERC-2771 Spoof](#vuln-08-signatures--replay-malleability-eip-712-permit-erc-2771-spoof)
11. [VULN-09: Front-Running, Sandwich, Back-Running, MEV](#vuln-09-front-running-sandwich-back-running-mev)
12. [VULN-10: Denial of Service, Griefing, Gas Abuse, Unbounded Loops](#vuln-10-denial-of-service-griefing-gas-abuse-unbounded-loops)
13. [VULN-11: Governance / Voting / Proposal Manipulation](#vuln-11-governance--voting--proposal-manipulation)
14. [VULN-12: Bridges, Cross-Chain Messaging, L1↔L2](#vuln-12-bridges-cross-chain-messaging-l1l2)
15. [VULN-13: Token-Standard Quirks (ERC20/777/721/1155, Fee-on-Transfer, Rebasing, Pausable)](#vuln-13-token-standard-quirks-erc207777211155-fee-on-transfer-rebasing-pausable)
16. [VULN-14: Approvals, Allowance, Permit2, Custom Approval Logic](#vuln-14-approvals-allowance-permit2-custom-approval-logic)
17. [VULN-15: Centralization, Rugpull, Timelock & Multisig Bypass](#vuln-15-centralization-rugpull-timelock--multisig-bypass)
18. [VULN-16: Account Abstraction (ERC-4337), Delegation, Snaps/Wallet](#vuln-16-account-abstraction-erc-4337-delegation-snapswallet)
19. [VULN-17: ZK Verifiers, Cryptography, Merkle Proofs, Precompiles](#vuln-17-zk-verifiers-cryptography-merkle-proofs-precompiles)
20. [VULN-18: Integer Overflow/Underflow, Truncation, Type Confusion](#vuln-18-integer-overflowunderflow-truncation-type-confusion)
21. [Appendix A: AI/Human Grep & Static-Analysis Pack](#appendix-a-aihuman-grep--static-analysis-pack)
22. [Appendix B: Fuzzing & Invariant Templates](#appendix-b-fuzzing--invariant-templates)
23. [Appendix C: Audit Checklist (Paste into Every Review)](#appendix-c-audit-checklist-paste-into-every-review)
24. [Appendix D: Report-to-Pattern Index (Where Each Lesson Came From)](#appendix-d-report-to-pattern-index-where-each-lesson-came-from)

---

## 1. How to Use This Guideline (Human vs AI)

### For humans
1. Start with §2 methodology. Do Pass 1 (access/proxy/oracle) before deep logic.
2. For each VULN chapter, run its **Hunting Checklist** top-to-bottom. Do not skip "low count" chapters (VULN-07, VULN-17) — they are low-frequency, fatal-severity.
3. For every external call, token transfer, oracle read, signature check, and upgrade function, force yourself to write the **exploit transaction sequence** (attacker contracts + ordering), not just "this looks risky."

### For AI agents (Cursor / Claude Code / Pi / Codex / Slither-assisted)
- Treat each VULN chapter as a **detector spec**: `Pattern → Query → PoC sketch → Invariant to fuzz`.
- Recommended agent loop per file:
  1. `grep` with Appendix A regexes → collect candidates.
  2. For each candidate, answer: *Can an attacker reach it? Can they control a parameter/value/timing? What is the profit path in 1 tx (flashloan?) or N txs?*
  3. Generate a Foundry/Hardhat PoC stub (attacker contract + fork test) before marking as confirmed.
  4. Propose minimal fix + regression invariant (Appendix B).
- Prompt template you can reuse:
  ```
  You are auditing {file}:{function}. Check ONLY for {VULN-XX} per ultimate_crypto_audit_hack_guideline.md.
  Output: (1) reachable? (2) attacker-controlled inputs? (3) vulnerable code quote,
  (4) exploit steps numbered, (5) profit estimate, (6) fix diff, (7) fuzz invariant.
  If not exploitable, say why (what check blocks it) with line refs.
  ```

---

## 2. Universal Audit Methodology — 5 Phases

Derived from what repeatedly found bugs across the 807 reports:

**Phase 1 — Trust boundaries & privileges (30 min, highest ROI)**
- List every `onlyOwner/admin/guardian/operator/pauser/upgrader` role. Who can mint, pause, upgrade, set oracle, set fees, rescue tokens, change bridge mapping?
- List every `initialize/setup/enableModule/addOwner/changeThreshold` — is it callable twice / by anyone / on implementation?
- List every `delegatecall/call/staticcall` — who controls `target` and `data`?

**Phase 2 — Money flow & accounting invariants**
- Draw deposits → shares → withdrawals → fees → rewards. For each: `totalAssets()`, `totalSupply()`, `exchangeRate`, `fee`, `rewardPerToken` — where do they come from (balance vs internal var vs oracle)?
- Ask: *What if token is fee-on-transfer, rebasing, ERC777, has >18 decimals, returns no bool, or is donated directly? What if first deposit is 1 wei? What if pool is empty/balanced/extreme?*

**Phase 3 — Time, order & external dependence**
- Mark every oracle read, TWAP, Chainlink round, Uniswap spot, `block.timestamp/number`, `msg.sender/tx.origin`, signature/nonce, cross-chain message, callback hook. Assume each is attacker-influenced within one block unless proven otherwise (flashloan, donation, front-run).

**Phase 4 — Adversarial transaction sequencing**
- For each sensitive function, enumerate: front-run it, back-run it, sandwich it, reenter it (same fn + every other external fn), call it with 0/1 wei/dust/max, call it twice in same block, call it from constructor, call it via multicall/batch, delay its message (bridge/4337).

**Phase 5 — Upgrade & failure modes**
- Simulate upgrade: storage layout diff, reinitializer, implementation self-destruct, admin key loss, oracle downtime, pauser grief, rate-limiter DoS, gas-exhaustion on L1→L2.

> **Unique insight from corpus:** ~60%+ of criticals were *composition bugs* (two safe features combined unsafely): ERC2771+Multicall, flashswap+rounding, TWAP+single-tick liquidity, proxy+selfdestruct, bridge+ERC777. Always audit **pairs**, not just singles.

---

## VULN-01: Reentrancy (Classic, Cross-Function, Read-Only, Cross-Protocol, ERC777/1155 Hooks)

### Why it dominates
Single most repeated fund-loss primitive in corpus (TheDAO $50M, Uniswap×ERC777, 0x v4 Ether theft, Euler×1inch cross-protocol, Linea TokenBridge, RocketPool `distribute/finalise`, Lybra liquid-staking, Radiant `emergencyWithdraw`, dForce/Fuji missing guards). Post-Istanbul (EIP-1884) `transfer/send` 2300-gas protection is **dead** — corpus explicitly warns against relying on it.

### Root causes seen
1. **State after interaction:** `send ETH → update balance` (TheDAO, 0x).
2. **Wrong order with hooks:** `calculate price → send ETH → pull tokens` where token is ERC777/ERC1155 with `tokensToSend/received` callback (Uniswap, Linea bridge `bridgeToken` balance-diff).
3. **Partial guards:** `nonReentrant` on `withdraw` but not on `borrow/claim/reward` sharing same state; public getters exposing mid-state (read-only reentrancy — highlighted in `final-results-blockchain-hacking-techniques-of-202*`).
4. **Cross-protocol:** Calling Euler/1inch/Convex that calls back into your accounting (`0xE400...` Euler×1inch, `exchangeRate` manipulation).
5. **Balance-diff without guard:** `before = balanceOf(); token.transferFrom(); after-balance` is reenterable if token has hooks.

### Vulnerable code vs fix

```solidity
// ❌ VULNERABLE (TheDAO / 0x / Uniswap-Vyper equivalent)
function withdraw(uint amt) public {
    require(balances[msg.sender] >= amt);
    (bool ok,) = msg.sender.call{value: amt}(""); // interaction first
    require(ok);
    balances[msg.sender] -= amt; // effect after
}
// ERC777 variant (Uniswap tokenToEthInput - simplified)
function tokenToEth(uint tokensSold) public {
    uint ethBought = getInputPrice(tokensSold);
    (bool ok,) = msg.sender.call{value: ethBought}(""); // ETH out first
    require(ok);
    require(token.transferFrom(msg.sender, address(this), tokensSold)); // hook reenters here
}

// ✅ FIXED — CEI + guard + pull pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Fixed is ReentrancyGuard {
    mapping(address=>uint) balances;
    function withdraw(uint amt) external nonReentrant {
        require(balances[msg.sender] >= amt, "insufficient");
        balances[msg.sender] -= amt; // effects first
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "send fail");
    }
    // For hook-tokens: pull tokens BEFORE sending ETH, + nonReentrant
    function tokenToEth(uint tokensSold) external nonReentrant {
        uint ethBought = getInputPrice(tokensSold);
        require(token.transferFrom(msg.sender, address(this), tokensSold));
        (bool ok,) = msg.sender.call{value: ethBought}("");
        require(ok);
    }
}
```

Read-only reentrancy fix: make view functions return consistent snapshots OR guard mutating entry points so views are never read mid-flight; remove `getPrice()` that reads transient `totalSupply/balances` during callbacks.

### Pattern / code smell (for grep)
- Any `.call{value:} / .send / .transfer` before state write.
- `transferFrom/mint/burn/safeTransfer` on arbitrary ERC20/777/1155 before accounting update.
- `nonReentrant` present on *some* but not *all* external functions touching same `mapping`.
- `balanceOf(this) - before` accounting without `nonReentrant`.
- External call to lending/AMM/strategy (`Euler`, `1inch`, `Convex`, `Curve`, `Uniswap`) then local state update.

### Exploitation (generic)
1. Deploy attacker with `receive()/tokensToSend()/onERC1155Received()` that re-calls `withdraw/bridgeToken/claim`.
2. Deposit small amount → call `withdraw` → on ETH receipt, reenter N times before `balances` zeroed → drain.
3. ERC777 variant: `tokenToEthSwap` → hook fires during `transferFrom` → reenter second swap at stale price → repeat → final transfer only once.
4. Read-only: reenter `getReward/price()` mid-`withdraw` to borrow/mint at stale share price.
5. Cross-protocol: trigger victim → Euler → attacker hook → back into victim's `repay/borrow`.

### Unique hunting insight (what most auditors miss)
- **Treat EVERY token transfer as a callback.** In corpus, teams whitelisted "ERC20" but attacker passed ERC777/ERC1155 with hooks, or fee-on-transfer token that breaks `balance-diff`. Fuzz with a malicious ERC777 mock for every `bridgeToken/deposit/swap`.
- **Check the second call, not the first.** Many fixes guard `withdraw` but leave `claimRewards/deleverage/swapTokens` unguarded sharing `balances`. Build a call-graph: if two external functions write same slot and only one has `nonReentrant`, flag.
- **Istanbul lesson:** `transfer()` no longer prevents reentrancy. If you see `transfer/send` justified as "reentrancy safe due to gas," mark Critical.
- **AI query:** `List all external calls (call/delegatecall/token hooks) and for each, list storage writes AFTER it. Output function, line, written slot.`

**Representative reports:** `15-lines-of-code-that-could-have-prevented-thedao`, `exploiting-uniswap-from-reentrancy-to-actual-profi`, `audits-2020-12-0x-exchange-v4`, `linea-bridge-audit-1`, `audits-2023-01-rocket-pool-atlas-v1-2`, `reentrancy-after-istanbul`, `radiant-riz-audit`, `rareskills/read-only-reentrancy` theme in `final-results-blockchain-hacking-techniques-of-202*`.

---

## VULN-02: Access Control & Authorization Bypass

### Why it dominates
Second-highest frequency (~848 hits). Includes: `confirmChange` with no check (28k bounty), `Hypervisor.deposit` missing `msg.sender` check (Gamma), `didTransferShares` no modifier (Forta), `InfinityPool` auth bypass (Glif), `ReserveFeed` no ACL (Ion), `Space AMM onSwap` missing ACL (Sense), Alchemix `AlchemistEth`, Enzyme missing forwarder check.

### Root causes
1. Missing `onlyOwner/onlyRole` on sensitive setter/mint/withdraw/upgrade.
2. Wrong `msg.sender` used (e.g., `deposit(victim)` credits `msg.sender` vs `onBehalfOf` confusion; `swapLiquidity` draining others in Aave v2 review).
3. `tx.origin` for auth (phishable; also breaks AA) — flagged in `account-abstractions-impact`.
4. Unprotected `initialize` (→ VULN-03).
5. Overprivileged `module/guardian/operator` that can call `execTransactionFromModule` without threshold (Gnosis Safe).

### Vulnerable vs fixed

```solidity
// ❌ Missing check (Gamma Hypervisor pattern, Forta pattern)
function deposit(uint amt, address to) external {
    // no check that msg.sender == to or authorized
    _mint(to, shares);
    // attacker mints to self with victim's approval/credit
}
function didTransferShares(address from, address to, uint amt) external {
    _move(from, to, amt); // anyone can move anyone's shares
}

// ✅ Fixed
import "@openzeppelin/contracts/access/AccessControl.sol";
contract Fixed is AccessControl {
    bytes32 constant OPERATOR = keccak256("OPERATOR");
    function deposit(uint amt, address to) external {
        require(msg.sender == to || hasRole(OPERATOR, msg.sender), "not auth");
        _mint(to, previewShares(amt));
    }
    function didTransferShares(address f, address t, uint a) external onlyRole(OPERATOR) {
        _move(f, t, a);
    }
}
```

Also: never use `tx.origin` for auth:
```solidity
// ❌ require(tx.origin == owner);
// ✅ require(msg.sender == owner); // + ERC4337-compatible (EntryPoint is msg.sender, validate via signature)
```

### Pattern / smell
- `public/external` + `mint/burn/setOwner/setOracle/setFee/pause/upgrade/withdrawRescue/transferShares` with no modifier.
- `msg.sender` vs `to/from/onBehalfOf` mismatch.
- `tx.origin` anywhere.
- `require(isModule(to))` but `to/data` attacker-controlled (Safe setup).

### Exploitation
1. Direct call: `confirmChange()`, `didTransferShares(victim, attacker, bal)`, `setOperator(attacker)`.
2. Confused deputy: victim approves pool; attacker calls `depositFrom(victim)` crediting self.
3. Phishing via `tx.origin`: trick owner to call malicious contract which calls `victim.withdraw()` — `tx.origin==owner` passes.

### Unique hunting insight
- **Diff `to` vs `msg.sender` on every mint/credit.** If function takes `address to/from` + moves value, and lacks `onlyX` or `msg.sender==to` check, it's almost always Critical. AI: auto-list all such functions.
- **Check initializer AND implementation.** Many ACLs are in proxy admin but implementation exposes same fn unguarded.
- **Modules = owners.** Treat every Safe/DAO module, guardian, operator, keeper as full owner. If module can be added by single tx or during setup, it's takeover.
- Real case: `28k-bounty-admin-brick-forced-revert` — `confirmChange()` with no ACL allowed bricking; `immunefi-alchemix-access-control`, `immunefi-sense-finance-access-control`, `ion-protocol-audit ReserveFeed`.

---

## VULN-03: Proxy / Upgradeability / Initialization

### Why it kills bridges & L2s
Most catastrophic bridge/L2 findings: Parity $30M+$300M frozen, Wormhole hundreds of millions at risk, Arbitrum DelayedInbox $250M hijack demo, Linea/zksync storage collisions, `oeth-withdrawal-queue __gap` decrement, Transparent vs UUPS confusion.

### Root causes (taxonomy from corpus)
1. **Uninitialized implementation:** UUPS/Transparent impl `initialize()` callable by anyone → attacker becomes owner/guardian → `upgradeTo(malicious)` → `selfdestruct` (Wormhole, `blog-high-risk-...-ondo`, `audits-2023-09-leequid-staking`, `origin-dollar-audit-2`).
2. **Storage wipe on upgrade:** `postUpgradeInit` `sstore(0,0)` clearing `initialized/owner/sequencerInbox` + removed `ALREADY_INIT` check for gas (Arbitrum).
3. **Storage collision:** proxy `implementation/admin` at slot 0 colliding with impl `value/initialized`; `__gap` mis-sized; Diamond facet selector replacement corrupting array (zksync-layer-1, Scroll Phase-2 wrong slot calc).
4. **Selector clash:** proxy `upgrade(address)` selector == impl function selector → non-admin can upgrade (State-of-Upgrades, Transparent-Proxy-Pattern).
5. **Constructor instead of initializer:** `owner` set in constructor never runs via proxy → zero owner (Towards-Frictionless-Upgradeability).
6. **Selfdestruct/delegatecall in impl:** `kill()/destruct` reachable via proxy or directly on impl (Parity second hack froze $300M).
7. **Unremoved reinitializer:** `reinitializer(2)` left executable → re-hijack (Linea rollup update).

### Vulnerable vs fixed

```solidity
// ❌ Parity-style + UUPS-uninitialized
contract WalletLib {
    function initWallet(address[] memory o, uint r) public { // no guard
        owners = o; required = r;
    }
    function() external payable { _lib.delegatecall(msg.data); } // catch-all
}
// UUPS impl without disable
contract MyUUPS is UUPSUpgradeable {
    function initialize(address o) public initializer { __Ownable_init(); _transferOwnership(o); }
    // missing: constructor() { _disableInitializers(); }
}

// ✅ Fixed (OZ v4.4.2+ / v5)
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
contract FixedUUPS is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); } // locks impl
    function initialize(address o) public initializer {
        __Ownable_init(o); __UUPSUpgradeable_init();
    }
    function _authorizeUpgrade(address) internal override onlyOwner {}
    uint256[50] private __gap; // reserve, never reorder, append-only
}
// Storage: use EIP-1967 slots, never slot 0 for impl vars; validate with `forge inspect` / OZ upgrades plugin.
```

Arbitrum fix: restore `require(bridge==address(0))`, never wipe `initialized`, verify post-upgrade state:
```solidity
function postUpgradeInit(address newBridge, address newInbox) external onlyOwner {
    require(!postUpgraded, "done");
    bridge = newBridge; sequencerInbox = newInbox; // set ALL wiped slots
    postUpgraded = true;
}
```

### Pattern / smell
- `initialize/setup/initWallet` without `initializer/reinitializer` + `onlyOwner` + `_disableInitializers` in constructor.
- `delegatecall` with `msg.data` or `to/data` params in fallback/setup.
- `selfdestruct/suicide` anywhere in impl or library.
- `__gap` missing/misplaced/decremented; storage vars reordered between versions.
- `upgradeTo/upgradeAndCall/setImplementation` reachable by non-admin; transparent proxy without `if (msg.sender==admin)` split.
- `initializer` modifier state at slots 0-1 being manually `sstore`'d.

### Exploitation
1. **Impl takeover:** `cast call <impl> "initialize(address)" <attacker>` → `upgradeTo(attackerImpl)` → drain proxy OR `selfdestruct` to brick.
2. **Parity:** `initWallet([attacker],1)` via fallback `delegatecall` → `execute(attacker, balance, "")`.
3. **Arbitrum:** after upgrade wipes slots, `initialize(attackerBridge,...)` → deposits routed to attacker.
4. **Storage collision:** craft impl where `setValue(x)` overwrites `implementation` slot → point proxy at attacker.

### Unique hunting insight
- **Always check the implementation address directly on Etherscan.** If `initialized==false` / `owner==0`, it's exploitable even if proxy looks safe. AI: fetch impl slot `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` and call `owner()/initialized()`.
- **Diff storage layout on every upgrade PR.** Use `forge inspect <contract> storage-layout` before/after; any reorder/insert (not append) = Critical. Corpus has 5+ such (Notional, OETH, Scroll, zksync).
- **Ban `selfdestruct` + `delegatecall(msg.data)` by policy** in impls; add Slither `suicidal,controlled-delegatecall` to CI.
- **Gas-optimization removals are red flags.** Arbitrum removed `ALREADY_INIT` for gas — treat any deleted `require` in upgrade path as Critical until proven safe.

**Representative:** `on-the-parity-wallet-multisig-hack`, `parity-wallet-hack-reloaded`, `immunefi-wormhole-uninitialized-proxy`, `-0xriptide-hackers-in-arbitrums-inbox`, `the-state-of-smart-contract-upgrades`, `the-transparent-proxy-pattern`, `testing-real-world-contract-upgrades`, `zksync-layer-1-diff-audit`, `oeth-withdrawal-queue-audit`.

---

## VULN-04: Price Oracle Manipulation

### Root causes
1. **Spot-price-as-oracle:** `price = reserveA/reserveB` or `totalAssets/totalSupply` read in same tx (Enzyme×Idle, Fei×Uniswap, Origin slippage, Balancer boosted).
2. **No TWAP / stale Chainlink:** missing `updatedAt`/`answeredInRound` checks, single source, no deviation circuit breaker (`price-oracle-audit`, `origin-oeth-integration`, `venus-protocol-oracles` outdated interface).
3. **Manipulatable `totalSupply`:** flash-mint/burn or donation changes denominator (Idle v5 flashloan empties balance).
4. **Missing slippage:** `swapExactTokensForTokens(amt, 0, path)` (Origin C01, Fei `addLiquidityETH` 100% tolerance).
5. **Concentrated-liquidity mark-price:** Perpetual v2 single-tick infinite leverage moves mark far from index.

### Vulnerable vs fixed

```solidity
// ❌ Spot oracle + zero slippage
function tokenPrice() public view returns (uint p) {
    p = idle.totalAssets() * 1e18 / idle.totalSupply(); // manipulatable in-tx
}
router.swapExactTokensForTokens(rewardAmt, 0, path, address(this), block.timestamp); // 0 min-out

// ✅ TWAP + Chainlink guard + slippage from oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
function safePrice(address feed) internal view returns (uint) {
    (, int ans,, uint upd, ) = AggregatorV3Interface(feed).latestRoundData();
    require(ans > 0 && block.timestamp - upd < MAX_DELAY, "stale");
    return uint(ans);
}
function liquidate(uint rewardAmt, uint minOutFromOracle) external onlyKeeper {
    // minOut derived from TWAP/oracle with 0.5-1% tolerance, plus deadline
    router.swapExactTokensForTokens(rewardAmt, minOutFromOracle, path, address(this), block.timestamp + 300);
}
// For AMM-based: use TWAP (Uniswap V3 observe / Chainlink) + deviation check:
require(abs(mark - index)*1e18/index < MAX_DEV, "deviation");
```

### Exploitation (Enzyme/Fei template)
1. Flashloan large `UNDERLYING` → manipulate pool/supply (dump ETH, empty Idle balance, or single-tick push).
2. Call victim `buyShares/allocate/liquidate` at distorted price (victim uses spot).
3. Unwind manipulation, repay flashloan, keep shares bought cheap / tokens sold dear.
4. Perpetual variant: multi-account 1%-by-1% pushes to bypass per-tx limit, then single-tick exit with no slippage.

### Unique hunting insight
- **If price can move in the same tx as it's consumed, it's broken.** Search `totalSupply/totalAssets/getReserves/balanceOf(pool)` feeding `buyShares/mint/borrow/liquidate/allocate`. Ask: *Can I flashloan/donate to move it >2%?* If yes → Critical.
- **Zero `amountOutMin` = auto-Critical** (Origin, Fei). AI: flag every swap/liquidity call with `0` min-out.
- **Check Chainlink hygiene:** must validate `answer>0`, `updatedAt` freshness, `answeredInRound>=roundId`, decimals, sequencer uptime (L2). Missing any = High.
- **L2/Blast/queued-asset edge:** Across/Oval DAI-to-Blast, Coinbase push failures — oracles that silently don't update on new chains. Test on fork of destination chain.

**Representative:** `immunefi-enzyme-finance-price-oracle-manipulation`, `immunefi-fei-protocol-flashloan`, `how-openzeppelin-foiled-a-catastrophic-hack`, `origin-dollar-audit C01`, `2023-02-07-bad-debt-attack-for-perpetual-protocol`, `aave-protocol-audit C01/C02`, `compound-open-oracle`, `price-oracle-audit`.

---

## VULN-05: Flash Loan / Flash Mint / Economic & Bad-Debt Attacks

Extends VULN-04: flash loans as **leverage**, not just oracle moves. Corpus: Fei 60k ETH, Balancer 20% TVL, Perpetual $40M insurance, UMA flash-voting, Origin reward swaps.

### Root causes
- Protocol assumes attacker capital ≈ own balance; flashloan gives infinite intra-tx capital.
- `nonContract/isContract/extcodesize` bypassed via constructor (Fei) → flashloan contract passes "EOA-only."
- No per-block / per-tx caps, no TWAP delay between `deposit→borrow`, `buy→redeem`, `vote→execute`.

### Vulnerable vs fixed

```solidity
// ❌ EOA-only via extcodesize (bypassable)
modifier nonContract(){ require(!Address.isContract(msg.sender), "no contracts"); _; }
// Attacker calls from constructor where extcodesize==0.

// ✅ Economic guards (not identity guards)
function buyShares(uint amt) external nonReentrant {
    uint price = twapPrice(); // not spot
    uint shares = amt * 1e18 / price;
    _mint(msg.sender, shares);
    require(block.timestamp - lastAction[msg.sender] > COOLDOWN || amt < DUST_CAP, "cooldown");
}
// + flashloan-aware: use reentrancy guard, reservation of price across callback,
// + caps: maxBorrowPerBlock, maxDeviation, funding-rate that spikes with deviation.
```

### Exploitation checklist
- Can I `flashloan → distort → victimAction → undistort → repay` in one tx? (Fei, Enzyme, Balancer)
- Can I `flashloan → vote → execute` in same block? (UMA, Anvil quorum) → require snapshot + delay.
- Can I `flashmint → inflate supply → manipulate governance/price → burn`? (flash-mintable-backed tokens post)

### Unique hunting insight
- **Replace identity checks with economic checks.** `isContract/tx.origin` never stops flashloans. Require TWAP + cooldown + caps.
- **Fuzz with flashloan amount = 10x TVL.** If invariant `solvent`/`priceStable` breaks, flag.
- AI: for each `mint/borrow/vote/allocate`, ask *"What if caller has 1B borrowed for this tx only?"*

---

## VULN-06: Precision, Rounding, and Accounting Errors

### Root causes (most under-audited)
1. **Division before multiplication:** `x/n*y` truncates to 0 for small x (Alpha Homora fee-on-others, Bancor `reducedFraction`).
2. **Rounding always down (or up) against protocol:** attacker repeats 1-wei ops to bleed pool (Balancer 1-wei swap bleed, DFX EURS assimilator, Notional vault division-by-zero).
3. **Stale/cached exchange rate:** GrowthDeFi cached Compound rate, dForce `exchangeRateStored` inaccuracy.
4. **Double-count / missing clear:** Notional bitmap+activeCurrencies double-count (26M DAI at risk), `enableBitmap` not clearing old currency.
5. **Fee/interest miscalc:** Synthetix fee rebate, Tidal staking, Trufin totalStaked, Ramses `positionPeriodSecondsInRange` add-vs-sub, `SPL` negative mint.
6. **Units/decimals:** Aave high-decimal underflow, `abs(int256.min)` revert (MCDEX), 1inch `depositUnderflow`, Venus `venusVAIVaultRate` irreversibility.

### Vulnerable vs fixed

```solidity
// ❌ div-before-mul + round-down drain
uint fee = (amt / 10000) * feeBps; // 0 for amt<10000
uint shares = amt / price; // truncates; 1-wei swaps bleed pool

// ✅ mul-before-div + explicit rounding direction + dust guard
uint fee = amt * feeBps / 10000; // protocol-favorable: round UP fees, DOWN payouts
uint shares = FixedPointMathLib.mulDivDown(amt, 1e18, price);
require(amt >= MIN_AMT && shares > 0, "dust");
// Balancer lesson: enforce MIN_SWAP + fee even when balanced + rate-change limit
require(swapAmt >= MIN_SWAP, "too small");
```

Notional fix: clear old state on transitions:
```solidity
function enableBitmap(uint16 newCcy) external {
    uint16 old = bitmapCcy[msg.sender];
    if (old != 0 && old != newCcy) _clearActiveCurrency(msg.sender, old);
    bitmapCcy[msg.sender] = newCcy;
    _setActiveCurrency(msg.sender, newCcy);
}
```

### Hunting insight
- **Test 0, 1 wei, 1, dust, max, empty pool, balanced pool.** Corpus criticals triggered at 1 wei (Balancer), empty vault (ERC4626), balanced (no-fee) pool.
- **Round fees UP, payouts DOWN, always.** If code uses `/` before `*` or bare `/` for shares, flag. AI: list every `/` and `*` order.
- **State-transition audit:** every `enable/disable/switch/migrate/set` must clear old accounting. Write invariant `sum(userCollateral)==poolBalance` and fuzz transitions.
- **Decimals matrix:** test 6 (USDC), 8 (WBTC), 18, 24+ decimals; `transfer` with no return (USDT) — see VULN-13.

**Representative:** `immunefi-balancer-rounding-error`, `immunefi-dfx-finance-rounding-error`, `immunefi-notional-double-counting`, `immunefi-synthetix-logic-error`, `alpha-homora-v2 M01`, `audits-2022-07-notional-finance div0`, `audits-2024-08-ramses-v3`, `mcdex-mai-fund-protocol abs`.

---

## VULN-07: ERC-4626 Inflation / Donation / First-Depositor Attack

### Why separate chapter
Low count (~42) but **near-universal Critical** for new vaults. Dedicated report `a-novel-defense-against-erc4626-inflation-attacks` + Forta staking vault `Incomplete ERC4626`, RestakeFi `Share Downscaling`, Pods `assetsOf` miscount.

### Root cause
`shares = assets * totalSupply / totalAssets` with `totalSupply==0` → 1:1. Attacker deposits 1 wei → donates 100e18 → victim deposit `100e18*1/100e18+1 ≈ 0` → attacker redeems all.

Variants: `totalAssets()` uses `balanceOf(vault)` (donatable via direct transfer) vs internal accounting; fee-on-transfer/rebasing breaks `convertTo`.

### Vulnerable vs fixed

```solidity
// ❌ Naive
function convertToShares(uint a) public view returns (uint){
    return totalSupply()==0 ? a : a * totalSupply() / totalAssets();
}
// totalAssets() returns token.balanceOf(address(this)) // donatable!

// ✅ OZ v5: virtual offset + dead shares + internal accounting
// Use OpenZeppelin ERC4626 (decimalsOffset) +:
constructor() ERC4626(token) ERC20("Vault","VLT") {
    // _decimalsOffset = 3..6 recommended; plus:
    _mint(address(0xdead), 1e6); // dead shares, or require min initial deposit
}
function totalAssets() public view override returns (uint){
    return _trackedAssets; // internal, updated only via deposit/withdraw, not raw balance
}
// Alternative: require(totalSupply()==0 ? assets>=MIN_INITIAL : true);
```

Full OZ pattern:
```solidity
function _convertToShares(uint assets, Math.Rounding r) internal view override returns (uint){
    return assets.mulDiv(totalSupply()+10**_decimalsOffset(), totalAssets()+1, r);
}
function _convertToAssets(uint shares, Math.Rounding r) internal view override returns (uint){
    return shares.mulDiv(totalAssets()+1, totalSupply()+10**_decimalsOffset(), r);
}
```

### Exploitation
1. Front-run vault creation: `deposit(1)` → `transfer(vault, 1e18)` → victim `deposit(1e18)` gets 0-1 shares → `redeem(all)` steals victim.
2. Even without front-run: donate to push `totalAssets` up, then small victim deposits round to 0.

### Unique hunting insight
- **If vault is new/empty/forkable, assume attacked.** Check: `decimalsOffset>0? dead shares? totalAssets uses balanceOf?` If any no → Critical.
- **Donation test is mandatory:** `token.transfer(vault, X)` directly (not via deposit) then `deposit()` — shares must not collapse. AI: auto-generate this test.
- **Also check `withdraw/mint/redeem` rounding directions** (shares up on withdraw, assets down on deposit per EIP-4626).

---

## VULN-08: Signatures — Replay, Malleability, EIP-712, Permit, ERC-2771 Spoof

### Sub-types in corpus
1. **Missing nonce/expiry/chainId/contract in signed message:** Umbra missing contract addr, ScopeLift fractional-vote replay, Ironblocks `ApprovedCallsPolicy` replay, Starbase permit-from-other-trade, `castVoteBySig` 4337-incompatible (zksync L2 governance).
2. **ECDSA malleability (EIP-2098 compact, `s` upper-half):** 1inch ECDSA lib, require `s <= n/2` + `v in {27,28}`.
3. **ERC2771+Multicall spoof (Critical, live 84 ETH+17k USDC stolen):** `ERC2771Context._msgSender()` reads last 20 bytes of calldata; `Multicall.delegatecall` lets attacker append any `trustedForwarder||victimAddr` suffix → spoof `onlyOwner`.
4. **Permit front-run / wrong refund:** UniswapX/Starbase DCA theft via others' permit; 1inch refund to `to` not `from`.
5. **Off-chain vote/signature ordering:** `voteData (For,Against,Abstain)` vs struct `(Against,For,Abstain)` mismatch.

### Vulnerable vs fixed

```solidity
// ❌ Replayable vote / permit
function castVoteBySig(uint pid, bool sup, uint8 v, bytes32 r, bytes32 s) external {
    address voter = ecrecover(keccak256(abi.encode(pid, sup)), v, r, s); // no nonce, chainid, contract
    _vote(pid, voter, sup);
}
// ❌ ERC2771+Multicall (pre-fix OZ)
function _msgSender() internal view returns (address) {
    if (msg.sender == trustedForwarder) return address(bytes20(msg.data[msg.data.length-20:]));
    return msg.sender;
}
// multicall() blindly delegatecalls each subcall preserving trailing suffix → spoof

// ✅ Fixed — EIP-712 + nonce + deadline + chain + contract
bytes32 constant VOTE_TYPEHASH = keccak256("Vote(uint256 pid,uint8 sup,uint256 nonce,uint256 deadline)");
mapping(address=>uint) nonces;
function castVoteBySig(uint pid, uint8 sup, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline, "expired");
    bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(VOTE_TYPEHASH, pid, sup, nonces[msg.sender]++, deadline)));
    address voter = ECDSA.recover(digest, v, r, s);
    require(voter != address(0), "bad sig");
    _vote(pid, voter, sup);
}
// ECDSA: require(uint(s) <= HALF_N && (v==27||v==28));
// ERC2771+Multicall: upgrade OZ (context-aware Multicall) OR disable forwarder OR remove one of the two features.
// Permit: bind permit to specific order/nonce/spender/amount/deadline; never accept permit from different trade.
```

### Hunting insight
- **For every `ecrecover/permit/castBySig`, list signed fields.** Must include: `chainId` (or EIP-712 domain with chainId+verifyingContract), `nonce` (incremented), `deadline`, `contract address`, `action-specific params`. Missing any = High/Critical.
- **If contract inherits BOTH `ERC2771Context` and `Multicall`, stop and verify OZ version.** Pre-fix = Critical. Test spoof: `multicall([abi.encodePacked(calldata, victimAddr)])` via forwarder.
- **Malleability:** `s` must be low-S; compact sigs must be rejected or normalized. AI: grep `ecrecover` without `ECDSA.recover` wrapper.
- **Permit theft:** if `permit` + `transferFrom` in same tx from different orders, check binding. Starbase: taker reused permit from trade A in trade B.

**Representative:** `arbitrary-address-spoofing-vulnerability-erc2771co`, `audits-2022-08-1inch-exchange... ECDSA malleability`, `scopelift-flexible-voting-audit`, `ironblocks-onchain-firewall-audit`, `audits-2024-08-starbase`, `audits-2021-03-umbra`, `eip-4337-...-incremental (replay on paymaster)`.

---

## VULN-09: Front-Running, Sandwich, Back-Running, MEV

### Manifestations
- Pooltogether winning-pods front-run with large deposit; TheGraph `redeem` front-run denies rewards; UMA `approve` front-run; DRAM `MintCap` front-run; UniswapX Dutch auction MEV; Oval sudden-price MEV; Tidal `addPremium` back-run; Notional `resolve` repeat.
- 0x `AssetProxyOwner` blocking, Bancor oracle atomic front-run, RocketPool sandwich on price update.

### Root cause
Public mempool + deterministic ordering + no commit-reveal/slippage/deadline/batch. Any `deposit→draw`, `swap(0 minOut)`, `setCap`, `claimReward` is orderable.

### Fix patterns
```solidity
// Slippage + deadline on EVERY swap/withdraw/claim
function swap(uint amtIn, uint minOut, uint deadline) external {
    require(block.timestamp <= deadline, "expired");
    uint out = _swap(amtIn);
    require(out >= minOut, "slippage");
}
// Commit-reveal for lottery/pods:
function commit(bytes32 h) external { commits[msg.sender]=h; }
function reveal(uint secret) external { require(keccak256(abi.encode(secret))==commits[msg.sender]); _enter(); }
// Caps/privileged sets: pre-announce + timelock, or batch at same price (no first-come advantage).
```

### Hunting insight
- **Ask for every state-changing fn: *What if I'm second in the block?*** If profit/eligibility changes (pod win prob, reward amount, price), require slippage/deadline/commit.
- **Mempool simulation:** AI should propose two orderings (victim-first vs attacker-first) and compute delta.
- MEV-specific: Dutch auction without filler bond (UniswapX), `updateAlpha` breaking accounting (Venus Prime) — check filler/keeper incentives can't be arbitraged.

---

## VULN-10: Denial of Service, Griefing, Gas Abuse, Unbounded Loops

### Sub-types
1. **Unbounded loops over user-controlled arrays:** `calcAccountEquity` loop (dForce), `revokeVotes` OOG (Celo), `withdrawUnstaked` gas limit (pSTAKE), Fiinu loops.
2. **Push payments to untrusted addresses:** Lien reverting fallback locks payouts; must use pull.
3. **Griefing via dust/flood:** Web3Tickets arbitrary creation flood, Charged Particles royalty grief, InstaDApp ownership-transfer DoS ×2.
4. **Gas-exhaustion in messaging:** LayerZero `NonBlockingLzApp` 63/64 + 22k store-fail (payload stuck), Linea `postman` heavy blocks, Scroll rate-limiter DoS.
5. **Rate-limiter/protocol-wide limits:** Linea bridge rate limit bricks all users; ScrollOwner rate abuse.
6. **Selfdestruct/gas-token (GST2) + EIP-4844 blob misuse:** `SELFDESTRUCT` deprecation, arbitrary blob lib (Scroll EIP-4844).

### Fix
```solidity
// ❌ Push + loop
for (uint i=0;i<users.length;i++) users[i].send(payout); // one revert bricks all
// ✅ Pull + paginate
mapping(address=>uint) pending;
function withdraw() external { uint a=pending[msg.sender]; pending[msg.sender]=0; (bool ok,)=msg.sender.call{value:a}(""); require(ok); }
function process(uint start, uint n) external onlyKeeper { /* paginated */ }
```

LayerZero fix: reserve 25k for failure-store, cap callback gas (`gasleft()-25000`).

### Hunting insight
- **Any loop over `array.length` where array grows via external call = High.** Require pagination + max length.
- **Any `.send/transfer` in loop or to arbitrary addr = DoS.** Demand pull.
- **For L0/L1→L2:** compute worst-case callback gas (63/64 rule) + store-fail cost; fuzz malicious receiver that burns all gas.
- AI: flag `for (...; i<*.length; ...)` + `send/transfer/call` inside.

---

## VULN-11: Governance / Voting / Proposal Manipulation

High-count (~1350) + high-impact (Maker $100M, Compound Dec 2021, Audius, Anvil quorum-with-zero-votes, UMA flash-voting, ScopeLift replay).

### Root causes
1. **Unetched/unvalidated slate/hash:** Maker `vote(bytes32 slate)` with no `slates[slate].length>0` → vote removal + MKR lock.
2. **Quorum reachable with 0 votes / without deposits:** Anvil `Proposals Can Reach Quorum Without Any Votes`, Audius stake lock.
3. **Flashloan voting:** UMA phases, Fei `GenesisGroup.commit` overwrite, Compound Bravo missing validation.
4. **Signature replay in voting:** ScopeLift fractional (see VULN-08).
5. **Proposal lifecycle DoS:** Compound queue/cancel/execute impossible with repeated actions; Bridge receiver `localTimelock` brick; Governor duplicate txs; `verifyNonce` skipping.
6. **Multisig/governance centralization:** Convex 1.5B rug multisig, Compound Gov can approve transfers (C-III).

### Vulnerable vs fixed (Maker)
```solidity
// ❌ Maker DSChief
function vote(bytes32 slate) public {
    subWeight(approvals[msg.sender], approvals[msg.sender]);
    approvals[msg.sender]=slate; addWeight(slate, approvals[msg.sender]);
}
// addWeight loops slates[slate] — empty if unetched → weight removed, never re-added.

// ✅
function vote(bytes32 slate) public {
    require(slate==bytes32(0) || slates[slate].length>0, "not etched");
    // ...
}
```

### Hunting insight
- **Governance must have: snapshot (no same-block vote), timelock delay, quorum counting For+Abstain correctly, proposal uniqueness, cancellation path, vote-weight checkpoint.** Missing any = High.
- **Test zero-vote quorum, double-vote, vote-then-transfer, flash-vote.** AI: generate 5 governance attack txs per system.
- **Check `COUNTING_MODE`:** `bravo` (For only) vs `for,abstain` — mismatch breaks quorum (ScopeLift).

---

## VULN-12: Bridges, Cross-Chain Messaging, L1↔L2

~649 hits; most expensive when broken (Wormhole, Arbitrum, Linea, Scroll, Mantle, Avalanche Teleporter, Across, Socket/Celer).

### Recurring bugs
1. **Reentrancy in `bridgeToken` via hooks** (Linea C01, Scroll BatchBridge sender-hooks steal/lock).
2. **Refund/theft on failed route:** Socket Celer refund stealable; `Calls to Non-Existent Routes Succeed`.
3. **Mint-out-of-thin-air fee:** Avalanche Teleporter fee minted, not paid.
4. **Small-denomination trap / blacklisted refund fail:** Across deadline + blacklist leaves `refundLeaf` unexecutable.
5. **Aliasing & messenger theft:** zksync WETH `Address Aliasing` locks ETH; Mantle `BVM_ETH/MNT in Messengers Stealable`; `CrossDomainMessenger` relay fail.
6. **No replay/destination validation:** Ava Warp missing replay + destination chain check.
7. **Gas/finalization:** Linea heavy blocks stall finalization, `Incorrect Final Block`, Scroll `Incorrect Batch Hashes / RLP(0)`, Mantle DA `id 1` unretrievable.
8. **Token-address collision:** Linea `Tokens Sharing Addresses Steal Funds / Prevent Bridging`.
9. **ERC721 through ERC20 bridge → locked NFTs.**

### Hunting checklist (bridge-specific)
- [ ] `bridgeToken/deposit` has `nonReentrant` + handles ERC777/1155 hooks + fee-on-transfer (`amount = after-before`, but guarded)?
- [ ] Refunds go to `msg.sender/depositor`, not `to`? Failed route reverts (not succeeds)?
- [ ] Mint/burn symmetric? Fee NOT minted (check `mint(fee)`)?
- [ ] Replay protection per chainId+nonce+source? Destination validated?
- [ ] L1↔L2 alias (`applyL1ToL2Alias`) handled — can't lock via aliased addr?
- [ ] `completeBridging` atomically updates `nativeStatus/mapping` (no async gap)?
- [ ] Rate limiter per-user + bypass monitoring (not global-only DoS)?
- [ ] Finalization validates block number/tree depth/pubdata; no hardcoded genesis incompatible with new nets?
- [ ] Custom bridged token `initialize` protected; decimals fallback doesn't mask ERC721?

AI prompt: *"Trace deposit on L1 → message → mint on L2 → withdraw → burn → release. For each step list attacker-reachable reentry/replay/retry and fund-theft delta."*

---

## VULN-13: Token-Standard Quirks (ERC20/777/721/1155, Fee-on-Transfer, Rebasing, Pausable)

### Corpus wisdom
- **Non-compliant ERC20 (no bool return — USDT):** Bitbank, Aave Safety, Barnbridge H01, Balancer non-compliant handling. Must use `SafeERC20`.
- **Fee-on-transfer (FoT):** Blog-BB1-DFX unsupported FoT, Fei decimals, DefiSaver >18 decimals. Never assume `amountIn == received`.
- **ERC777 hooks:** Fairmint FAIR steal via hooks, Uniswap drain (see VULN-01).
- **ERC721 in ERC20 bridge:** locked (Linea).
- **Decimals:** Aave CPM high-decimal underflow, Tierion `decimals` type, `Tokens with no decimals locked in Niftyswap`.
- **Pausable/allowance:** Auki `Paused token doesn't pause allowance`, blocklist limits unclear (Mountain), `withdrawAll` unsupported tokens (Origin Metapool).
- **Zero-transfer poisoning:** `how-to-ensure-web3-users-are-safe-from-zero-transf` — `transferFrom(0)` event spoof poisons address books; wallets must not trust `Transfer` events alone.

### Fix canon
```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
uint before = token.balanceOf(address(this));
token.safeTransferFrom(from, address(this), amt);
uint received = token.balanceOf(address(this)) - before; // FoT-safe
_shares = received.mulDivDown(totalSupply(), totalAssets()); // use received, not amt
// + nonReentrant if token may be 777/1155; + decimals check (6..24); + no bool assumption.
```

### Hunting insight
- **Fuzz every money fn with 4 token mocks:** standard, no-return, FoT (10%), rebasing (+/-), ERC777-hooks-malicious. If any breaks accounting → High.
- **Check `approve` race + `safeApprove`:** use `safeIncreaseAllowance`, never `approve(spender, type-max)` blindly (see VULN-14).

---

## VULN-14: Approvals, Allowance, Permit2, Custom Approval Logic

~626 hits. Patterns: 1inch `Allowance Management`, Daofi `addLiquidity` approval theft, Beefy Zap `Permit2 steals tokens`, Redacted `wxBTRFLY custom approval bug`, Centre `No Allowance Decrement`, Auki allowance-during-pause, Augur `All CASH approved to Augur can be emptied`.

### Bugs
- `permit`/`Permit2` witness mismatch lets filler spend more than taker approved (Starbase, 1inch maker-takes-more).
- Custom `approve` not decrementing / not checking `allowance-amount` (Redacted, Centre).
- `transferFrom` without allowance check on L2/aliased path (UniswapX, Scroll).
- Infinite approval to aggregator that gets exploited (Augur).

### Fix
```solidity
// Bind permit tightly; verify spender==this, nonce, deadline, amount; use Permit2 witness for order hash.
PERMIT2.permit(msg.sender, PermitSingle({details:{token, amount, expiration, nonce}, spender: address(this), sigDeadline: dl}), sig);
// Never: token.approve(spender, type(uint).max) without timelock/revoke UX; prefer exact + increase/decrease.
```

### Hunting insight
- **List every `approve/permit/permit2/transferFrom`.** For each: *Who is spender? Can amount/spender/nonce be swapped from another order? Does allowance decrement?* If spender is user-supplied or permit is replayable → Critical.

---

## VULN-15: Centralization, Rugpull, Timelock & Multisig Bypass

### Patterns
- **Multisig rug:** Convex multisig could rug $15B (anonymous team + EOA control); Paxos owners never removable; DRAM all-roles-same-account; Kiln `setOperator` privilege.
- **Timelock bypass (game-theoretic, not code):** beneficiary is contract → tokenize future claim → sell before unlock (Bypassing-Timelocks). Fix: EOA-only beneficiary (`msg.sender==tx.origin` narrowly justified here) or signature-bound vesting, or cliff+linear with non-transferable position.
- **Admin brick / forced revert:** `confirmChange` brick (28k), Compound `pauseGuardian` irreplaceable, `BaseBridgeReceiver localTimelock` brick.
- **Gnosis Safe backdoor:** `setup(to,data)` delegatecall + overprivileged modules (`execTransactionFromModule` no threshold).

### Hunting insight
- **Map every privileged fn to timelock delay + multisig threshold + revocation path.** If `setOwner/setOracle/upgrade/mint` is EOA-instant → Critical (centralization). Demand `TimelockController(minDelay) + Safe(3/5) + guardian veto`.
- **For vesting/timelocks:** check `beneficiary` can be contract → if yes, bypass exists. Demand EOA proof or soulbound claim.
- **For Safes:** verify `setup` data, no modules at deploy unless audited, `isModule` allowlist, factory is canonical.

---

## VULN-16: Account Abstraction (ERC-4337), Delegation, Snaps/Wallet

~120 hits but growing. Reports: `account-abstractions-impact`, `eip-4337-incremental`, `erc-4337-incremental`, `eth-foundation-aa-audit`, `argent-multisig-Starknet`, `metamask-delegator/delegation-framework`, `particle-btc-account`, snaps (Starknet/ShapeShift/Fil/Solflare/MSQ/Tezoro/Push/WalletGuard).

### Bugs
- **Paymaster throttle/manipulation:** ops throttle paymaster, deposit manipulation, prefund miscalc, no fee limits (Argent V3).
- **Replay on paymaster / `OutsideExecution` ID mismatch:** EIP-4337 aggregate sig invalid, verifying-paymaster replay.
- **Delegation front-run:** `NativeTokenPaymentEnforcer` open-delegation front-run; `Delegators Can Abuse Gas`; `No Guarantee of Execution`.
- **Snap dapp trust:** `eth_signMessage` silent signing, dapp manages keys, markdown/control-char injection, private-key export exposed, missing origin check, uncontrolled address addition.
- **4337-incompatible governance:** `castVoteWithReasonAndParamsBySig` breaks with smart wallets (zksync L2 governance, Decentralized-Governance multisig-incompatible `immutable`).

### Hunting insight
- **Never assume `msg.sender` is EOA; never use `tx.origin`.** EntryPoint is sender; validate via `validateUserOp` signature + nonce + `validAfter/Until`.
- **Paymaster:** cap gas/fee, require `deadline`, TWAP price for token paymasters, throttle per sender.
- **Delegation:** bind `authority+delegate+caveats+nonce+expiry`; prevent front-run by `redeem` allowlist.
- **Snaps/UX:** origin-check every RPC, sanitize markdown/ctrl chars, never expose `exportPrivateKey` to dapp, show full message pre-sign.

---

## VULN-17: ZK Verifiers, Cryptography, Merkle Proofs, Precompiles

~107 hits, fatal when hit: Linea PLONK `u` missing `Wζ` (proof forgery → steal rollup), `Qci` missing from γ/β (frozen-heart), `so-far-digest` deviation, unconstrained memory write (Chainlight zkEVM soundness), `Last Challenge Attack`, quotient shards not blinded (BSB22), incorrect randomness, Astar ERC20 precompile truncation, Balance/Asset precompile impersonation (okyEG4...), Frontier truncation CVE-2022-31111, Merkle `checkMembership` multi-location + exclusion-of-present-key (MerkleDB), `checkMerkleRootAndVerifySignatures` public (Aligned), SHA256 mis-impl (Particle).

### Hunting insight
- **Fiat-Shamir must hash FULL transcript in order.** For every challenge (`β,γ,α,ζ,u,v`), verify every prior commitment/input is included. Missing one = forgery (Linea #1). Compare against paper/spec line-by-line; fuzz with mutated proof.
- **Precompiles:** test truncation (`uint256→uint128`), impersonation (`msg.sender` vs precompile caller), aliasing.
- **Merkle:** test duplicate leaf, second-preimage, exclusion-of-included, empty-leaf, bitmap length. Demand `leaf = hash(domain, ...)` with domain separation.
- AI: *"List all challenge derivations; for each, list hashed inputs; diff against spec §X; propose forgery if any input missing."*

---

## VULN-18: Integer Overflow/Underflow, Truncation, Type Confusion

~533 hits. Classic (SKALE overflow steal, Matchpool SafeMath gap) + modern (unchecked math in L2, `abs(int.min)` revert, `quantize` overflow DoS (Forta Firewall), signed-compare bug, `int256` division-by-zero (Notional Vault), `uint` loop index overflow (Polymath), `decimals` type mismatch, Frontier/Astar truncation draining via precompile).

### Fix canon (0.8.x still needs care in `unchecked` + truncation)
```solidity
// Always mul-before-div; audit every `unchecked{}` justification; avoid downcasts without bounds.
function abs(int x) internal pure returns (uint){
    require(x != type(int).min, "min");
    return uint(x >= 0 ? x : -x);
}
// Downcast:
require(v <= type(uint128).max, "truncate"); uint128 s = uint128(v);
```

### Hunting insight
- **Grep `unchecked` + `assembly` + casts (`uint8/uint128/int128`).** For each, prove bounds or flag.
- **Test `type(X).min/max, 0, 1, -1`.** Especially `abs`, `neg`, `quantize`, fee math, tick bitmaps.

---

## Appendix A: AI/Human Grep & Static-Analysis Pack

Run these before manual review (ripgrep). Any hit → go to linked VULN chapter.

```bash
# V01 reentrancy: external interaction before state write (manual confirm ordering)
rg -n "\.call\{value:|\.send\(|\.transfer\(|transferFrom|safeTransfer|mint\(|burn\(" --glob '*.sol'
rg -n "nonReentrant" --glob '*.sol'  # compare coverage vs external fns
# V02 access control
rg -n "function (deposit|withdraw|mint|burn|set[A-Z]|confirm|didTransfer|enable|setup|upgrade|pause|unpause|rescue|sweep)" --glob '*.sol'
rg -n "tx\.origin" --glob '*.sol'   # V02/V16: must be zero hits except timelock-EOA narrow case
# V03 proxy/upgrade
rg -n "initialize|initWallet|setup\(|upgradeTo|upgradeAndCall|_authorizeUpgrade|delegatecall|selfdestruct|suicide|__gap|reinitializer" --glob '*.sol'
rg -n "_disableInitializers" --glob '*.sol'  # must exist in every UUPS impl
# V04 oracle
rg -n "latestRoundData|getReserves|totalSupply\(\)|totalAssets\(\)|spot|twap|observe\(|getPrice|amountOutMin" --glob '*.sol'
rg -n "swapExactTokensForTokens\([^,]+,\s*0[,\)]" --glob '*.sol'  # zero slippage = Critical
# V05 flashloan
rg -n "flashLoan|flashloan|flashMint|flashSwap|isContract|extcodesize|nonContract" --glob '*.sol'
# V06 rounding/accounting
rg -n "/ [^*]*\*|\/ [0-9]|mulDiv|previewDeposit|previewMint|convertTo|exchangeRate|feeBps|totalStaked" --glob '*.sol'
# V07 ERC4626
rg -n "ERC4626|convertToShares|convertToAssets|decimalsOffset|totalAssets\(\)" --glob '*.sol'
# V08 signatures
rg -n "ecrecover|ECDSA|permit\(|PERMIT2|EIP712|_hashTypedData|castVote.*BySig|nonces\[|deadline|Multicall|ERC2771|_msgSender" --glob '*.sol'
# V09 MEV / V10 DoS
rg -n "for \(.*\.length|msg\.value|block\.timestamp|deadline|minOut|commit\(|reveal\(" --glob '*.sol'
# V11 governance
rg -n "vote\(|propose\(|queue\(|execute\(|quorum|COUNTING_MODE|slates\[|checkpoints" --glob '*.sol'
# V12 bridge
rg -n "bridgeToken|completeBridging|relayMessage|_nonblockingLzReceive|storeFailed|Teleporter|applyL1ToL2Alias|mint\(.*fee" --glob '*.sol'
# V13 tokens
rg -n "SafeERC20|safeTransfer|feeOnTransfer|rebase|decimals\(\)|onERC721Received|tokensToSend|tokensReceived" --glob '*.sol'
# V14 approvals
rg -n "\.approve\(|allowance\(|PermitSingle|permit2|increaseAllowance" --glob '*.sol'
# V15 centralization/timelock
rg -n "onlyOwner|DEFAULT_ADMIN|TimelockController|GnosisSafe|execTransactionFromModule|setup\(.*to,.*data" --glob '*.sol'
# V16 AA
rg -n "validateUserOp|EntryPoint|Paymaster|postOp|delegation|enforcer|caveats" --glob '*.sol'
# V17 ZK/crypto
rg -n "Verify\(|Transcript|challenge|Fiat|Shamir|merkle|MerkleProof|precompile|ecPairing|ecAdd|ecMul" --glob '*.sol'
# V18 ints
rg -n "unchecked|assembly|uint128\(|uint96\(|int128|abs\(" --glob '*.sol'
```

**Slither / Aderyn (CI must-pass):** `reentrancy-eth,reentrancy-no-eth,reentrancy-benign,controlled-delegatecall,suicidal,uninitialized-state,uninitialized-storage,arbitrary-send-eth,incorrect-equality,timestamp,tx-origin,too-many-digits,unchecked-transfer,erc20-interface,assembly,upgradeable,storage-layout` + OZ Upgrades `validateUpgrade` + `forge inspect storage-layout` diff.

---

## Appendix B: Fuzzing & Invariant Templates

Paste into Foundry (`test/Invariants.t.sol`). Use malicious token mocks.

```solidity
// 1. Solvency: sum owed <= held (catches Notional double-count, Balancer bleed, ERC4626 donation)
function invariant_solvable() public {
    assertGe(token.balanceOf(address(vault)), vault.totalOwed());
}
// 2. Share-price monotonic-ish: price cannot drop >X% in one tx without loss event (oracle/flashloan)
function invariant_sharePriceBounded() public {
    assertApproxEqRel(vault.convertToAssets(1e18), lastPrice, 0.05e18);
}
// 3. No zero-share deposit: any deposit > dust mints >0 shares even after donation
function invariant_noZeroShares(uint amt) public {
    token.transfer(address(vault), 1e18); // donation
    uint s = vault.previewDeposit(amt);
    if (amt > DUST) assertGt(s, 0);
}
// 4. Reentrancy: malicious ERC777 that reenters withdraw/bridge cannot increase attacker balance beyond deposit
// 5. Governance: totalVotes <= totalSupply; quorum cannot pass with 0 For; vote cannot be replayed (nonce increments)
// 6. Bridge symmetry: l1Locked - l2Minted == pendingMessages (no mint-out-of-thin-air)
// 7. Slippage: every swap path with 10x flashloan capital still respects minOut/TWAP deviation
// Handlers: deposit/withdraw/borrow/repay/vote/bridge/donate/upgrade — with 1-wei, max, zero, FoT, rebase, hook variants.
```

---

## Appendix C: Audit Checklist (Paste into Every Review)

- [ ] All `initialize/setup` guarded (`initializer`, `_disableInitializers`, no double-init, impl locked)? (V03)
- [ ] No `selfdestruct/delegatecall(msg.data)` in impl/library? (V03)
- [ ] Storage layout append-only + `__gap` + `forge inspect` diff clean? (V03)
- [ ] Every value-moving fn has correct ACL (`onlyX` or `msg.sender==to`)? No `tx.origin`? (V02)
- [ ] CEI + `nonReentrant` on ALL fns sharing state, not just `withdraw`? Tokens assumed hookable? (V01)
- [ ] No spot-price oracle; TWAP/Chainlink fresh (`answer>0`, `delay`, `round`, decimals, L2 sequencer)? No `0 minOut`? (V04)
- [ ] Flashloan-resistant (TWAP+cooldown+caps, not `isContract`)? (V05)
- [ ] Mul-before-div, fees UP / payouts DOWN, `MIN_AMT`, 1-wei tested, transitions clear old state? (V06)
- [ ] ERC4626: `decimalsOffset`, dead shares, internal `totalAssets`, donation-tested? (V07)
- [ ] Sigs: EIP-712 (chain+contract+nonce+deadline), low-S, no ERC2771+Multicall spoof, permit bound? (V08)
- [ ] Front-run safe (slippage+deadline/commit-reveal)? (V09)
- [ ] No unbounded loops, no push-to-arbitrary, paginated, rate-limiter per-user? (V10)
- [ ] Governance: snapshot+delay+quorum+no-replay+cannot-brick? (V11)
- [ ] Bridge: guarded hooks, symmetric mint, replay+destination checks, alias-safe, atomic completion? (V12)
- [ ] Tokens: `SafeERC20`, FoT/rebase/777/721/decimals-tested, no zero-transfer trust? (V13)
- [ ] Approvals minimal, decrementing, permit-bound, no infinite to aggregator? (V14)
- [ ] No instant-EOA admin on criticals; timelock+multisig; vesting EOA-bound; Safe setup clean? (V15)
- [ ] AA: `validateUserOp` sig+nonce+expiry, paymaster caps, delegation non-front-runnable? (V16)
- [ ] ZK: full-transcript Fiat-Shamir, precompile/truncation/merkle edge-tested? (V17)
- [ ] No unsafe `unchecked`/casts; `min/max/0/1` tested? (V18)

---

## Appendix D: Report-to-Pattern Index (Where Each Lesson Came From)

> Every bullet below is a real file in `reports-summery/` — spot-check any claim by opening it.

- **Reentrancy:** `15-lines-of-code-that-could-have-prevented-thedao`, `exploiting-uniswap-from-reentrancy-to-actual-profi`, `audits-2020-12-0x-exchange-v4`, `0xE400...-LOZF1YB (Euler×1inch)`, `linea-bridge-audit-1`, `audits-2023-01-rocket-pool-atlas-v1-2`, `audits-2023-08-lybra-finance`, `radiant-riz-audit`, `reentrancy-after-istanbul`, `final-results-blockchain-hacking-techniques-of-202*` (read-only, phantom fns).
- **Access control:** `28k-bounty-admin-brick-forced-revert`, `audits-2022-02-gamma (Hypervisor.deposit)`, `audits-2022-11-forta-delegated-staking (didTransferShares)`, `audits-2023-04-glif-filecoin-infinitypool`, `ion-protocol-audit (ReserveFeed)`, `immunefi-sense-finance-access-control`, `immunefi-alchemix-access-control`, `immunefi-enzyme-finance-missing-privilege-check`.
- **Proxy/upgrade:** `on-the-parity-wallet-multisig-hack`, `parity-wallet-hack-reloaded`, `immunefi-wormhole-uninitialized-proxy`, `-0xriptide-hackers-in-arbitrums-inbox`, `the-state-of-smart-contract-upgrades`, `the-transparent-proxy-pattern`, `testing-real-world-contract-upgrades`, `blog-high-risk-vulnerability-disclosed-to-ondo-fin`, `audits-2023-09-leequid-staking`, `zksync-layer-1-diff-audit`, `oeth-withdrawal-queue-audit`, `towards-frictionless-upgradeability`.
- **Oracle:** `immunefi-enzyme-finance-price-oracle-manipulation`, `how-openzeppelin-foiled-a-catastrophic-hack`, `origin-dollar-audit (C01 slippage)`, `compound-open-oracle`, `price-oracle-audit`, `aave-protocol-audit`, `audits-2020-05-balancer-finance (setController)`, `venus-protocol-oracles-audit`.
- **Flashloan/economic:** `immunefi-fei-protocol-flashloan`, `2023-02-07-bad-debt-attack-for-perpetual-protocol`, `flash-mintable-asset-backed-tokens`, `origin-dollar-audit`, `uma-audit-phase-3 (flash voting)`.
- **Rounding/accounting:** `immunefi-balancer-rounding-error`, `immunefi-dfx-finance-rounding-error`, `immunefi-notional-double-counting`, `immunefi-synthetix-logic-error`, `alpha-homora-v2 (rounding favor)`, `audits-2022-07-notional-finance (div0)`, `audits-2024-08-ramses-v3`, `bancor-compounding-rewards-audit`, `mcdex-mai-fund-protocol (abs(min))`.
- **ERC4626:** `a-novel-defense-against-erc4626-inflation-attacks`, `forta-staking-vault-audit`, `restakefi-audit (downscaling)`, `pods-finance-...-audit-1/2`.
- **Signatures:** `arbitrary-address-spoofing-vulnerability-erc2771co`, `audits-2022-08-1inch-exchange-aggregationrouter-v5 (malleability)`, `scopelift-flexible-voting-audit`, `ironblocks-onchain-firewall-audit`, `audits-2024-08-starbase`, `audits-2021-03-umbra`, `uniswapx-audit`, `eip-4337-...-incremental`.
- **MEV/front-run:** `audits-2021-03-pooltogether-pods`, `thegraph-timeline-aggregation-audit`, `audits-2023-05-tidal (back-run)`, `audits-2023-12-dram-stablecoin (mintCap front-run)`, `openzeppelin-security-analysis-uniswapx`, `uma-oval-audit`.
- **DoS/griefing:** `audits-2020-05-lien-protocol`, `instadapp-audit`, `audits-2023-12-web3-tickets`, `immunefi-charged-particles-griefing`, `post-learning-by-breaking-a-layerzero-case-study`, `linea-bridge-audit-1 (rate limiter)`, `scrollowner-and-rate-limiter-audit`, `audits-2021-03-dforce-lending-protocol-review (unbounded loop)`.
- **Governance:** `makerdao-critical-vulnerability`, `compound-case-study-how-compound-secures-its-proto`, `anvil-protocol-audit (quorum-with-zero)`, `audius-contracts-audit`, `uma-audit-phase-1/2/3/4/6`, `aave-governance-dao-audit`, `notional-v2-audit-governance-contracts`.
- **Bridge/cross-chain:** `linea-bridge-audit-1`, `scroll-batch-token-bridge-audit`, `avalanche-interchain-token-transfer-audit`, `ava-warp-messaging-audit`, `post-critical-finding-stealing-tokens-from-o3-brid`, `audits-2023-02-socket`, `across-v2/v3-incremental-audit`, `mantle-token-and-bridge-audit`, `mantle-v2-solidity-contracts-audit`, `zksync-weth-bridge-audit`.
- **Token quirks/approvals:** `blog-BB1-DFX (FoT)`, `audits-2019-11-fairmint (ERC777)`, `how-to-ensure-web3-users-are-safe-from-zero-transf`, `balancer-contracts-audit`, `barnbridge-smart-yield-bonds-audit`, `beefy-zap-audit-1 (Permit2)`, `immunefi-redacted-cartel-custom-approval`, `augur-core-v2-audit (CASH drain)`, `audits-2021-02-daofi`.
- **Centralization/timelock/multisig:** `15-billion-rugpull-vulnerability-in-convex-finance`, `bypassing-smart-contract-timelocks`, `backdooring-gnosis-safe-multisig-wallets`, `admin-accounts-and-multisigs`, `compound-iii-audit`, `audits-2020-11-paxos`.
- **AA/wallet:** `account-abstractions-impact-on-security-and-user-e`, `eip-4337-...-incremental`, `erc-4337-...-incremental`, `eth-foundation-account-abstraction-audit`, `audits-2024-06-metamask-delegator`, `audits-2024-08-metamask-delegation-framework`, `audits-2023-06-argent-account-multisig-for-starkne`, `particle-network-btc-smart-account-audit`.
- **ZK/crypto:** `linea-verifier-audit-1`, `linea-prover-audit`, `chainlight-uncovering-a-zk-evm-soundness-bug-in-zk`, `the-last-challenge-attack`, `merkledb-audit`, `blog-finding-a-critical-vulnerability-in-astar`, `okyEG4... (precompile impersonation)`, `RFNTSouIIlHVNmTNDThUVb1obIeN5c1LAiQuN9Ve-ok (Frontier truncation)`.
- **Ints:** `audits-2020-01-skale-token`, `forta-firewall-incremental-audit (quantize)`, `audits-2022-07-notional-finance`, `tierion-network-token-audit (decimals type)`.

---

## Final Note for Hunters

If you remember nothing else:

1. **Follow the money + the caller.** Who can move value, with whose permission, at what price, in what order, and after what upgrade?
2. **Assume composability is hostile.** Every token may hook, every oracle may move, every message may replay, every admin may be phished, every impl may be uninitialized.
3. **Write the exploit tx before the finding.** A finding without numbered exploit steps + profit math is a guess. This corpus rewards those who simulate the attacker.

*End of guideline — generated from full-corpus analysis of `reports-summery/` (807 files). Keep alongside code; re-run Appendix A on every PR.*

