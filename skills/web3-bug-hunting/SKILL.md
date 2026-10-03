---
name: web3-bug-bounty-hunting
description: Use this skill when auditing or hunting vulnerabilities in Web3 systems, including Solidity, Rust, Cosmos/Go, Solana, Cairo, Move, TypeScript, ZK circuits, bridges, governance, lending, stablecoins, AMMs, vaults, NFTs, presales, account abstraction, frontends, SDKs, deployment/lifecycle, and operational infrastructure. It operationalizes a merged historical incident corpus and external Immunefi/public-disclosure corpus into an evidence-led, PoC-first bug bounty workflow.
metadata:
  version: 1.0.0
  category: security
  tags:
    - web3
    - bug-bounty
    - smart-contract-audit
    - solidity
    - rust
    - cosmos
    - solana
    - zk
    - bridge
    - defi
    - governance
    - lending
    - stablecoin
    - nft
    - account-abstraction
    - frontend-security
---

# SKILL: Web3 Bug Bounty Hunting

Use this skill as a complete operating manual for hunting real Web3 vulnerabilities. It is designed for both human auditors and AI coding agents. The workflow is evidence-led: classify the failed invariant, run the smallest adversarial test, then build a full kill chain with reproducible state transition, attacker delta, victim loss, and remediation.

This skill merges and preserves the logic of two source corpora:

- **Source A — Historical incident corpus**: 1,624 incident reports, historical `T1–T24` taxonomy, deep PoC traces, and loss-frequency ranking.
- **Source B — External / Immunefi multi-language corpus**: public Immunefi, HackenProof, Code4rena, Sherlock, Cantina, GitHub disclosures, external `T01–T30` taxonomy, ZK, AA, SDK, Cosmos/Go, Rust, frontend, formal verification, and cross-language runtime lessons.

If a condensed table in this skill appears to conflict with a source section, the source section is authoritative. The original type numbers remain intentionally distinct: `T1` and `T01` are different source labels unless mapped explicitly in the crosswalk.

---

## 1. Skill Purpose

This skill teaches how to find, prove, and report vulnerabilities in real cryptocurrency systems before attackers do. It is not a theoretical checklist. It is a hunting system built from actual incidents.

Use it to:

1. Identify high-value attack surfaces quickly.
2. Prioritize by historical loss frequency and severity.
3. Run cheap local probes before building complex exploits.
4. Classify bugs by invariant failure, not project name.
5. Produce valid PoCs with concrete balance/state deltas.
6. Write high-quality bug bounty reports with root cause, impact, and fix.
7. Avoid false positives, unsafe live testing, and unsupported claims.

---

## 2. When to Use This Skill

Use this skill when asked to:

- Audit a Solidity, Rust, Go, Cosmos SDK, Solana, Cairo, Move, TypeScript, or ZK codebase.
- Review a DeFi protocol, AMM, vault, lending market, stablecoin, CDP, bridge, NFT marketplace, presale, vesting contract, staking system, governance system, reward farm, or account-abstraction EntryPoint.
- Hunt for bugs in smart contracts, chain runtime, SDKs, frontends, APIs, databases, deployment manifests, or operational configuration.
- Validate a suspected vulnerability with a PoC.
- Convert an incident report into reusable hunting logic.
- Build automated or AI-assisted security tests safely.
- Prepare a bug bounty submission.

Do not use this skill to:

- Attack production systems without authorization.
- Move production funds.
- Forge live proofs.
- Delete data.
- Drain wallets.
- Claim impact without reproducible evidence.

---

## 3. Mandatory Safety and Evidence Rules

### Safety Rule

Always use one or more of the following:

- Local forks.
- Unit tests.
- Read-only checks.
- Mocks.
- Explicitly authorized test environments.
- Shadow simulations or dry runs.

Never:

- Move production funds.
- Forge a live proof.
- Delete production data.
- Execute destructive transactions.
- Use compromised credentials.
- Submit live exploits.
- Claim impact without a reproducible state transition.

### Evidence Rule

A finding is real only when it shows:

1. Attacker capability.
2. Exact call sequence or message sequence.
3. Before/after state.
4. Victim loss or protocol invariant violation.
5. Repeatability or conditions for repeatability.
6. Fixed code or mitigation.
7. Residual attack surface, if any.

Reconstructed snippets are hypotheses until matched to the target commit and deployed bytecode.

### PoC Minimum Standard

Every PoC should show:

```text
Pre-state:
  victim balance / protocol state / proof state / role state

Attacker action:
  exact transaction, message, call, proof, or web request

Post-state:
  attacker gain, victim loss, invariant break, or forced revert
```

A revert alone is usually DoS, not theft. A theoretical path alone is not critical. Prove the state transition.

---

## 4. Golden Rules from the Corpus

Value flows out whenever a system:

1. Trusts a number the attacker can move.
2. Calls an address the attacker can pick.
3. Updates state after sending value.
4. Authenticates content but not context.
5. Loses information across type, serialization, chain, or runtime boundaries.
6. Treats a phase, queue, nonce, timestamp, or lifecycle transition as atomic when it is not.
7. Assumes one component, token, chain, adapter, or proof is equivalent to another.

### Master Golden Rule

A value, permission, proof, or state transition is unsafe whenever the code trusts a number, address, identity, context, message, or state transition that the caller can move, choose, replay, reinterpret, downgrade, omit, or leave unbound.

---

## 5. Universal Failure Model

Most real Web3 losses reduce to these primitives:

### 5.1 Movable Accounting

An attacker can donate, flash-borrow, rebase, reorder, duplicate, time-shift, or directly transfer an asset/reserve/share/accumulator/timestamp that the protocol treats as a stable fact.

Examples:

- Direct token donation to a vault.
- Flash-loan reserve manipulation.
- Rebasing token balance changes.
- Pending withdrawal counted in supply.
- Live `balanceOf(this)` treated as accounted deposits.

### 5.2 Unbound Execution

The caller chooses an external target, calldata, delegate implementation, callback data, adapter, bridge message, or retry path, and the protocol executes it without binding it to the intended caller/context.

Examples:

- Arbitrary `target.call(data)`.
- Confused-deputy router spending victim allowances.
- Delegatecall to user-chosen implementation.
- Flash-loan callback decoded from attacker data.

### 5.3 Unbound Identity

A signature, subaccount, forwarder, validator, signer, updater, proxy, implementation, chain, epoch, wallet, session, or Merkle root authenticates content but not the context in which it is used.

Examples:

- Signature replay across chains.
- Permit missing nonce/deadline/chain ID.
- ERC-2771 `_msgSender` spoofing.
- Batch order missing subaccount validation.
- Merkle root not bound to campaign or chain.

### 5.4 Type / Serialization Loss

Values silently change meaning across boundaries:

- `uint256 → uint32/uint64/uint96/uint128/uint160`
- `BigInt → Number`
- ABI offsets/flags/arrays
- Token units
- Q-format packing
- Storage keys
- Native/wrapped sentinels
- Decimal scaling

Examples:

- Chainlink 8 decimals used as 18 decimals.
- JavaScript `Number` truncating 256-bit keys.
- `uint160` downcast masking high bits.
- Frontier `msg.value` truncated to 128 bits.

### 5.5 Temporal / State-Machine Desynchronization

Phase boundaries, cooldowns, queues, nonces, maturity, expiry, batch ranges, migrations, withdrawals, claims, or transaction ordering are not atomic.

Examples:

- Claim before spent marker.
- Withdrawal request ID overlap.
- Drawing phase missing on batch function.
- Exact timestamp boundary errors.
- Cooldown bypass.
- Pending withdrawal still counted as redeemable.

### 5.6 External Composition Failure

One market, adapter, chain, token, market variant, proof, client, database, API, renderer, or signer is assumed equivalent to another.

Examples:

- Mainnet adapter reused on another chain.
- WETH/native ETH mismatch.
- Curve pool coin index mismatch.
- Token with fee-on-transfer assumed standard.
- LP token assumed equivalent to underlying.
- Frontend database content assumed safe.

### 5.7 Proof / Configuration Failure

Verifier math, trusted setup, oracle freshness/scale, role revocation, deployment initialization, or operational credentials are wrong even when the application code looks correct.

Examples:

- Groth16 `gamma == delta`.
- Missing Fiat–Shamir transcript absorb.
- Stale Chainlink round accepted.
- Old updater not revoked.
- Uninitialized implementation.
- Compromised Merkle-root signer.

---

## 6. Seven Questions for Every Candidate Vulnerability

For every candidate bug, answer:

1. **What is the protected asset or authorization?**
   - Funds, shares, roles, proofs, votes, collateral, rewards, configuration, or lifecycle authority.

2. **Which untrusted input can change its accounting or proof context?**
   - Amount, target, calldata, receiver, subaccount, signature, proof, root, timestamp, batch ID, oracle read, or direct transfer.

3. **Is the input bound to the same actor, chain, contract, asset, epoch, and call frame?**
   - If not, suspect replay, spoofing, or confused deputy.

4. **Can the input be moved or manipulated atomically?**
   - Donation, flash loan, sandwich, callback, batch, direct transfer, rebase, or self-transfer.

5. **Does an external call occur before effects, or does a view expose half-updated state?**
   - If yes, suspect reentrancy or read-only reentrancy.

6. **What exact balance delta, forged proof, permission change, or forced revert proves impact?**
   - If none, the finding is not yet actionable.

7. **What invariant failed, and what test should remain in CI forever?**
   - Every valid bug becomes a regression test.

---

## 7. Unified Priority and Execution Order

Use this order for a new codebase. The historical loss-frequency ranking and external-system priority map are complementary.

| Order | Hunt First | Why |
| --- | --- | --- |
| 1 | Historical T1: burn-from-pair + `sync()` / `skim()`; external T24: fee-on-transfer/rebase/reflection | Direct balance corruption and token-semantic assumptions are cheap to test and historically high-loss. |
| 2 | T2 / T02 arbitrary call and delegatecall | A deputy can spend other users’ allowances or take over proxy storage. |
| 3 | T3/T14 / T03 callbacks, flash-loan callbacks, execution-context confusion | Direct callback calls or nested AA frames can drain inventories or grief signed operations. |
| 4 | T4/T12 / T04 oracle spot, scale, stale, wrapper, median bugs | Flash loans/donations can turn a price read into immediate borrowing or minting power. |
| 5 | T5 / T01 donation, empty-market, share-price inflation | One-wei deposits, fresh markets, and direct transfers expose denominator/denominator-zero bugs. |
| 6 | T6 / T06 reentrancy, cross-function, read-only paths | Hooks and shared state can invalidate an otherwise correct entry function. |
| 7 | T7 / T07 reward, rate, claim, checkpoint accounting | Repeated actions, partial actions, and stale debt produce repeatable extraction. |
| 8 | T8/T16/T22 / T08/T15/T22 access, initialization, upgrade, role, lifecycle | Unprotected authority or stale updater/implementation keys bypass the whole application. |
| 9 | T9 / T09/T13 signatures, subaccounts, forwarders, AA, SDK coercion | Valid-looking authorization can be replayed, confused, or backed by a narrower key space. |
| 10 | T10 / T10/T30 governance, consensus, validator, runtime invariants | Flash-loanable quorum, double accounting, fee decorators, and cross-tree behavior affect the chain. |
| 11 | T11 / T11/T19 bridges, wrappers, adapters, deployment matrices | Alternate encodings, retry paths, native/wrapped assets, and ABI drift bypass canonical verification. |
| 12 | T13/T20 / T05/T14/T20 precision, units, serialization, resource boundaries | Casts, rounding, flags, arrays, gas units, and unbounded loops affect many integrations. |
| 13 | T15/T17/T23/T24 / T25–T27 sale, lending, peg, PCV state machines | These hold direct user value and expose route/liquidation/backing inconsistencies. |
| 14 | T18/T21 / T16/T20/T28 time, DoS, races, MEV | A freeze or predictable ordering can become a discount purchase or forced loss. |
| 15 | External T12/T21/T23/T29/T30 | ZK soundness, app-to-wallet compromise, verification gaps, AI safety, and cross-language runtime boundaries need a broader threat model. |

---

## 8. Historical Loss Statistics

Approximate distribution from the 1,624-report historical corpus:

| Rank | Family | Share | Signature Examples |
| --- | --- | --- | --- |
| 1 | T1 FoT burn + `sync()` AMM drain | ~22%, ~360 | CashCowCoin, FalconHeavy, NGP, WXC, RANT, UPENG, FIL314, LAURA, FIRE, AIDCToken |
| 2 | T4 Spot-oracle manipulation | ~18%, ~290 | UwuLend, Polter, BonqDAO, Inverse, Lodestar, WooFi, MahaLend, Cream/OUSD |
| 3 | T2 Arbitrary-call routers | ~12%, ~190 | SquidMulticall, Kame, Size Credit, ParaSwap, Sushi RouteProcessor2, LiFi, Socket |
| 4 | T7 Reward accounting | ~10%, ~165 | Penpie, Level, WIFCOIN, OSN, Bankroll, PancakeHunny, SafeDollar |
| 5 | T8 Access control | ~9%, ~150 | Parity ×2, Bybit Safe, Telcoin proxy, BBT mint, MARA mint, BTC24H claim |
| 6 | T6 Reentrancy | ~8%, ~130 | LendfMe, Cream/AMP, Euler-adjacent, dForce/Curve RO, Grim, Nomad-adjacent |
| 7 | T9 Signature/permit spoof | ~6%, ~95 | Exactly, AzukiDAO replay, FoomCash Groth16, Lixir permit, Odos 6492 |
| 8 | T5 Donation/share inflation | ~5%, ~85 | Sonne, Onyx, bZx iToken, Resupply, Thetanuts, Wise Lending, 0VIX |
| 9 | T18 Reflection/deliver | ~4%, ~60 | HODL, MCC, BEVO, QTN, XAI, HCT, Starlink |
| 10 | T3 Callback hijack | ~3%, ~50 | 0x8d2e, BaseCallback, CoW solver, Civfund V3 mint, Unverified6883 |
| 11–24 | Governance, bridge, NFT, proxy, etc. | remainder | Term Finance gov, Nomad zero-root, Ronin keys, TreasureDAO 0-qty |

Takeaway: if you only have one hour, hunt T1 → T5 first. They represent a large share of real losses and are often testable quickly with fork tests.

---

## 9. Historical T1–T24 ↔ External T01–T30 Crosswalk

This is a navigation aid. Many findings belong to more than one type.

| Historical Type | External Type(s) | Shared Invariant / Incident Families |
| --- | --- | --- |
| T1 FoT burn + `sync()` | T24, T01, T04, T17, T20, T28 | Pair balance, tax location, reserve sync, fee/reward conservation, MEV loops |
| T2 arbitrary external call | T02, T08, T22 | Caller-selected target/calldata, allowance deputy, delegate authority |
| T3 unauthenticated swap callback | T03, T20, T28 | Canonical pool/call-frame authentication and bot inventory |
| T4 spot-price oracle | T04, T18, T26, T27 | Manipulable reserves/rates used for mint, borrow, liquidation, PCV, peg actions |
| T5 donation/share inflation | T01, T05, T18, T24, T26, T27 | Live balance versus accounted assets, virtual supply/offset, empty markets |
| T6 reentrancy | T06, T03, T20 | CEI, token hooks, cross-function locks, read-only transient state |
| T7 reward accounting | T07, T18, T20 | `accPerShare` / reward debt, duplicate/partial actions, stale harvest |
| T8 access control | T08, T22, T23 | Public initializer/setter/mint/burn, roles, implementation and deployment state |
| T9 signature replay/permit | T09, T13, T15, T21 | Domain/nonce/deadline/caller/execution-frame binding and SDK type boundaries |
| T10 governance takeover | T10, T22, T28 | Snapshot/quorum/timelock/abandoned authority and flash-loanable voting power |
| T11 bridge forgery | T11, T19, T30 | Source proof, message uniqueness, fast paths, native/wrapped semantics |
| T12 oracle decimal/stale/wrapper/median | T04, T05, T18, T19 | Scale, freshness, source identity, wrapper/LP valuation, median legs |
| T13 precision/rounding/overflow | T05, T14, T20, T23 | Casts, division order, packed fields, directionality, boundary values |
| T14 flash callback hijack | T03, T20, T28 | Unauthenticated bot callback, attacker-controlled repayment/recipient |
| T15 NFT/presale/claim | T25, T16, T21, T24 | Zero quantity, duplicate IDs, phase/Merkle/receiver state machines |
| T16 proxy/upgrade/Diamond | T08, T15, T22, T23 | Implementation lifecycle, storage layout, facets, old authority |
| T17 self-liquidation/bad debt | T26, T01, T18, T27 | Same-actor liquidation, donated reserves, collateral/debt price-time mismatch |
| T18 reflection/deliver/rebase | T24, T01, T28 | Global rate changes, pair exclusion, snapshots, repeated skim loops |
| T19 ERC-404/DN-404/ERC-314 | T24, T15, T25 | Hybrid token/NFT conversion, fractional dust, mint/burn asymmetry |
| T20 unit/scale/math library | T05, T14, T19 | Token units, gas/token units, tick/sqrt/float libraries, constants |
| T21 DoS/griefing/time-warp | T20, T16, T28 | Bounded resources, phase boundaries, forced reverts, ordering, liveness |
| T22 key compromise/backdoor | T08, T21, T22 | Who can move whose funds, operational keys, signer policy, lifecycle |
| T23 lending/liquidation bypass | T26, T01, T05, T17, T27 | Health factor, stale/pending interest, direct-route bypass, solvency |
| T24 stablecoin/CDP/peg | T27, T18, T01, T26 | Backing valuation, transfer-vs-swap incentives, surplus/auction, peg games |
| — | T12 ZK proof soundness | Fiat–Shamir transcript, trusted setup, pairing/batch verification |
| — | T13 SDK/key derivation | JavaScript/TypeScript number coercion and entropy reduction |
| — | T14 ABI/hooks/serialization | Hook flags, offsets, arrays, batch variant validation |
| — | T21 web/application supply chain | API/database/markdown/browser/wallet trust graph |
| — | T23 formal verification gaps | Specification assumptions, mutation sensitivity, deployed-state proof |
| — | T29 AI-assisted hunting | Bounded local search, evidence gate, independent validation |
| — | T30 chain-runtime/cross-language | Rust/Go/Cosmos/Solana/Cairo/precompile/ABI semantics |

---

## 10. Unified 15-Minute First Pass

Run these searches over Solidity, Rust, Go, Cairo, Move, TypeScript, deployment manifests, and frontend code.

### 10.1 Authorization, Initialization, Lifecycle, and Value Movement

```bash
rg -n "function (initialize|init|set|add|remove|mint|burn|withdraw|claim|execute|delegate|transferFrom|swap|bridge|prove|verify|handleOps|upgrade|diamondCut)\b|pub fn (execute|validate|verify|handle)|ValidateBasic|onlyOwner|onlyRole|initializer" .
```

```bash
rg -n "\.call\{|\.call\(|\.delegatecall|functionCall|multicall|execTransaction|sendTransaction|target.*calldata|withdrawTo" .
```

### 10.2 Accounting, Prices, Rates, Shares, Reserves, Utilization, Proofs

```bash
rg -n "balanceOf\(address\(this\)\)|totalAssets|totalSupply|totalDeposits|totalBorrows|getReserves|slot0|getAmountsOut|pricePerShare|getRate|exchangeRate|utilization|rewardPerToken|accPerShare|convertToAssets|effectiveSupply|latestAnswer|latestRoundData|median" .
```

### 10.3 Callbacks, Hooks, Messages, Queues, Signatures, Account Abstraction

```bash
rg -n "uniswapV3SwapCallback|pancakeCall|onFlashLoan|tokensReceived|tokensToSend|onERC721Received|onERC1155|handleOps|executeUserOp|ecrecover|permit\(|_msgSender|ERC2771|Subaccount|block\.timestamp|startTime|maturity|cooldown|withdraw.*request|batchId|requestId|finalize" .
```

### 10.4 Type, Unit, Storage, ABI, Resource Boundaries

```bash
rg -n "unchecked|uint(8|16|32|64|96|120|128|160)\(|/=|/ *1e[0-9]+|decimals|Number\(|bytesToNumber|toNumber|keccak256\(|abi\.encodePacked|mapping\(|struct |slot|sload|sstore|for \(" .
```

### 10.5 Web, Database, Deployment, Chain, Operational Boundaries

```bash
rg -n "dangerouslySetInnerHTML|innerHTML|remark|markdown|sanitize|javascript:|window\.ethereum|injectedWeb3|jwt|Authorization|Grafana|Hasura|Crowdin|API_KEY|SECRET|precompile|native|WETH|ETH_ADDRESS|0xEeee|module account|chainid|CREATE2|CREATE3" --glob '*.{sol,rs,go,cairo,move,ts,tsx,js,py,json,yml,yaml,md}' .
```

---

## 11. Rapid Triage Questions

Run these five questions on every codebase first.

### 11.1 AMM-Touching Token Logic? — T1/T18/T19

Search:

```bash
grep -rn "sync()\|skim()\|burn(.*pair\|pair.*burn\|_burn(.*pair" --include=*.sol
grep -rn "function sell\|function buy\|_transfer.*tax\|deliver(" --include=*.sol
```

Ask:

- Does any path burn from the pair?
- Does any path transfer from the pair to dead?
- Does `sync()` or `skim()` run after balance changes?
- Does the pair receive reflections or rebase gains?

Cheap PoC:

```text
sell(1) → pair.skim()
```

If skim extracts value, accounting is desynced.

### 11.2 Arbitrary Calls? — T2

Search:

```bash
grep -rn "\.call{\|functionCallWithValue\|delegatecall" --include=*.sol
```

Ask:

- Can `target` and `calldata` both be caller-chosen?
- Does the contract hold user allowances?
- Can `transferFrom(victim, attacker, amount)` be reached?
- Is delegatecall implementation caller-selected?

If yes, stop: likely critical.

### 11.3 Callbacks Authenticated? — T3/T14

Search:

```bash
grep -rn "uniswapV3SwapCallback\|pancakeCall\|onFlashLoan\|tokensReceived\|onERC721Received" --include=*.sol
```

Ask:

- Does the callback verify `msg.sender` is a canonical pool?
- Is the pool from a factory or stored registry?
- Are amounts/recipients decoded from attacker-controlled `data`?
- Can the callback be called directly?

If not authenticated, likely drainable.

### 11.4 Price Source? — T4/T12

Search:

```bash
grep -rn "getReserves\|slot0\|getAmountsOut\|balanceOf(pair\|totalHoldings\|pricePerShare\|getRate\|exchangeRate" --include=*.sol
```

Ask:

- Is the price used for mint/borrow/reward/liquidation?
- Can the source move in one tx?
- Is any median leg spot?
- Are decimals/staleness/wrappers checked?

If yes, manipulate it.

### 11.5 Share Math on Empty/Near-Empty Vault? — T5

Search:

```bash
grep -rn "totalSupply() == 0\|totalSupply == 0\|exchangeRate\|convertToAssets\|previewRedeem" --include=*.sol
```

PoC:

```text
deposit 1 wei → donate/rebase → deposit 1 wei → redeem both
```

Profit = bug.

---

## 12. Immediate Local Probes

Run these cheap probes early.

1. **Donation / empty market**

   ```text
   deposit(1)
   direct donation / selfdestruct / rebase
   deposit(1)
   redeem
   ```

2. **Burn/sync AMM probe**

   ```text
   sell(1)
   pair.skim()
   repeated sell/sync loop
   ```

3. **Duplicate claim / self-transfer**

   ```text
   claim();
   claim();
   claim([id,id]);
   transfer(me, me, 1);
   register fresh address;
   ```

4. **Direct callback**

   ```text
   uniswapV3SwapCallback(...)
   pancakeCall(...)
   onFlashLoan(...)
   arbitrary target/calldata with local victim allowance
   ```

5. **Oracle skew**

   ```text
   flash-skew reserve/spot price 10×
   call every mint/borrow/redeem/liquidation/PCV sink
   unwind and repay
   ```

6. **Boundary inputs**

   ```text
   0
   1
   type maximum
   2/6/8/18 decimal tokens
   exact phase boundaries
   timestamp == startTime
   alternate chain
   duplicate ID
   ```

7. **Proxy/lifecycle**

   ```text
   deploy proxy
   initialize every implementation/beacon
   upgrade
   read back every storage slot
   revoke old updater/forwarder roles on every chain
   ```

8. **ZK mutation**

   ```text
   mutate one public input
   mutate absorbed commitment
   mutate batch member
   mutate setup constant
   invalid proof must fail
   ```

9. **Web-chain mock**

   ```text
   local database → markdown → DOM → wallet-mock
   no live wallet or production data
   ```

10. **Empty market / new adapter / new chain**

   ```text
   test independently
   mainnet works is not universal proof
   ```

---

## 13. Universal PoC Battery Index

Use these batteries alongside source-specific code.

### Battery A — Donation / Empty Market

Variants:

- Direct transfer.
- `selfdestruct`.
- Rebase.
- Fee-on-transfer.
- Near-zero supply.
- Virtual offset.
- Pending withdrawal.

Pattern:

```solidity
vault.deposit(1 wei);
token.transfer(address(vault), 1e24);
vault.deposit(1 wei);
vault.redeemAll();
```

Profit means share price is manipulable.

### Battery B — Duplicate / Replay

Variants:

- Duplicate IDs/arrays.
- Stateless claims.
- Signature replay.
- Permit replay.
- ERC-4337 nested execution.
- Merkle root replay.

Pattern:

```solidity
claim();
claim();
claim([id, id]);
```

Second payout > 0 means bug.

### Battery C — Arbitrary Call

Plant a local victim allowance, then try:

- `transferFrom`
- `approve`
- `delegatecall`
- `upgradeTo`
- `registerFee`
- `execute`
- typed router variants

Pattern:

```solidity
run([{
  target: token,
  data: transferFrom(victim, attacker, amount)
}]);
```

Success means critical deputy drain.

### Battery D — Callback / Context

Variants:

- Direct pool callback.
- Malicious clone.
- Altered callback data.
- Double-entry token.
- Nested AA call.
- Read-only reentrancy.

Pattern:

```solidity
victim.uniswapV3SwapCallback(1e18, 0, attackerData);
```

Any token movement means critical.

### Battery E — Oracle Skew

Variants:

- 10× swap/donation.
- One-block and two-block TWAP.
- Stale feed.
- Wrapper/LP.
- Decimals 6/8/18.
- Alternate oracle legs.

Pattern:

```text
skew → mint/borrow/claim → unwind → compare delta
```

Behavior change means oracle is transactional.

### Battery F — Arithmetic / Type

Variants:

- Narrow casts.
- `unchecked`.
- Assembly.
- Q-format packing.
- Division-first math.
- Max values.
- Zero-rounding.
- Phase boundaries.

Inputs:

```text
0, 1, 2, type(uintN).max, type(uintN).max - 1
```

### Battery G — Go / Cosmos

Test every:

- Message.
- Order.
- Batch variant.
- Foreign subaccount.
- Nested order.
- Module-account transfer.
- Fee/refund.
- Migration path.

Invariant:

```text
sender == owner of every nested object
```

### Battery H — ZK

Mutate:

- Public input.
- Absorbed commitment.
- Batch membership.
- Setup constants.
- Transcript order.
- Circuit hash.

Invariant:

```text
invalid proofs fail; batch verification equals individual verification
```

### Battery I — Lifecycle

Test:

- Implementation initialization.
- Clone initialization.
- Proxy initialization.
- Beacon initialization.
- Upgrade/readback.
- Old-role revocation.
- Chain-specific CREATE2/CREATE3.
- Rollback.

Invariant:

```text
old authority dead everywhere
```

### Battery J — Web-Chain

Mock:

- Database.
- API.
- Markdown.
- DOM.
- Wallet.

Prove injection reaches harmless marker, then map signer/transfer consequence.

---

## 14. Part I — Historical 1,624-Incident Playbook, T1–T24

This section preserves the historical taxonomy. Each type includes definition, root cause, hunting method, exploitation model, fix direction, and unique insight.

---

### T1. Fee-on-Transfer Burn + `sync()` AMM-Reserve Drain

**Definition**

A token or helper removes the token’s own LP inventory — burn from pair, transfer pair → dead, pool-side tax — then calls `pair.sync()`, rewriting reserves to a one-sided collapse the attacker arbitrages in a loop.

**Root Cause**

Uniswap-V2 `sync()` sets reserves equal to balances with no invariant check. Any path that moves token out of the pair without a matching swap payout, then syncs, donates the pair inventory to `k`.

**Vulnerable Pattern**

```solidity
function sell(uint256 amountIn, uint256, uint256) external {
    token.transferFrom(msg.sender, address(this), amountIn);
    token.transfer(pair, amountAfterTax);
    pair.swap(0, wbnbOut, address(router), "");
    token.burnFromPair(pair, DEAD, amountAfterTax);
    pair.sync();
    payable(msg.sender).transfer(wbnbOut);
}
```

**Fixed Pattern**

```solidity
function sell(uint256 amountIn, uint256, uint256) external {
    token.transferFrom(msg.sender, address(this), amountIn);
    uint256 burn = amountIn * taxBps / 10_000;
    token.burn(address(this), burn);
    token.transfer(pair, amountIn - burn);
    pair.swap(0, wbnbOut, msg.sender, "");
}
```

No burn from pair after swap, no `sync()`.

**How to Find**

```bash
rg -n "sync\(\)|skim\(\)"
rg -n "burn"
```

For each burn, ask:

- Can burn source be the pair?
- Is there a `from == pair` branch?
- Is there arbitrary `from`?
- Does `sync()` or `skim()` follow?

Variants:

- Sell-path burn.
- Buy-tax charged to pair.
- Self-transfer burn.
- Owner `burn(pair)`.
- `burnLpToken()`.
- Dividend distribution from pair.
- Zero-amount-triggered burn.

**Kill Chain**

1. Flash-loan WBNB.
2. Buy or hold token.
3. Loop `sell()` N times.
4. Each loop swaps WBNB out, burns token from pair, syncs.
5. Repay flash loan.
6. Keep WBNB delta.

**Unique Insight**

Auditors check tax math, not tax location. The question is not “is the fee 5%?” but “whose balance does the fee leave from, and does `sync()` run after?” Any burn-from-pair plus sync, even 1 wei per tx, can become a full drain when looped.

---

### T2. Arbitrary External Call / Confused-Deputy Routers

**Definition**

A contract users approve — router, multicall, settler, zapper, paymaster — executes caller-chosen `target` plus caller-chosen `calldata`, letting anyone spend other users’ approvals via `transferFrom(victim, attacker, amount)`.

**Root Cause**

ERC-20 authorization is by `msg.sender`. The deputy is the approved spender, so the token cannot distinguish router acting for victim from attacker steering the router.

**Vulnerable Pattern**

```solidity
function run(Call[] calldata calls) external payable {
    for (uint256 i; i < calls.length; i++) {
        (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
        require(ok);
    }
}
```

**Fixed Pattern**

```solidity
mapping(address => bool) public allowedTarget;
mapping(bytes4 => bool) public allowedSelector;

function run(Call[] calldata calls) external payable {
    for (uint256 i; i < calls.length; i++) {
        require(allowedTarget[calls[i].target], "target");
        require(allowedSelector[bytes4(calls[i].callData)], "selector");
        require(_from(calls[i].callData) == msg.sender, "only-self");
        (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
        require(ok);
    }
}
```

**How to Find**

```bash
rg -n "\.call\{|\.call\(|functionCall|delegatecall"
```

Trace:

- Can untrusted caller control target?
- Can untrusted caller control calldata?
- Does contract hold allowances?
- Can `transferFrom`, `approve`, `permit`, `upgradeTo`, `execute` be reached?

**Kill Chain**

```text
run([{
  target: USDC,
  data: transferFrom(victim, attacker, victimBalance)
}])
```

Repeat for every victim/token that approved the deputy.

**Unique Insight**

The audit question is not “is the call result checked?” but “whose allowance is being spent, and did that person authorize this call?” Permit2-style per-tx, exact-amount, short-deadline approvals are the structural fix.

---

### T3. Unauthenticated Swap Callbacks

**Definition**

`uniswapV3SwapCallback`, `pancakeCall`, `swapCallback`, or similar executes state changes or token pulls without verifying `msg.sender` is a legitimate pool.

**Root Cause**

Callbacks authenticate only by caller address. If contract never checks `msg.sender == canonical pool`, anyone can invoke the callback directly.

**Vulnerable Pattern**

```solidity
function uniswapV3SwapCallback(int256 amount0, int256 amount1, bytes calldata) external {
    if (amount0 > 0) USDC.transferFrom(msg.sender, attackerVault, uint256(amount0));
}
```

**Fixed Pattern**

```solidity
function uniswapV3SwapCallback(int256 a0, int256 a1, bytes calldata data) external {
    (address tokenIn, address tokenOut, uint24 fee) = abi.decode(data, (address, address, uint24));
    require(msg.sender == IUniswapV3Factory(factory).getPool(tokenIn, tokenOut, fee), "not-pool");
}
```

**How to Find**

```bash
rg -n "Callback|pancakeCall"
```

Check first lines. If no caller authentication, stop reading: likely bug.

**Kill Chain**

Call callback directly with crafted deltas. Contract pulls tokens from its own balance/allowance to attacker destination.

**Unique Insight**

MEV bots are rich victims: inventory + approvals + copy-pasted callbacks. Delete business logic mentally and read first five lines. Missing caller authentication is the bug.

---

### T4. Spot-Price Oracle Manipulation

**Definition**

Mint, borrow, reward, liquidate, buyback, or claim amounts are computed from a price the attacker can move inside the same transaction.

**Root Cause**

Spot state is not a price; it is an offer. Reading it as a price lets flash loans or donations set exchange rates, transact at false rates, then unwind.

**Vulnerable Pattern**

```solidity
function collateralValue(address user) public view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    uint256 price = r1 * 1e18 / r0;
    return collateral[user] * price / 1e18;
}
```

**Fixed Pattern**

```solidity
uint256 price = IOracle(chainlinkOrTWAP).getPrice(token);
require(block.timestamp - updatedAt < MAX_STALENESS);
require(price > 0 && deviationBps < MAX_DEV);
```

**How to Find**

List every price read:

- `getReserves`
- `slot0`
- `getAmountsOut`
- `balanceOf(pair)`
- `get_virtual_price`
- `totalHoldings`
- `getRate`
- `exchangeRate`

Trace to state-changing sink:

- mint
- borrow
- redeem
- reward
- liquidation
- presale price
- buyback

**Kill Chain**

```text
flash loan → skew pool → borrow/mint/claim at false price → unwind → repay → keep profit
```

**Unique Insight**

Median-of-N oracles fails if any leg is spot. “We use Chainlink” fails on decimals/staleness. Always test with 10× skew fork test.

---

### T5. Donation / Share-Price Inflation

**Definition**

Attacker inflates `exchangeRate = cash / supply` or `convertToAssets` by donating to a near-empty market/vault, then deposits tiny value for huge shares, then redeems.

**Root Cause**

Share math divides by supply that can be near zero while numerator is attacker-controlled.

**Vulnerable Pattern**

```solidity
function mint(uint256 mintAmount) external returns (uint256 shares) {
    uint256 exRate = (totalCash + totalBorrows - reserves) / totalSupply;
    shares = mintAmount / exRate;
    totalSupply += shares;
}
```

**Fixed Pattern**

```solidity
uint256 VIRTUAL_SHARES = 1e6;

shares = mintAmount * (totalSupply + VIRTUAL_SHARES)
        / (totalCash + VIRTUAL_SHARES);
```

Or burn minimum liquidity to address(0).

**How to Find**

```bash
rg -n "totalSupply\(\) == 0|exchangeRate|convertToAssets|previewDeposit"
```

Run battery:

```text
deposit 1 wei
donate 1e24
deposit 1 wei
redeem all
```

**Unique Insight**

“We already have deposits” is false. Near-empty markets inside big protocols are still empty markets. Audit every market, not just the protocol.

---

### T6. Reentrancy — Classic, Hooks, Read-Only, Cross-Function

**Definition**

State is read or value leaves before effects are committed, and an external call re-enters.

**Root Cause**

CEI violated, or a view exposes half-updated state, or token hooks hand control to attacker mid-function.

**Vulnerable Pattern**

```solidity
function withdraw(uint256 amount) external {
    uint256 bal = balanceOf(msg.sender);
    IERC777(token).send(msg.sender, amount, "");
    balances[msg.sender] = bal - amount;
}
```

**Fixed Pattern**

```solidity
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;
    total -= amount;
    IERC20(token).safeTransfer(msg.sender, amount);
}
```

**How to Find**

```bash
rg -n "\.send\(|\.call\{value|safeTransfer|\.transfer\("
```

Ask:

- Is all state updated before external call?
- Are reward debts, share totals, oracle snapshots updated?
- Can a view read mid-flight state?
- Are ERC777/721/1155/404/FoT tokens involved?

**Kill Chain**

Deploy malicious token or NFT receiver that re-enters `withdraw`, `claim`, `borrow`, or price read.

**Unique Insight**

`nonReentrant` on entry function is not enough. Read-only reentrancy exploits functions never “entered.” Guard the whole economic state.

---

### T7. Reward-Accounting Bugs

**Definition**

Rewards paid from stale checkpoints, un-updated debt on transfer/unstake, repeatable stateless claims, or self-referential farming.

**Root Cause**

Reward math has three moving parts:

```text
user amount
global accumulator
user debt
```

Any path changing one without syncing all three mints free rewards.

**Vulnerable Pattern**

```solidity
function claimEarned() external {
    uint256 reward = staked[msg.sender] * accPerShare / 1e18 - rewardDebt[msg.sender];
    token.transfer(msg.sender, reward);
}
```

**Fixed Pattern**

```solidity
function claimEarned() external updatePool {
    uint256 reward = staked[msg.sender] * accPerShare / 1e18 - rewardDebt[msg.sender];
    rewardDebt[msg.sender] = staked[msg.sender] * accPerShare / 1e18;
    require(block.timestamp >= lastClaim[msg.sender] + EPOCH, "gated");
    lastClaim[msg.sender] = block.timestamp;
    token.safeTransfer(msg.sender, reward);
}
```

**How to Find**

```bash
rg -n "rewardDebt|accPerShare|lastPayout|claim\("
```

Verify every mutation path updates debt:

- deposit
- withdraw
- transfer
- emergencyWithdraw
- migrate
- self-transfer

**Cheap Probe**

```text
claim(); claim();
transfer(me, me, 1); claim();
register twice;
self-refer;
```

**Unique Insight**

Each function may look fine; the combination breaks. Fuzz action pairs, not single functions. Self-transfer is the cheapest universal probe.

---

### T8. Broken Access Control

**Definition**

A privileged function is callable by anyone: `initialize`, `mint`, `burn`, `setOwner`, `setRouter`, `setRegistry`, `withdrawFees`, `upgrade`.

**Root Cause**

Missing `onlyOwner`, `onlyRole`, initializer guard, or uninitialized implementation.

**Vulnerable Pattern**

```solidity
function initWallet(address[] _owners, uint _required, uint _daylimit) public {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
}
```

**Fixed Pattern**

```solidity
bool private _initialized;

modifier initializer() {
    require(!_initialized, "init");
    _;
    _initialized = true;
}

function initWallet(address[] o, uint r, uint d) external initializer {}
```

Also:

```solidity
constructor() {
    _disableInitializers();
}
```

**How to Find**

```bash
rg -n "function init|initialize\(|function mint|function burn|function set.*Owner|function set.*Router|function set.*Registry|onlyOwner"
```

Build authorization matrix:

| Function | Intended Caller | Actual Modifier | Privileged? |
| --- | --- | --- | --- |

**Kill Chain**

```text
initialize()
become owner
mint / upgrade / withdraw
```

**Unique Insight**

Access-control bugs are boring but common. Every fork, factory clone, and redeployment reintroduces them.

---

### T9. Signature Replay / Permit / EIP-712 / ERC-6492 / ERC-2771 Spoofing

**Definition**

Signatures usable twice, on another chain/contract, by another relayer, or with attacker-rewritten parameters; `_msgSender()` spoofed via forwarder/multicall.

**Root Cause**

Signed message omits nonce/expiry/chain ID/contract/caller binding; `ecrecover` returns zero address; ERC-2771 suffix attacker-controlled; ERC-6492 allows side effects.

**Vulnerable Pattern**

```solidity
function claim(bytes calldata sig) external {
    address signer = ecrecover(hash, v, r, s);
    require(signer == admin, "bad");
    _mint(msg.sender, amount);
}
```

**Fixed Pattern**

```solidity
bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
    TYPEHASH,
    msg.sender,
    amount,
    nonces[msg.sender]++,
    block.chainid,
    address(this),
    expiry
)));

require(block.timestamp <= expiry, "exp");
address signer = ECDSA.recover(digest, sig);
require(signer == admin && signer != address(0), "bad");
```

**How to Find**

```bash
rg -n "ecrecover|isValidSig|permit\(|_msgSender\(\)|ERC2771|6492|allowSideEffects"
```

Check signed fields:

- nonce
- expiry
- chain ID
- contract address
- caller
- target
- calldata
- value
- execution frame

**Kill Chain**

Capture valid signature, replay:

- twice
- from another address
- on another chain
- against another contract

**Unique Insight**

The deadliest variant is parameter confusion, not missing nonce. Whenever `msg.sender` is derived, ask: “who chose these bytes?”

---

### T10. Governance Takeover

**Definition**

Attacker gains proposal/voting/upgrade power via flash-loaned votes, abandoned governor, thin quorum, or self-answered referendum.

**Root Cause**

Voting power checkpointed too late, quorum tiny, timelock zero, or abandoned governance still wired to funds.

**How to Find**

```bash
rg -n "propose\(|queue\(|execute\(|votingPower|getVotes|quorum"
```

Ask:

- Snapshot at proposal or vote time?
- Quorum percent of total supply?
- Timelock delay?
- Can governor call treasury?
- Is governance abandoned but live?

**Kill Chain**

```text
flash borrow governance token
delegate
propose
vote
queue
execute
repay
```

**Unique Insight**

Abandoned governance is live governance. Trace outgoing calls from every governor/timelock/Safe module.

---

### T11. Bridge / Cross-Chain Message Forgery

**Definition**

Mint/release/unlock on destination chain without real lock/burn on source.

**Root Cause**

Destination trusts message whose authenticity it never verifies: self-signed validator set, permissionless relayer entrypoint, express path skipping verification.

**How to Find**

```bash
rg -n "lzReceive|retryMessageIn|expressExecute|process\(|mint.*message|nonblockingLzReceive"
```

Walk backward from mint/release to verification.

Ask:

- Who can call entrypoint?
- What proves source state?
- Is message unique?
- Is fast path escrow or mint?
- Is native/wrapped representation consistent?

**Kill Chain**

Craft message with fake amount/recipient and call destination entrypoint directly.

**Unique Insight**

Test bridges backwards: start at mint/release and walk toward verification.

---

### T12. Oracle Decimal / Stale / Wrapper / Median Bugs

**Definition**

Correct source, wrong interpretation: decimals mis-scaled, stale price accepted, wrapper/LP treated as underlying, manipulable median leg.

**Vulnerable Pattern**

```solidity
uint256 price = oracle.latestAnswer(); // 8 decimals used as 18
uint256 value = collateral * price / 1e18;
```

**Fixed Pattern**

```solidity
(, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
require(block.timestamp - updatedAt <= MAX_STALENESS && answer > 0);
uint256 price = uint256(answer) * 1e18 / (10 ** oracle.decimals());
```

**How to Find**

```bash
rg -n "latestAnswer|latestRoundData|decimals\(\)|1e8|1e18"
```

Check:

- Decimal normalization.
- Staleness.
- Wrapper/LP pricing.
- Median legs.
- Zero/negative answers.

**Unique Insight**

Decimal bugs survive audits because reviewers assume known feeds. Write normalization as tested helper per feed.

---

### T13. Precision / Rounding / Overflow / Underflow

**Definition**

Value leaks or bricks through integer division order, truncation casts, share-rounding asymmetry, or overflow/underflow.

**Root Cause**

`a/b*c` instead of `a*c/b`, narrow casts, first-depositor rounding, fee-on-zero-supply, pre-0.8 overflow.

**How to Find**

```bash
rg -n "unchecked|uint128|uint64|uint32|uint16|/=\|/ 1e"
```

Test:

- oversized counts
- dust values
- boundary IDs
- max values
- zero values
- division before multiplication

**Unique Insight**

Rounding bugs are directional. Attacker-profitable rounding sits where attacker chooses transaction size. Round against caller on user-chosen paths.

---

### T14. Flash-Loan Callback Hijack & MEV-Bot Self-Drain

**Definition**

Contract’s own flash-loan/callback entrypoint is callable by anyone and moves contract funds/approvals to attacker-chosen destinations.

**Root Cause**

Callback authenticated by nothing; recipient/amount taken from calldata instead of storage.

**Vulnerable Pattern**

```solidity
function pancakeCall(address sender, uint amount0, uint amount1, bytes calldata data) external {
    (address token, address to, uint amount) = abi.decode(data, (address, address, uint));
    IERC20(token).transfer(to, amount);
}
```

**Fixed Pattern**

```solidity
function pancakeCall(address, uint, uint, bytes calldata data) external {
    require(msg.sender == PANCAKE_PAIR, "only-pair");
}
```

**How to Find**

```bash
rg -n "FlashLoan|callFunction|pancakeCall|executeOperation|assetTo"
```

Ask:

- Are sender/recipient/amount decoded from `data`?
- Were they stored before loan?
- Can callback be called directly?

**Unique Insight**

Bots are unaudited protocols with treasuries. Public callback on private-key-operated contract is a live bounty.

---

### T15. NFT / Marketplace / Presale / Airdrop / Vesting Logic

**Definition**

NFTs bought for zero quantity, free-minted via broken sale math, rental/escrow double-spent, presale priced below AMM, vesting released early, airdrops farmed by sybils.

**Root Cause**

Sale/claim math trusts caller-supplied counts/addresses/prices.

**Vulnerable Pattern**

```solidity
function buy(uint256 tokenId, uint256 qty) external payable {
    uint256 cost = pricePerItem[tokenId] * qty;
    require(msg.value >= cost);
    nft.transferFrom(seller, msg.sender, tokenId);
}
```

If `qty == 0`, cost is zero but NFT may still move.

**Fixed Pattern**

```solidity
require(qty > 0 && qty <= MAX_PER_TX, "qty");
require(msg.value == pricePerItem[tokenId] * qty, "exact");
```

**How to Find**

```bash
rg -n "quantity|qty|buy\(|mint\(|claim\(|presale|merkleRoot|release\("
```

Test:

- 0 quantity
- 1 quantity
- max + 1
- double claim
- duplicate ID
- self-funded purchase
- presale vs AMM price
- exact timestamp boundaries

**Unique Insight**

Presale/airdrop code is written last and audited least, yet holds unconditional value. Audit sale before staking.

---

### T16. Proxy / Upgrade / Diamond Re-Initialization

**Definition**

Implementation, clone, or Diamond facet re-initialized or upgraded by attacker.

**Root Cause**

Initializer missing, implementation left uninitialized, `upgradeTo`/`diamondCut` exposed, storage collision.

**Fixed Pattern**

```solidity
constructor() {
    _disableInitializers();
}

function initialize(address o) external initializer {}

function upgradeTo(address i) external onlyOwner {}
```

**How to Find**

```bash
rg -n "initialize\(|upgradeTo|diamondCut|delegatecall"
```

Check:

- Is implementation initialized/disabled?
- Is clone initialize front-runnable?
- Is upgrade authorized on both proxy and implementation?
- Are storage gaps correct?

**Unique Insight**

The implementation contract is a contract too. If it has open `initialize`, the proxy system may already be owned.

---

### T17. Self-Liquidation / Bad Debt / Donate-to-Reserves

**Definition**

Attacker engineers own or victim liquidation/borrow to extract reserves, donate to inflate accounting, or leave bad debt socialized.

**Root Cause**

Liquidator and borrower can be same actor, or donations count as profit.

**How to Find**

```bash
rg -n "liquidate|donateToReserves|selfLiquidat|restructureBadDebt"
```

Test:

- liquidator == borrower
- same-block donation + borrow
- donate then self-liquidate
- reserve accounting after donation

**Unique Insight**

Liquidation is adversarial, but tests rarely model liquidator and borrower cooperating. Add collusion test.

---

### T18. Reflection / Deliver / Dividend / Rebase Loops

**Definition**

Elastic/reflect tokens where `deliver()`, burn, `skim`, self-transfer, or rebase changes global rate without moving real value, minting phantom balance AMM pays out.

**Root Cause**

Reflection math breaks when global denominator shrinks while pool balance is not excluded.

**How to Find**

```bash
rg -n "deliver\(|_rTotal|reflection|rebase\(|index =|distribute.*[Dd]ividend"
```

Ask:

- Can anyone call deliver/burn/rebase?
- Is pair excluded?
- Do dividend checkpoints update on transfer/mint/burn?
- Can `skim()` extract value after rate change?

**Cheap Probe**

```text
deliver(1) or self-transfer 1 wei
pair.skim()
```

If anything comes out, bug.

**Unique Insight**

If token has global-rate variable and pair is not excluded, assume T18 until fork test proves otherwise.

---

### T19. ERC-404 / DN-404 / ERC-314 Asymmetries

**Definition**

Hybrid NFT↔FT standards where mint/burn/transfer paths disagree on amounts, exemptions, or timing.

**Root Cause**

Two accounting systems updated in different functions with different rounding/exemptions; AMM `sync`/`skim` interacts with only one.

**How to Find**

```bash
rg -n "404|ERC314|_mintERC721|_burnERC721|minted.*NFT|swap.*314"
```

Test:

- fractional transfer dust
- flash-mint NFTs then claim airdrop then burn
- self-transfer inflation
- vesting proxy re-init
- sell-triggered pool burn
- buy-mint skew

**Unique Insight**

The exotic conversion path is where invariant breaks. Fuzz every conversion edge with 1 wei and max values.

---

### T20. Unit / Scale / Math-Library Bugs

**Definition**

Correct formula, wrong units: wei vs token, tick spacing, sqrt/log/float helpers, fee denominators, spread/impact inconsistency.

**How to Find**

```bash
rg -n "sqrt|log|float|tick|540|365 days|10 \*\*|1e"
```

Check:

- every constant’s unit
- decimal scaling
- gas vs token units
- tick alignment
- library diff against upstream

**Unique Insight**

Math-library bugs are forever-bugs. Shared libraries propagate errors to every integrator.

---

### T21. DoS / Griefing / Frontrunning / Time-Warp

**Definition**

Attacker bricks withdrawals/claims/votes/launches without stealing directly, or steals via the brick.

**How to Find**

```bash
rg -n "for \(|block\.timestamp|deadline|random|vote|finalize|execute\("
```

Test:

- unbounded loops
- 1-wei donation bricks
- vote-window games
- predictable randomness
- gas underestimation
- forced reverts in batch
- exact phase boundaries

Dirty-dozen inputs:

```text
0, 1, 2-wei, max, max+1, twice, front-run, back-run, same-block, other-account, other-chain, self
```

**Unique Insight**

DoS is underrated. Bricked queue plus secondary market can convert freeze into discount purchase. Ask: “who profits while this is stuck?”

---

### T22. Key-Compromise Primitives & Owner Backdoors

**Definition**

Code works as written but hands one key power to drain everything: owner burn/mint/tax-wallet `transferFrom`, unlimited mint, weak multisig.

**How to Find**

```bash
rg -n "onlyOwner.*mint|onlyOwner.*burn|taxWallet|marketingWallet|manager.*transferFrom|multisig|getSigners"
```

Ask:

- Who can move whose funds?
- Can owner burn others’ tokens?
- Can tax wallet `transferFrom` users?
- Is upgradable owner a single EOA?
- Are signer keys operational risk?

**Unique Insight**

Backdoors are found by reading who can move whose money, not by reading comments.

---

### T23. Lending Health-Factor & Liquidation Bypass

**Definition**

Borrowers evade liquidation or corrupt health check via stale rates, cross-market reentrancy, liquidation increasing position, disabled configs, dust borrows resetting indexes.

**How to Find**

```bash
rg -n "healthFactor|liquidat|exchangeRate.*repay|redeemFresh|usageIndex|positionIndex"
```

Test four price/time combinations:

1. stale collateral × fresh debt
2. fresh collateral × stale debt
3. donated collateral
4. interest-skipping windows

Also test:

- self-liquidation
- direct market bypass
- withdraw immediately after borrow
- disabled config reuse
- dust debt reset

**Unique Insight**

Lending has two prices and two times. Bugs live in the four combinations.

---

### T24. Stablecoin / CDP / Peg Games

**Definition**

Mint unbacked stablecoins or drain backing via price-input games, empty-collateral `frob`, free vault closure, NAV inflation, surplus/auction mis-math.

**How to Find**

```bash
rg -n "frob|mint.*stable|peg|NAV|totalHoldings|surplusAuction|debtAuction|stabilityPool"
```

Test:

- backing valuation
- transfer vs swap incentives
- empty collateral mint
- NAV manipulation
- auction math
- free closure
- peg reward/penalty bypass

**Unique Insight**

Every stablecoin is a lending market with one collateral and hardcoded price of $1. Audit backing valuation, not peg assertion.

---

## 15. Part II — External / Immunefi Multi-Language Playbook, T01–T30

This section preserves the external taxonomy. It expands coverage to ZK, SDK, Cosmos, Rust, frontend, formal verification, and cross-language runtime failures.

---

### T01 — Direct-Balance and Donation/Share-Price Accounting

**Definition**

A vault, strategy, lending market, or reward pool derives user value from current token balance, `totalAssets`, `getRate`, utilization, or share price. Attacker changes rate by direct transfer, donation, pending withdrawal, or empty-market manipulation.

**Root Cause**

Protocol fails to distinguish:

- depositor assets vs unsolicited donations;
- cached accounted balance vs live `balanceOf`;
- live supply vs zero denominator;
- utilization vs uncapped ratio;
- pending withdrawal vs redeemable supply.

**Hunt**

```bash
rg -n "balanceOf\(address\(this\)\)|totalAssets|totalSupply|totalDeposits|totalBorrows|exchangeRate|getRate|pricePerShare|utilization|convertToAssets|convertShares" .
```

Ask:

- Can `totalAssets` increase without minting shares?
- Can supply decrease via pending withdrawal, fee, burn, virtual offset?
- Is first-deposit denominator protected?
- Is rate used for mint/redeem/borrow/liquidation/rewards?
- Is rounding direction safe both ways?

**PoC**

```solidity
vault.deposit(1, attacker);
token.transfer(address(vault), 1e24);
vault.deposit(1, attacker);
vault.redeem(vault.balanceOf(attacker), attacker, attacker);
```

**Fix**

- Account only deposited assets.
- Use virtual shares/assets.
- Cap utilization.
- Exclude pending withdrawals from freely redeemable supply.
- Test every market independently.

**Unique Insight**

The denominator is an attack surface. A direct transfer is not harmless dust if balance is treated as user capital.

---

### T02 — Arbitrary Calls, Delegatecall, Confused-Deputy Routers

**Definition**

Approved router, zapper, settler, paymaster, bridge, fee claimer, or delegatecall entrypoint lets caller choose external target/calldata or fails to bind operation to the account whose allowance/role is used.

**Root Cause**

ERC-20 authorization is based on `msg.sender`. A router is the spender seen by token, so malicious caller can steer router into spending victim allowance.

**Hunt**

```bash
rg -n "\.call\{|\.call\(|\.delegatecall|functionCall|multicall|execTransaction|execute\(" .
```

Build table:

| Question | Required Answer |
| --- | --- |
| Who chose target? | trusted registry or caller? |
| Who chose calldata? | typed encoder or caller? |
| Who is msg.sender at token? | user or deputy? |
| Is `from` bound to caller? | explicit equality? |
| Is delegate code-hashed? | yes/no |
| What allowances held? | enumerate |

**Fix**

- Allowlist targets and selectors.
- Bind `from == msg.sender`.
- Use typed operations.
- Avoid arbitrary calldata on allowance-holding contracts.
- Code-hash delegate implementations.

**Unique Insight**

Ask “whose allowance?” before “does the call succeed?”

---

### T03 — Callback Authentication and Execution-Context Confusion

**Definition**

Callback, hook, flash-loan entrypoint, ERC-4337 `handleOps`, token receiver hook, or batch verifier accepts caller/context not proven canonical.

**Root Cause**

Implementation authenticates data but not call frame.

**Hunt**

```bash
rg -n "Callback|callback|onFlashLoan|pancakeCall|uniswapV3SwapCallback|tokensReceived|tokensToSend|onERC721Received|handleOps|executeUserOp" .
```

Test:

- direct attacker call;
- malicious factory clone;
- altered callback data;
- proxy/target double-entry token;
- nested AA operation.

**Fix**

```solidity
require(msg.sender == expectedPool, "not pool");
```

For AA, enforce top-level EOA execution where appropriate.

**Unique Insight**

Callback authentication is a context problem, not just address problem.

---

### T04 — Spot-Price, Reserve, and Manipulable Oracles

**Definition**

Mint, borrow, reward, liquidation, redemption, PCV allocation, or stablecoin mechanism reads price attacker can move atomically.

**Root Cause**

Spot price is executable quote, not time-weighted fact.

**Hunt**

```bash
rg -n "getReserves|slot0|getAmountsOut|get_virtual_price|balanceOf\(.*pair|pricePerShare|getRate|convertToAssets|latestAnswer|latestRoundData|median" .
```

Trace price read to sink.

Run:

- 10× fork skew;
- one-block donation;
- two-block stale-price test;
- wrapper/LP pricing;
- decimal checks.

**Fix**

- TWAP or robust oracle.
- Staleness checks.
- Deviation checks.
- Explicit decimals.
- No spot median legs.

**Unique Insight**

Test oracle source, not only consumer. Chainlink label does not prove freshness or scale.

---

### T05 — Integer Truncation, Decimals, Rounding, Unit Mismatch

**Definition**

Value loses magnitude or changes scale across type boundary, division, ABI boundary, token decimals, or math composition.

**Root Cause**

Assumed bound not enforced.

**Hunt**

```bash
rg -n "uint(8|16|32|64|96|120|128|160|240)\(|unchecked|assembly|and\(|shr\(|shl\(|low_u|unique_saturated|/ *1e[0-9]+|/=|decimals\(\)" .
```

```bash
rg -n "bytesToNumber|parseInt|Number\(|BigInt\(|toNumber|hexToNumber|as number" --glob '*.{ts,tsx,js,py,cairo,move,rs,go}' .
```

Fuzz:

- 0, 1, 2
- type max
- max - 1
- decimals 0, 2, 6, 8, 18, 27
- `a/b*c` vs `a*c/b`
- exact phase boundaries
- Q-format boundaries

**Fix**

- SafeCast.
- Explicit decimals.
- mulDiv.
- Virtual offsets.
- Unit structs.

**Unique Insight**

Rounding direction is economic policy. Round against caller on user-chosen paths.

---

### T06 — Reentrancy, Cross-Function, Read-Only Reentrancy

**Definition**

External call, token hook, swap callback, or oracle view occurs while protocol has stale or partially updated state.

**Root Cause**

CEI incomplete, local guard only, view used as live oracle, token hooks.

**Hunt**

```bash
rg -n "\.send\(|\.transfer\{|\.call\{|safeTransfer|safeTransferFrom|swap\(|stakeTokens|initiateWithdraw|finalize" --glob '*.sol' .
```

```bash
rg -n "function (getRate|price|totalAssets|convertToAssets|balanceOf|preview).*view|external view" .
```

Build call graph, not function list.

**Fix**

- Shared lock for full economic action.
- Cross-contract guard registry.
- Update accounting before external interaction.
- Cache stable rate for views used as oracles.

**Unique Insight**

Mutex on entry function is not mutex on economic state. Read-only function can be reentrancy gadget.

---

### T07 — Reward, Rate, Claim Accounting

**Definition**

Reward, staking, emission, fee, or vesting system pays from stale accumulator, rewards partial action as full, permits duplicate claims, or does not synchronize debt.

**Root Cause**

Every mutation must update same checkpoint.

**Hunt**

```bash
rg -n "rewardDebt|accPerToken|rewardPerToken|lastPayout|lastClaim|claim|harvest|vest|unmint|withdraw.*reward|pending" .
```

Run action pairs:

```text
deposit → claim → transfer → claim
stake → partial unstake → claim
initiateWithdraw → claim → finalize
self-transfer → harvest → claim
claim(id) twice
claim([id,id])
```

**Fix**

- Initialize debt at current accumulator.
- Update debt before payout.
- Mark spent IDs.
- Multiply partial rewards exactly.

**Unique Insight**

Bug is usually in second transition. Fuzz sequences.

---

### T08 — Access Control, Initialization, Proxies, Stale Authority

**Definition**

Privileged state-changing function callable by wrong caller, implementation/beacon initialized/upgraded by attacker, or old authority remains authorized.

**Root Cause**

Authorization checked in only one path, initialization not idempotent, implementation constructors treated as proxy constructors, revocation not cross-chain.

**Hunt**

```bash
rg -n "function (init|initialize|upgrade|setOwner|setRouter|setRegistry|setOracle|setFee|withdraw|mint|burn)|ValidateBasic|onlyOwner|onlyRole|initializer" .
```

Build authorization matrix.

**Fix**

- `initializer`.
- `_disableInitializers()` in implementation.
- Timelock upgrades.
- Code-hash allowlist.
- Uniform validation across message variants.
- Revoke old authority everywhere.

**Unique Insight**

Authorization must be uniform across variants. A batch can validate limit orders but forget market orders.

---

### T09 — Signatures, Subaccounts, Meta-Transactions, Account Abstraction

**Definition**

Signature, permit, relay, forwarder, subaccount, batch message, or UserOperation authenticates payload but not actor/context/chain/contract/deadline/caller/execution frame.

**Root Cause**

Signed hash omits security dimension, or derived sender trusted without checking actual caller.

**Hunt**

```bash
rg -n "ecrecover|ECDSA|permit\(|isValidSignature|EIP712|_msgSender|ERC2771|meta.?transaction|relay|forwarder|UserOperation|Sender|Subaccount" .
```

Signature field table:

| Field | Included? | Why |
| --- | --- | --- |
| chain ID | | cross-chain replay |
| verifying contract | | cross-contract replay |
| nonce | | replay |
| deadline | | stale permit |
| caller/from/subaccount | | confused deputy |
| target/calldata/value | | arbitrary execution |
| execution context | | nested AA griefing |

**Fix**

Bind all fields. For subaccounts, derive ownership from authenticated sender and validate every nested object.

**Unique Insight**

Do not confuse “signature valid” with “operation authorized.”

---

### T10 — Governance, Consensus, Validator Accounting

**Definition**

Protocol consensus, validator power, governance quorum, module-account invariant, or transaction tree accepts state transition that should be rejected.

**Root Cause**

System assumes one canonical representation of power/state. Migration/tree/account/fee path changes one counter but not another.

**Hunt**

```bash
rg -n "quorum|proposal|vote|votingPower|getVotes|checkpoint|validator|stake|unstake|migrate|module account|invariant|distribution|fee|refund|consensus" .
```

Test:

- flash governance takeover;
- migration + unstake double subtraction;
- module account funding;
- cross-tree double spend;
- fee decorator bypass.

**Fix**

- Checkpoint power at proposal time.
- Quorum percent total supply.
- Timelock.
- Single canonical stake counter.
- Reject unauthorized module-account funds.
- Cross-client and cross-tree tests.

**Unique Insight**

Consensus bugs are often “two correct updates” that combine incorrectly.

---

### T11 — Bridges, Wrappers, Runtime Boundaries

**Definition**

Bridge, wrapper token, precompile, portal, or cross-chain adapter credits/mints/unlocks/executes based on message/event/balance/proof/runtime assumption destination cannot independently verify.

**Root Cause**

Source action and destination credit not bound as one atomic state transition.

**Hunt**

```bash
rg -n "bridge|portal|relay|relayer|messageId|nonce|retry|express|finalize|withdraw|mint|burn|proof|validator|quorum|precompile|delegatecall|msg.value" .
```

Walk backward from destination mint/release to source proof.

Ask:

- Can any field change without invalidating proof?
- Can same source event be represented twice?
- Are fast paths escrow or mint?
- Are native/wrapped assets distinct?

**Fix**

- Canonical message ID.
- Bind all fields into hash.
- Reject duplicates/retry variants.
- Escrow on fast path.
- Test ABI boundary for native/wrapped.

**Unique Insight**

A bridge is an authorization protocol, not transport.

---

### T12 — ZK Proof Soundness, Fiat–Shamir Binding, Trusted Setup

**Definition**

ZK verifier accepts proof for false statement, or deployment parameters destroy soundness. Proof becomes authorization token for state transition.

**Root Cause**

Incomplete transcript, batch aggregation omits prover message, trusted setup constant duplicated/default, verifier config unchecked.

**Hunt**

```bash
rg -n "absorb|squeeze|transcript|Fiat|challenge|randomizer|gamma|delta|alpha|beta|trusted.?setup|verification.?key|verifyProof|ecpairing|batch" .
```

Audit:

- transcript message order;
- challenge dependencies;
- batch weights;
- pairing equation;
- setup ceremony inputs;
- proof binding to chain/contract/root/nullifier/recipient/nonce.

**PoC Rules**

- Mutate public input after proof: must reject.
- Assert `gamma != delta`.
- Assert constants non-identity/on-curve.
- Replace one batch proof with invalid: batch must reject.

**Unique Insight**

A proof verifier is access control. Forged proof bypasses wallet ownership and application authorization.

---

### T13 — Key Derivation, Entropy Collapse, SDK Type Coercion

**Definition**

Off-chain SDK/wallet converts secret/private key/nullifier/signature into narrower type and loses entropy.

**Root Cause**

Dynamic-language numeric coercion treated as lossless. JavaScript `Number` is not 256-bit integer.

**Hunt**

```bash
rg -n "bytesToNumber|toNumber\(|Number\(|parseInt\(|parseFloat\(|BigInt\(|number\b|int\(|uint" --glob '*.{ts,tsx,js,py,rs,go,cairo,move}' .
```

```bash
rg -n "privateKey|secret|seed|mnemonic|entropy|randomBytes|PRNG|nullifier|master" .
```

Test:

- values above `2^53`;
- round-trip serialization;
- derivation equality across languages;
- domain separation;
- legacy migration.

**Fix**

Use `BigInt`/`Hex` end-to-end. Prefer `bytesToBigInt`, not `bytesToNumber`.

**Unique Insight**

Check type after every cryptographic boundary. Solidity typing cannot protect JavaScript derivation.

---

### T14 — ABI, Hook Flags, Serialization, Batch Boundaries

**Definition**

Data encoded by one component is interpreted differently by another: arrays mismatch, hook flags encode target differently, token/gas units compared, batch omits per-item invariant.

**Root Cause**

Serialization treated as neutral transport.

**Hunt**

```bash
rg -n "abi\.encode|abi\.decode|bytes|uint8|uint32|uint64|offset|length|flags|traits|hook|batch|array|calldata" .
```

For every array/struct:

- zero length;
- one element;
- max length;
- mismatched nested lengths;
- fuzz flags/reserved bits;
- compare token identity both sides;
- call each batch variant independently.

**Fix**

- Versioned schema.
- Reject unknown flags.
- Canonical encoder/decoder.
- Length checks.
- Encode→decode→encode property tests.

**Unique Insight**

Decoder is part of authorization policy.

---

### T15 — Storage Layout, Slot Collisions, Upgrade State

**Definition**

Two logical records map to same storage slot, proxy/implementation layout incompatible, or packed field read from different slot than written.

**Root Cause**

Hash/struct layout not collision-resistant for actual key domain, or upgrade convention unchecked.

**Hunt**

```bash
rg -n "keccak256\(|abi\.encodePacked\(|mapping\(|struct |slot|storage|assembly|sload|sstore|delegatecall|upgrade" .
```

Check:

- `abi.encode` vs `abi.encodePacked`;
- dynamic arrays/nested mappings;
- namespacing by pool/token/chain;
- bit packing widths;
- read/write after upgrade.

**Fix**

- Domain-separated keys.
- Storage gaps.
- Namespaced storage.
- Layout hash comparison.
- Post-upgrade readback.

**Unique Insight**

Collision can be economic exploit even without key theft. Corrupting oracle/reward accumulator changes downstream decisions.

---

### T16 — Time, Phase, Races, Front-Running, Withdrawal Queues

**Definition**

State transition accepted at wrong time, twice, or by different actor because phase boundaries, timestamps, nonce capacity, request IDs, cooldown, or ordering not atomic.

**Root Cause**

`>` vs `>=`, future start treated as current start, shared ID range, UI phase not enforced on-chain.

**Hunt**

```bash
rg -n "block\.timestamp|startTime|endTime|deadline|drawing|phase|maturity|cooldown|claim|nonce|batchId|requestId|finalize" .
```

Test:

- `t-1`, `t`, `t+1`;
- duplicate arrays;
- concurrent calls;
- repeated blocks;
- zero/one-unit withdrawals;
- shared queue entries.

**Fix**

- Exact boundary checks.
- Spent markers before payout.
- Per-request accounting.
- Wide nonces.
- Recovery path for partial finalization.

**Unique Insight**

Phase check must live on every entrypoint, including batch/multicall variants.

---

### T17 — Balance, Allowance, Recipient, Caller Validation

**Definition**

Token, bridge, loan, withdrawal, or transfer moves value using caller-selected `from`, `to`, `receiver`, subaccount, allowance, or signature without checking actor entitlement.

**Root Cause**

Function validates syntax/signature/existence but not relationship between caller and object.

**Hunt**

```bash
rg -n "function (transfer|transferFrom|transferWithSig|borrow|withdraw|mint|claim|bridge|send)|_approve|_spendAllowance|receiver|beneficiary|onBehalf|subaccount" .
```

Test:

- `from = victim`, `msg.sender = attacker`;
- zero amount;
- allowance exact, one less, one more;
- non-standard tokens;
- receiver != authenticated owner.

**Fix**

```solidity
require(msg.sender == owner || msg.sender == approvedOperator[owner]);
_spendAllowance(from, msg.sender, amount);
```

**Unique Insight**

Allowance is relationship `(owner, spender)`, not number attached to token.

---

### T18 — Pegs, Interest, Fees, Economic Incentives

**Definition**

Stablecoin, lending rate, fee rebate, reward, or PCV mechanism economically manipulated by transferring value, changing utilization, taking wrong settlement side, or repeated harvest.

**Root Cause**

Economic invariant treated as accounting convenience.

**Hunt**

```bash
rg -n "peg|stable|burn|mint|reward|rebate|fee|harvest|utilization|interest|APR|PCV|allocate|reweight|buyback|sell" .
```

Write conservation equation:

```text
assets_out + fees + rewards + debt_change
== assets_in + price_change
```

Test:

- transfer vs swap;
- repeated loops;
- direct donations;
- flash-loan atomicity.

**Fix**

- Single settlement path.
- Explicit transfer/swap semantics.
- Capped rewards.
- Manipulation-resistant oracle.
- Bounded utilization.

**Unique Insight**

Economic exploits often choose different code path, not different amount.

---

### T19 — External Adapters, ABI Drift, Integration Assumptions

**Definition**

Protocol assumes external token, pool, curve interface, Convex deployment, LST, bridge, or ERC-20 behaves exactly as primary chain. Integration fails when ABI, native-token convention, decimals, allowance behavior, or reward path differs.

**Root Cause**

Configuration copied without assertion; generic bytes payload; WETH/ETH conflation; token quirks handled in one path only.

**Hunt**

```bash
rg -n "interface I|exchangeData|pool|coins\(|baseAsset|WETH|ETH_ADDRESS|0xEeee|decimals|approve\(|chainid|block\.chainid|Convex|Curve|Pendle" .
```

Build deployment matrix:

```text
chain × token × pool version × adapter × native/wrapped representation
```

**Fix**

- Constructor assertions.
- Per-chain adapters.
- Typed native/wrapped assets.
- SafeERC20/forceApprove.
- Fork tests per chain.

**Unique Insight**

Integration bugs hide in the word “same.”

---

### T20 — DoS, Griefing, Resource Exhaustion, Forced Reverts

**Definition**

Attacker makes critical function revert, consume unbounded resources, force gas, lock withdrawals, or prevent batch completion.

**Root Cause**

Untrusted input controls loop/response/memory/retry; one sub-operation revert treated as whole batch revert; gas/storage assumptions unenforced.

**Hunt**

```bash
rg -n "for \(|while \(|revert|try |catch |gasleft|MAX_|batch|retry|timeout|query|response|underflow|balanceOf\(address\(this\)\)" .
```

Test:

- zero/max array lengths;
- malformed response;
- one failing batch item;
- concurrent duplicate requests;
- direct token transfer before update;
- reverting callback.

**Fix**

- Bound loops and responses.
- Isolate batch item failures.
- Use atomic claims.
- Guard underflows from donations.

**Unique Insight**

Severity depends on recoverability and breadth. A bricked withdrawal manager is worse than one user’s failed tx.

---

### T21 — Web/Application Supply Chain, Stored XSS, Wallet Compromise

**Definition**

Vulnerability outside contract — exposed Grafana API, writable database, untrusted markdown, localization key, JWT endpoint, browser extension, wallet integration — lets attacker inject content/code or obtain signing authority.

**Root Cause**

Application trust graph larger than contract scope.

**Attack Chain Pattern**

```text
anonymous API / database
→ writable content
→ markdown/renderer
→ innerHTML / javascript:
→ window.ethereum / injected signer
→ signature or approval
```

**Hunt**

```bash
rg -n "dangerouslySetInnerHTML|innerHTML|remark|markdown|sanitize|DOMPurify|href=|javascript:|localStorage|window\.ethereum|injectedWeb3|signPayload|api/|jwt|Authorization|admin" --glob '*.{js,ts,tsx,html,md,json}' .
```

```bash
rg -n "grafana|hasura|postgres|dblink|translation|crowdin|API_KEY|SECRET|service account" .
```

**Fix**

- Sanitize markdown/HTML.
- Restrict URL protocols.
- CSP.
- Least-privilege service accounts.
- No anonymous admin APIs.
- Rotate exposed credentials.
- Separate wallet signing origin.

**Unique Insight**

A web vulnerability becomes crypto vulnerability when browser origin owns signer.

---

### T22 — Deployment, Upgrade, Revocation, Cross-Chain Lifecycle

**Definition**

Contract individually correct at deployment becomes unsafe because implementation, beacon, updater, bridge, role, address, or chain-specific configuration is initialized, authorized, migrated, or revoked incorrectly.

**Root Cause**

Deployment treated as one-time event.

**Hunt**

```bash
rg -n "constructor|initialize|initializer|upgrade|beacon|implementation|CREATE2|CREATE3|set.*(Oracle|Router|Registry|Updater|Keeper)|revoke|authorize|chainid|WETH" .
```

Lifecycle checklist:

1. Initialize every implementation/beacon.
2. Disable initializers in implementation constructors.
3. Bind upgrade roles to timelock and code-hash allowlist.
4. Read back implementation/admin/roles/storage after upgrade.
5. Revoke old updaters/keepers/forwarders on every chain.
6. Use chain-keyed CREATE2/CREATE3 manifests.
7. Monitor privileged state writes.
8. Test migration and rollback per chain.

**Unique Insight**

A fix is not complete until old authority is dead everywhere.

---

### T23 — Formal Verification, Specifications, Mutation Gaps

**Definition**

Formal specification, invariant, unit test, or mutation campaign gives false confidence because it verifies wrong state transition, omits reachable path, or is not connected to deployed bytecode/configuration.

**Root Cause**

Model assumes intended entrypoints, standard tokens, initialized roles, checked arithmetic, no donations, no callbacks, no upgrades.

**Hunt**

```bash
rg -n "assert|invariant|property|rule|ghost|vacuous|assume|summary|spec|mutation|test_" --glob '*.{sol,spec,conf,md}' .
```

Review hidden assumptions:

- trusted `msg.sender`;
- 18 decimals;
- nonzero supply;
- no direct transfer/rebase;
- no upgrade;
- no callback;
- no duplicate IDs.

**Fix**

Include in every invariant test:

- malicious token;
- direct donation;
- callback;
- zero amount;
- wrong caller;
- exact timestamp;
- max type;
- upgrade;
- stale role;
- empty market;
- multi-chain config.

**Unique Insight**

A proof is only as strong as its environment model. Mutation testing often beats another happy-path test.

---

### T24 — Fee-on-Transfer, Rebasing, Reflection, Unusual Token Semantics

**Definition**

Protocol assumes token transfers exact requested amount, has stable `balanceOf`, returns bool from `approve`, and has no transfer hook. Non-standard tokens break assumptions.

**Root Cause**

Accounting uses argument amount, not actual balance delta.

**Cases**

- Fee-on-transfer.
- Rebasing.
- Reflection/deliver.
- ERC-777 hooks.
- ERC-1155/721/404.
- USDT no bool approve.
- Double-entry/proxy tokens.

**Hunt**

```bash
rg -n "fee.?on.?transfer|rebasing|reflection|deliver|balanceOf\(.*before|balanceOf\(.*after|safeTransferFrom|approve\(|tokensReceived|onERC1155|onERC721|404" .
```

**Fix**

```solidity
uint256 before = token.balanceOf(address(this));
token.safeTransferFrom(from, address(this), requested);
uint256 received = token.balanceOf(address(this)) - before;
shares = convertToShares(received);
```

Use token matrix:

```text
standard 18, 6, 2, fee-on-transfer, rebasing, reflection, ERC-777, ERC-1155, USDT, proxy/double-entry
```

**Unique Insight**

Token compatibility is security boundary. Put policy in code and test it.

---

### T25 — NFT, Presale, Vesting, Claims, Marketplace State Machines

**Definition**

Sale, auction, raffle, airdrop, vesting, marketplace, or NFT bridge accepts zero quantity, duplicate ID, self-funded purchase, premature release, weak Merkle proof, or wrong recipient.

**Root Cause**

State machine checks ownership/existence but not full transition.

**Hunt**

```bash
rg -n "buy\(|mint\(|claim\(|airdrop|presale|vesting|merkle|quantity|qty|tokenId|release|withdraw" .
```

Test:

- zero quantity;
- duplicate ID;
- self-transfer/self-referral;
- contract-funded purchase;
- fixed presale below AMM;
- early release;
- Merkle domain binding;
- wrong recipient;
- NFT receiver hooks.

**Fix**

```solidity
require(qty > 0 && qty <= MAX_QTY);
require(msg.value == price * qty);
require(!claimed[tokenId]);
claimed[tokenId] = true;
```

**Unique Insight**

Free claim is often state-machine omission, not pricing bug.

---

### T26 — Lending, Health Factors, Liquidation, Withdrawal Valuation

**Definition**

Lending/derivatives protocol overvalues collateral, underestimates debt, lets user escape liquidation, prices pending withdrawal incorrectly, or liquidation depends on front-runnable transaction.

**Root Cause**

Two views of account: raw shares/debt vs economically adjusted state. Different routes use different values.

**Hunt**

```bash
rg -n "healthFactor|borrowShares|borrowAssets|collateral|liquidat|withdraw_collateral|max_withdraw|interest|effectiveSupply|escrow|pending|oracle|toAssetsUp|toAssetsDown" .
```

Compare formulas across:

- borrow;
- repay;
- withdraw;
- liquidate;
- price;
- migration;
- direct market entry;
- router entry.

**Fix**

- Same oracle/context for all routes.
- Round debt against borrower.
- Round collateral in protocol favor.
- Update interest before checks.
- Disable bypass routes or make them equivalent.

**Unique Insight**

Every public route must produce same solvency answer.

---

### T27 — Stablecoins, Bonding Curves, PCV

**Definition**

Stablecoin/algorithmic/PCV system lets attacker obtain cheap tokens, bypass buy/sell incentives, manipulate peg, drain reserves, or repeat settlement/reward operation.

**Root Cause**

Peg mechanism mixes transfers, swaps, mint/burn, rewards, penalties, reserves, allocation without conservation invariant.

**Hunt**

```bash
rg -n "peg|above|below|buy reward|sell penalty|burn|mint|PCV|allocate|reweight|bonding|curve|reserve|TIMEOUT|epoch" .
```

Test:

- peg direction;
- pool depth;
- reward rate;
- transfer vs swap;
- repeated loops;
- flash atomicity.

**Fix**

Define and enforce conservation equation across all actions.

**Unique Insight**

Compare invariant across `transfer`, `swap`, `mint`, `burn`, `allocate`, `reweight`, `claim`. Cheapest route is often the one spec forgot.

---

### T28 — MEV, Ordering, Sandwiches, Atomic Execution

**Definition**

Attacker profits by reordering, front-running, backrunning, bundling, or atomically manipulating harvest, swap, order, withdrawal, or market operation.

**Root Cause**

Protocol assumes independent transactions, EOA callers, honest ordering, or sufficient manipulation cost.

**Hunt**

```bash
rg -n "harvest|swap|order|lottery|draw|random|block\.timestamp|tx\.origin|front|sandwich|slippage|deadline|nonce" .
```

Simulate bundles:

```text
attacker skew → victim tx → attacker unwind
```

**Fix**

- Commit/reveal or verifiable randomness.
- Bounded slippage.
- Per-block/per-epoch limits.
- Frequent small harvests.
- Private order flow/batch auctions.
- On-chain phase/deadline/nonce checks.

**Unique Insight**

`tx.origin` restriction is not anti-MEV design.

---

### T29 — AI-Assisted Hunting and Safe Automation

**Definition**

AI agent or automated hunter searches code, mutates inputs, builds proofs, or generates reports. Risk includes unsafe execution, credential leakage, hallucinated code, unbounded fuzzing, or optimizing wrong invariant.

**Root Cause**

Automation given production credentials/broad network access, no evidence gate, no independent verifier, no safety boundary.

**Safe Agent Contract**

1. Read repository and deployment manifest.
2. Build hypothesis with exact source lines and invariant.
3. Select local fork/unit-test environment.
4. Use read-only calls or mocks first.
5. Reproduce with before/after state and control.
6. Prove attacker delta and victim loss.
7. Run second independent implementation/checker.
8. Redact secrets and never execute live destructive action.
9. Output confidence, assumptions, missing evidence, remediation.

**Good AI Targets**

- Enumerate external functions without modifiers.
- Map `balanceOf(address(this))` and `totalSupply()` sinks.
- Compare formula variants across routes.
- Find casts/unchecked/assembly boundaries.
- Identify `msg.sender`/signed-field omissions.
- Generate adversarial sequences.
- Inspect cross-language interfaces.
- Generate mutation tests.

**Unique Insight**

Best AI hunting task is bounded proof search, not autonomous exploitation.

---

### T30 — Chain-Runtime and Cross-Language Failures

**Definition**

Implementation locally correct, but chain runtime, precompile, native-token representation, consensus client, ABI, or deployment environment changes meaning of call.

**Root Cause**

Developer assumes EVM equivalence, Rust integer semantics, Cosmos message validation, Solana account ownership, Cairo storage, or precompile behaves like standard model.

**Cases**

- Frontier `msg.value` truncated to 128 bits.
- Custom precompile delegatecall wrong context.
- Aurora native bridge promise misuse.
- Evmos module-account invariant break.
- Cronos fee decorator bypass.
- Decred regular/stake tree input reuse.
- Foom/Aleo verifier/config defects.

**Hunt**

```bash
rg -n "precompile|delegatecall|native|wrapped|WETH|ETH_ADDRESS|0xEeee|module|account|chainid|version|upgrade|client|rpc|transaction" --glob '*.{sol,rs,go,cairo,move,ts}' .
```

Test every language boundary with:

- high-bit value;
- zero;
- max;
- alternate chain ID;
- native/wrapped token;
- malformed message;
- duplicate state transition.

**Fix**

- Model native/wrapped as distinct types.
- Assert chain ID, precompile hash, module permissions.
- Differential-test EVM vs runtime calls.
- Verify consensus across client versions/upgrades.
- Maintain cross-language ABI/schema registry.

**Unique Insight**

The smart contract is only one component. Runtime is part of security boundary.

---

## 16. Case-to-Type Index

| Report / Source | Dominant Type(s) | Hunting Lesson |
| --- | --- | --- |
| Wormhole uninitialized proxy | T08, T22 | Initialize implementation, not only proxy |
| Aurora infinite spend | T11, T30 | Native/runtime call semantics and bridge message binding |
| Optimism money duplication | T10, T18, T30 | Client/runtime balance semantics must match EVM assumptions |
| Moonbeam/Astar/Acala Frontier | T05, T11, T30 | Never narrow 256-bit value at runtime boundary |
| Interlay interBTC | T11 | Validate entire Bitcoin proof/script, not local status bit |
| Notional Exponent | T01, T03, T05, T06, T14, T16, T19, T26 | Compare every route, adapter, queue, rounding rule |
| Belt | T01, T18 | Live balance versus accounted snapshot |
| Fei | T04, T18, T27 | Flash-loan PCV, reward/penalty path, transfer-vs-swap |
| Arbitrum inbox | T11 | Verify burn uniqueness and canonical message encoding |
| Balancer rounding/DoS | T03, T04, T05 | Proxy token entry points and 1-wei rounding |
| Beanstalk | T17 | Allowance/transfer mode must match caller |
| Evmos | T10, T30 | Module-account invariants are consensus-critical |
| Injective batch orders | T08, T09, T28 | Validate every order variant and subaccount owner |
| Bifrost | T21, T22 | Database/API/markdown/wallet trust graph |
| 1inch Aqua | T05, T14, T20, T23 | Flags, units, storage slots, rounding, mutation tests |
| TrustSec ERC-4337 | T03, T09, T20 | Signed payload does not imply top-level execution |
| Veria Aleo | T12, T29 | Fiat–Shamir transcript completeness and proof-as-authorization |
| Privacy Pools | T13, T29 | `Number` is not 256-bit key container |
| StakeDAO Votemarket | T10, T22 | Revoke old updater on every chain after replacement |
| Foom Cash | T12 | Trusted-setup constants are part of application |
| Decred | T10, T30 | Regular/stake tree input consumption must be globally unique |
| Marginal V1 | T05, T15 | Explicit downcast/bounds checks and storage-safe upgrades |
| Ekubo | T05, T15, T16 | Oracle key isolation, start-time boundaries, rounding |
| Panoptic | T23, T26 | Phantom shares, interest index, solvency invariants |
| Tokemak/Certora | T05, T19, T23 | Prove deployed assumptions, not only model |
| 88mph, Tidal, Pods, Mushrooms | T07, T16, T18 | Synchronize reward debt and test action sequences |
| Zapper, ParaSwap, Morpho | T02 | Caller-selected target/calldata is deputy vulnerability |
| Polygon, Cronos, Decred | T10 | Test cross-component/cross-tree state |
| Bifrost/Crowdin/Bitswift | T20, T21 | Off-chain races and supply-chain credentials are part of impact |

---

## 17. AI Agent Operating Procedure

Use this procedure whenever acting as an automated or AI-assisted bug hunter.

### Phase 0 — Scope and Model

- Identify all chains, contracts, libraries, precompiles, SDKs, APIs, deployment manifests.
- Identify custodians, roles, proxy/implementation/beacon/updater/forwarder addresses.
- Record compiler/language versions and decimals for every supported token.
- Separate on-chain, off-chain, consensus, and cryptographic boundaries.

### Phase 1 — Static Inventory

List:

- Every external/public state-changing function and modifier.
- Every `balanceOf(address(this))`, `totalAssets`, `totalSupply`, reserve, price, accumulator, timestamp.
- Every `.call` / `.delegatecall`, callback, hook, receiver, token transfer, signature verification.
- Every uint cast, unchecked block, division, assembly, packed storage, ABI decoder.
- Every upgrade, initializer, role setter, oracle setter, chain-ID branch, CREATE2/CREATE3 address.

### Phase 2 — Hypothesis and Test

For each hypothesis:

- State one falsifiable invariant.
- Identify exact untrusted input and attacker capability.
- Write smallest fork/unit test:
  - one wei;
  - duplicate;
  - boundary;
  - direct call;
  - donation;
  - skew;
  - malformed proof.
- Include control that does not use suspected path.
- Record before/after balances, shares, debt, root, proof result, role, consensus state.
- Test every route/market/adapter/chain variant.

### Phase 3 — Validation

- Reproduce from clean fork and clean compile.
- Check fix removes root cause, not only payload.
- Check second exploit variant and residual authority.
- Have independent checker review invariant and code line.
- Classify impact:
  - theft;
  - unauthorized action;
  - bad debt;
  - proof failure;
  - censorship/DoS;
  - information disclosure.

### Phase 4 — Report

Include:

- Exact commit, file, line, vulnerable code.
- Fixed code and why complete.
- Reproducible commands and raw output.
- Redacted secrets/signatures/private keys/user data.
- Assumptions, unverified external behavior, severity caveats.
- Never write “critical” from revert or theoretical path alone.

---

## 18. Bug Bounty Report Template

Use this structure for submissions.

```markdown
# Title

Short, invariant-based title.

## Severity

Critical / High / Medium / Low / Informational

## Summary

One paragraph describing the vulnerable invariant and impact.

## Vulnerable Code

Exact file, commit, line, snippet.

## Root Cause

Explain the failed invariant.

## Attack Prerequisites

- Attacker capital
- Roles
- Market state
- Chain state
- Token configuration
- Timing constraints

## Proof of Concept

Step-by-step local fork test.

Include:
- setup
- attacker action
- before state
- after state
- attacker delta
- victim/protocol delta

## Impact

Quantify loss, repeatable extraction, unauthorized control, bad debt, DoS, or proof bypass.

## Recommended Fix

Provide concrete patch.

## Regression Test

Provide test that should remain in CI.

## Residual Risk

Mention related variants, other deployments, other chains, operational risks.
```

---

## 19. Severity Classification Guide

### Critical

Direct loss of user/protocol funds, unauthorized minting, bridge forgery, proof forgery, allowance drain, governance takeover with treasury access, arbitrary upgrade, key-level fund movement.

### High

Repeatable extraction, bad debt, collateral overvaluation enabling borrow, liquidation bypass, frozen withdrawals with economic consequence, cross-chain stale authority with value impact.

### Medium

DoS with recovery path, griefing with cost asymmetry, reward inflation limited by caps, rounding leakage requiring unusual tokens, non-critical state corruption.

### Low

Information disclosure, inefficient gas usage, minor rounding against protocol, best-practice violations without exploitable path.

### Informational

Hardening, missing events, unclear docs, centralization risk without direct exploit, unused roles, missing monitoring.

Do not inflate severity without PoC-backed impact.

---

## 20. High-Value Search Patterns Cheat Sheet

### Access Control

```bash
rg -n "onlyOwner|onlyRole|initializer|initialize|init\(|upgrade|upgradeTo|diamondCut|setOwner|setRouter|setRegistry|setOracle|setFee|withdraw|mint|burn"
```

### Value Movement

```bash
rg -n "\.call\{|\.call\(|delegatecall|functionCall|multicall|execTransaction|sendTransaction|transferFrom|withdrawTo|target.*calldata"
```

### Accounting

```bash
rg -n "balanceOf\(address\(this\)\)|totalAssets|totalSupply|totalDeposits|totalBorrows|getReserves|slot0|getAmountsOut|pricePerShare|getRate|exchangeRate|utilization|rewardPerToken|accPerShare|convertToAssets|effectiveSupply"
```

### Oracles

```bash
rg -n "latestAnswer|latestRoundData|decimals\(\)|updatedAt|stale|median|TWAP|slot0|getReserves|get_virtual_price|totalHoldings"
```

### Callbacks / Hooks

```bash
rg -n "Callback|pancakeCall|onFlashLoan|tokensReceived|tokensToSend|onERC721Received|onERC1155Received|handleOps|executeUserOp|hook"
```

### Signatures

```bash
rg -n "ecrecover|ECDSA|permit\(|isValidSignature|EIP712|_msgSender|ERC2771|forwarder|relay|UserOperation|Subaccount|nonce|deadline|chainid"
```

### Types / Math

```bash
rg -n "unchecked|assembly|uint8|uint16|uint32|uint64|uint96|uint128|uint160|/=|/ *1e|decimals|Number\(|bytesToNumber|toNumber|BigInt"
```

### Bridges / Cross-Chain

```bash
rg -n "bridge|portal|relay|relayer|messageId|nonce|retry|express|finalize|proof|validator|quorum|chainid|CREATE2|CREATE3|precompile|native|wrapped|WETH|ETH_ADDRESS|0xEeee"
```

### Web / Ops

```bash
rg -n "dangerouslySetInnerHTML|innerHTML|remark|markdown|sanitize|javascript:|window\.ethereum|injectedWeb3|jwt|Authorization|API_KEY|SECRET|Grafana|Hasura|Crowdin"
```

---

## 21. Mandatory Local Test Matrix

For every protocol, run at least this matrix.

### Inputs

```text
0
1
2 wei
max
max + 1
duplicate
twice
self
other account
other chain
front-run
back-run
same block
exact timestamp
stale timestamp
```

### Token Types

```text
standard 18 decimals
6 decimals
8 decimals
2 decimals
0 decimals
fee-on-transfer
rebasing
reflection
ERC-777
ERC-1155
ERC-721
ERC-404/DN-404/ERC-314
USDT-like approve
double-entry proxy token
```

### Market States

```text
empty market
one wei market
near-empty market
high utilization
low liquidity
pending withdrawals
paused state
post-upgrade state
new chain deployment
new adapter
```

### Actor Combinations

```text
attacker as caller
attacker as receiver
attacker as liquidator and borrower
attacker as validator/signer where applicable
victim as approver
contract as receiver
EOA vs contract caller
nested AA caller
relayer/forwarder caller
```

---

## 22. Invariant Library

Use these invariants as regression tests.

### Accounting Invariants

```text
totalAssets >= totalShares redeemable value
deposits - withdrawals + yield == accounted assets
utilization <= 100% unless explicitly modeled
pending withdrawals not freely redeemable
direct donation cannot inflate attacker shares
```

### AMM Invariants

```text
pair sync must not follow unauthorized balance changes
burn from pair must not reduce pair inventory without swap accounting
skim proceeds should not exist after correct protocol action
```

### Authorization Invariants

```text
no external state-changing function without modifier/check
implementation cannot be initialized
proxy cannot be reinitialized
old updater revoked on all chains
delegatecall only to code-hashed trusted implementation
```

### Signature Invariants

```text
signature cannot replay on same contract
signature cannot replay on another chain
signature binds caller, target, nonce, deadline, contract
derived msg.sender cannot be chosen by attacker
```

### Oracle Invariants

```text
price cannot be moved materially in one tx
stale feeds rejected
decimal normalization explicit
wrapper/LP not priced as underlying unless safe
median legs all manipulation-resistant
```

### Reward Invariants

```text
claim twice pays once
transfer updates reward debt
partial unstake pays partial reward
new user cannot claim historical rewards
self-transfer does not duplicate rewards
```

### Lifecycle Invariants

```text
after upgrade, all old state readable and correct
after role rotation, old role fails
after replacement deployment, old authority revoked
rollback restores safe state
```

---

## 23. Source Preservation and Navigation Notes

- This skill is a merged operationalization of the historical and external corpora.
- Historical labels are `T1` through `T24`.
- External labels are zero-padded `T01` through `T30`.
- `T1` and `T01` are intentionally distinct source labels; consult the crosswalk before treating them as identical.
- Incident evidence remains traceable through type labels, example names, and report categories.
- All PoC material is local-first. Snippets are hypotheses/templates until matched to target source, commit, deployment, and authorized test environment.
- If a condensed section appears to conflict with original source evidence, the original source section is authoritative.

---

## 24. Master Closing Rule

When a codebase resists a grep, do not conclude that it is safe. Change the question:

> Which value, permission, proof, message, or state transition would still be accepted if the caller controlled one more bit, one more token, one more chain, one more block, one more order variant, one more key, or one more omitted transcript message?

That question has found:

- donation drains;
- burn/sync collapses;
- arbitrary calls;
- callback hijacks;
- oracle skews;
- uninitialized proxies;
- stale updaters;
- reward/reentrancy chains;
- hybrid-token edges;
- ZK transcript omissions;
- SDK entropy collapse;
- consensus double accounting;
- frontend-to-wallet chains;
- cross-language runtime failures.

Reproduce the state transition, preserve the evidence, fix the invariant, and only then call it a vulnerability.
