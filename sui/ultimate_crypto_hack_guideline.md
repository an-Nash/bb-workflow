# ULTIMATE Crypto Hack Guideline — Hunt Vulnerabilities Like the 1,624 Reports Teach

> **Dataset:** all 1,624 `crypto.training/hacks/` reports (`D:/ruff/lins-all.txt`), fetched in 17 batches of ~100 and read cover-to-cover (2026-08 → 2017-07 Parity), fused with the deep PoC traces in `tips.md` (§1–§77), `typewise_finding.md` (T01–T20) and `analyze_summery.md` (M1–M8).
> **Audience:** human auditors AND AI coding agents auditing real Solidity codebases.
> **Format per type:** Definition → Root cause → VULNERABLE code → FIXED code → How to find (exact grep + 3-minute triage) → How to exploit (kill-chain + PoC sketch) → Unique insight (the thing scanners miss).
> **Golden rule from all 1,624 cases:** value flows out whenever a contract (a) trusts a number the attacker can move, (b) calls an address the attacker can pick, or (c) updates state after sending value. Every type below is one costume worn by those three sins.

## Contents

- [0. The 1,624-case statistics — where the money actually went](#0-the-1624-case-statistics--where-the-money-actually-went)
- [1. 15-minute triage workflow (run this on EVERY codebase first)](#1-15-minute-triage-workflow-run-this-on-every-codebase-first)
- [T1. Fee-on-Transfer burn + `sync()` AMM-reserve drain](#t1-fee-on-transfer-burn--sync-amm-reserve-drain)
- [T2. Arbitrary external call / confused-deputy routers](#t2-arbitrary-external-call--confused-deputy-routers)
- [T3. Unauthenticated swap callbacks (V3/V2/pancakeCall)](#t3-unauthenticated-swap-callbacks-v3v2pancakecall)
- [T4. Spot-price oracle manipulation](#t4-spot-price-oracle-manipulation)
- [T5. Donation / share-price inflation (ERC-4626 & Compound-fork empty markets)](#t5-donation--share-price-inflation-erc-4626--compound-fork-empty-markets)
- [T6. Reentrancy — classic, ERC777/721 hooks, read-only, cross-function](#t6-reentrancy--classic-erc777721-hooks-read-only-cross-function)
- [T7. Reward-accounting bugs (MasterChef debt, repeatable claims, self-transfer)](#t7-reward-accounting-bugs-masterchef-debt-repeatable-claims-self-transfer)
- [T8. Broken access control (unprotected init/mint/burn/setter)](#t8-broken-access-control-unprotected-initmintburnsetter)
- [T9. Signature replay / permit / EIP-712 / ERC-6492 / ERC-2771 spoofing](#t9-signature-replay--permit--eip-712--erc-6492--erc-2771-spoofing)
- [T10. Governance takeover](#t10-governance-takeover)
- [T11. Bridge / cross-chain message forgery](#t11-bridge--cross-chain-message-forgery)
- [T12. Oracle decimal / stale / wrapper / median bugs](#t12-oracle-decimal--stale--wrapper--median-bugs)
- [T13. Precision / rounding / overflow / underflow](#t13-precision--rounding--overflow--underflow)
- [T14. Flash-loan callback hijack & MEV-bot self-drain](#t14-flash-loan-callback-hijack--mev-bot-self-drain)
- [T15. NFT / marketplace / presale / airdrop / vesting logic](#t15-nft--marketplace--presale--airdrop--vesting-logic)
- [T16. Proxy / upgrade / Diamond re-initialization](#t16-proxy--upgrade--diamond-re-initialization)
- [T17. Self-liquidation / bad-debt / donate-to-reserves](#t17-self-liquidation--bad-debt--donate-to-reserves)
- [T18. Reflection / deliver / dividend / rebase loops](#t18-reflection--deliver--dividend--rebase-loops)
- [T19. ERC-404 / DN-404 / ERC-314 asymmetries](#t19-erc-404--dn-404--erc-314-asymmetries)
- [T20. Unit / scale / math-library bugs](#t20-unit--scale--math-library-bugs)
- [T21. DoS / griefing / frontrunning / time-warp](#t21-dos--griefing--frontrunning--time-warp)
- [T22. Key-compromise primitives & owner backdoors](#t22-key-compromise-primitives--owner-backdoors)
- [T23. Lending health-factor & liquidation bypass](#t23-lending-health-factor--liquidation-bypass)
- [T24. Stablecoin / CDP / peg games](#t24-stablecoin--cdp--peg-games)
- [Appendix A. Universal Foundry PoC skeletons](#appendix-a-universal-foundry-poc-skeletons)
- [Appendix B. AI-agent hunting checklist (copy-paste prompt)](#appendix-b-ai-agent-hunting-checklist-copy-paste-prompt)
- [Appendix C. Report-count by family (evidence of priority)](#appendix-c-report-count-by-family-evidence-of-priority)

---

## 0. The 1,624-case statistics — where the money actually went

| Rank | Family | Share of 1,624 | Signature examples |
|---|---|---|---|
| 1 | T1 FoT burn+`sync()` AMM drain | ~22% (~360) | CashCowCoin, FalconHeavy, NGP, WXC, RANT, UPENG, FIL314, LAURA, FIRE, AIDCToken |
| 2 | T4 Spot-oracle manipulation | ~18% (~290) | UwuLend, Polter, BonqDAO, Inverse, Lodestar, WooFi, MahaLend, Cream/OUSD |
| 3 | T2 Arbitrary-call routers | ~12% (~190) | SquidMulticall, Kame, Size Credit, ParaSwap, Sushi RouteProcessor2, LiFi, Socket |
| 4 | T7 Reward accounting | ~10% (~165) | Penpie, Level, WIFCOIN, OSN, Bankroll, PancakeHunny, SafeDollar |
| 5 | T8 Access control | ~9% (~150) | Parity ×2, Bybit Safe, Telcoin proxy, BBT mint, MARA mint, BTC24H claim |
| 6 | T6 Reentrancy (all flavors) | ~8% (~130) | LendfMe, Cream/AMP, Euler-adjacent, dForce/Curve RO, Grim, Nomad-adjacent |
| 7 | T9 Signature/permit spoof | ~6% (~95) | Exactly, AzukiDAO replay, FoomCash Groth16, Lixir permit, Odos 6492 |
| 8 | T5 Donation/share inflation | ~5% (~85) | Sonne, Onyx, bZx iToken, Resupply, Thetanuts, Wise Lending, 0VIX |
| 9 | T18 Reflection/deliver | ~4% (~60) | HODL, MCC, BEVO, QTN, XAI, HCT, Starlink |
| 10 | T3 Callback hijack | ~3% (~50) | 0x8d2e, BaseCallback, CoW solver, Civfund V3 mint, Unverified6883 |
| 11–24 | rest (gov, bridge, NFT, proxy, …) | ~remainder | Term Finance gov, Nomad zero-root, Ronin keys, TreasureDAO 0-qty |

**Takeaway for hunters:** if you only have one hour, hunt T1→T5 in that order. They are >60% of all real losses and all testable in <5 minutes each with a flash-loan fork test.

---

## 1. 15-minute triage workflow (run this on EVERY codebase first)

```bash
# 1. AMM-touching token logic? (T1/T18/T19) — 5 min, highest hit-rate
grep -rn "sync()\|skim()\|burn(.*pair\|pair.*burn\|_burn(.*pair" --include=*.sol
grep -rn "function sell\|function buy\|_transfer.*tax\|deliver(" --include=*.sol
# PoC: flash-buy, then sell in a loop; assert pair WBNB balance only falls.

# 2. Arbitrary calls? (T2) — 3 min
grep -rn "\.call{\|functionCallWithValue\|delegatecall" --include=*.sol
# Q: can `target` AND `calldata` both be caller-chosen on a contract users approve? If yes → STOP, you found it.

# 3. Callbacks authenticated? (T3/T14) — 2 min
grep -rn "uniswapV3SwapCallback\|pancakeCall\|onFlashLoan\|tokensReceived\|onERC721Received" --include=*.sol
# Q: does the callback verify msg.sender == a real pool the contract created? If not → drainable.

# 4. Price source? (T4/T12) — 3 min
grep -rn "getReserves\|slot0\|getAmountsOut\|balanceOf(pair\|totalHoldings\|pricePerShare\|getRate\|exchangeRate" --include=*.sol
# Q: is this number used for mint/borrow/reward/liquidation AND movable in one tx (flash loan)? If yes → manipulate it.

# 5. Share math on empty/near-empty vault? (T5) — 2 min
grep -rn "totalSupply() == 0\|totalSupply == 0\|exchangeRate\|convertToAssets\|previewRedeem" --include=*.sol
# PoC: deposit 1 wei → donate/rebase → deposit 1 wei → redeem both. Profit = bug.
```

If all five are clean, proceed type-by-type below.

---

## T1. Fee-on-Transfer burn + `sync()` AMM-reserve drain

**Definition.** A token (or its helper/proxy/sell contract) removes the token's *own LP inventory* — burn from the pair, transfer pair→dead, pool-side tax — then calls `pair.sync()`, rewriting reserves to a one-sided collapse the attacker arbitrages in a loop.

**Root cause.** Uniswap-V2 `sync()` sets `reserves = balances` with no invariant check. Any code path that (a) moves token OUT of the pair without a matching `swap()` payout, then (b) syncs, donates the pair's inventory to `k`. The sell/buy/tax path treats the AMM pair as a burn sink instead of inventory.

**VULNERABLE (CashCowCoin 2026-08, ~$117K — reconstructed from trace):**
```solidity
function sell(uint256 amountIn, uint256, uint256) external {
    token.transferFrom(msg.sender, address(this), amountIn); // seller pays
    // ... tax, then:
    token.transfer(pair, amountAfterTax);
    pair.swap(0, wbnbOut, address(router), "");  // WBNB leaves the pair
    token.burnFromPair(pair, DEAD, amountAfterTax); // pair's CCC → dead
    pair.sync(); // reserves := balances → CCC reserve snaps BACK, WBNB stays drained
    payable(msg.sender).transfer(wbnbOut); // attacker keeps WBNB, pool kept nothing
}
```

**FIXED:**
```solidity
function sell(uint256 amountIn, uint256, uint256) external {
    token.transferFrom(msg.sender, address(this), amountIn);
    uint256 burn = amountIn * taxBps / 10_000;
    token.burn(address(this), burn);          // burn from SELLER, before pair contact
    token.transfer(pair, amountIn - burn);    // everything sent to pair stays in pair
    pair.swap(0, wbnbOut, msg.sender, "");    // NO sync(), NO post-swap burn
}
```

**How to find.**
1. `grep -rn "sync()\|\.skim()"` — every hit is a suspect; ask *who can change the pair balance right before it*.
2. `grep -rn "burn" ` inside token `transfer/sell/buy` — if the burn source can be the pair address (explicit `pair` arg, `msg.sender == pair` branch, or arbitrary `from`), it's T1.
3. Variants to cover: sell-path burn (CashCow, FalconHeavy, NGP, WXC), buy-tax charged to pair (INVISTECH), self-transfer burn (RANT, TGBS), owner `burn(pair)` (SKP backdoor, SafeMoon `burn(from)`), `burnLpToken()` (FPC), dividend `distribute` from pair (JHY), zero-amount-triggered burn (PLN).
4. 3-minute PoC: `pair.skim()` yourself after any protocol tx — if your skim extracts value, the accounting is desynced and exploitable.

**How to exploit (kill-chain).**
1. Flash-loan WBNB, optionally donate + `sync()` to fatten the pool.
2. `buy()` to hold the token (or just hold it).
3. Loop `sell()` N times: each iteration swaps token→WBNB out, burns the token side from the pair, syncs — WBNB reserve ratchets down, token reserve never grows.
4. Repay flash loan, keep the WBNB delta. CashCow: 80 sells → 165.47 WBNB profit.

**Unique insight.** Auditors check "tax math" but not "tax *location*". The question is never "is the fee 5%?" but **"whose balance does the fee leave from — and does `sync()` run after?"** Any burn-from-pair + sync, even 1 wei per tx, is a full drain when looped. Also watch `transfer` hooks that behave differently when `to == pair` or `from == pair` (BRA, XAI, HCT burn 1-wei→collapse).

---

## T2. Arbitrary external call / confused-deputy routers

**Definition.** A contract users approve (router, multicall, settler, zapper, paymaster) executes caller-chosen `target` + caller-chosen `calldata`, letting anyone spend *other users'* approvals via `transferFrom(victim, attacker, x)`.

**Root cause.** ERC-20 authorizes by `msg.sender`. The deputy *is* the approved spender, so the token cannot distinguish "router acting for the victim" from "attacker steering the router". Arbitrary-call + standing allowance = universal drain proxy.

**VULNERABLE (Squid `SquidMulticall.run`, 2026-04, ~$800K at risk):**
```solidity
function run(Call[] calldata calls) external payable {
    for (uint256 i = 0; i < calls.length; i++) {
        Call memory call = calls[i];
        // ... Default type: NO transformation, NO checks ...
        (bool ok,) = call.target.call{value: call.value}(call.callData); // attacker: target=USDC, data=transferFrom(victim, me, all)
        require(ok);
    }
}
```

**FIXED:**
```solidity
mapping(address => bool) public allowedTarget;
mapping(bytes4 => bool) public allowedSelector; // only transferFrom(msg.sender,...) shapes
function run(Call[] calldata calls) external payable {
    for (uint256 i = 0; i < calls.length; i++) {
        require(allowedTarget[calls[i].target], "target");
        require(allowedSelector[bytes4(calls[i].callData)], "selector");
        require(_from(calls[i].callData) == msg.sender, "only-self"); // bind spent allowance to caller
        (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
        require(ok);
    }
}
```

**How to find.**
1. `grep -rn "\.call{\|\.call(\|functionCall\|delegatecall"` — for each, trace: can an untrusted caller control the target? the calldata? BOTH = critical (Squid, Kame `executor.call`, Size Credit `router.call`, Unibot, Maestro, RnsPay `dexRouter`, Chainge `MinterProxyV2.swap`, DoughFina connector, FiberRouter, Seneca, BrahmaTOPG, Arcadia `swapData`, Revert V3Utils, TokenFactory fake router).
2. Check what approvals the contract normally holds (routers/settlement/zappers = infinite). 0x Settler `BASIC`, Bebop JAM, Coinbase fee-account, Odos 6492, OpenOcean `transferTokens`, Yodl `transferFee` — all the same sin.
3. `delegatecall` variant is worse (Bybit Safe `masterCopy`, Renegade darkpool, Poly Network selector collision): caller-chosen delegate = full storage takeover.

**How to exploit.** One tx, no capital: `run([{target: USDC, data: transferFrom(victim, attacker, victimBalance)}])` for every victim/token that ever approved the deputy. Repeatable until allowances are revoked.

**Unique insight.** The audit question is NOT "is the call result checked" — it is **"whose allowance is being spent, and did *that* person authorize *this* call?"** Any `transferFrom`/`approve`/`permit` reachable with attacker-shaped calldata on an approved contract is a critical even if the surrounding feature "works". Permit2-style per-tx, exact-amount, short-deadline approvals are the structural fix.

---

## T3. Unauthenticated swap callbacks (V3/V2/pancakeCall)

**Definition.** `uniswapV3SwapCallback` / `pancakeCall` / `swapCallback` executes state changes (or token pulls) without verifying `msg.sender` is a legitimate pool the contract itself created/trusts.

**Root cause.** V3-style callbacks authenticate *only* by caller address, and the pool address is `msg.sender`. If the contract never checks `msg.sender == address(getPool(...))`, anyone can invoke the callback directly and trigger its internal transfers.

**VULNERABLE (BaseCallback `0x8d2e`, 2025-08):**
```solidity
function uniswapV3SwapCallback(int256 amount0, int256 amount1, bytes calldata) external {
    if (amount0 > 0) USDC.transferFrom(msg.sender, attackerVault, uint256(amount0)); // msg.sender is the ATTACKER, not a pool
}
```

**FIXED:**
```solidity
function uniswapV3SwapCallback(int256 a0, int256 a1, bytes calldata data) external {
    (address tokenIn, address tokenOut, uint24 fee) = abi.decode(data, (address, address, uint24));
    require(msg.sender == address(IUniswapV3Factory(factory).getPool(tokenIn, tokenOut, fee)), "not-pool");
    // ... proceed
}
```

**How to find.** `grep -rn "Callback\|pancakeCall"` → assert the first lines verify the caller against the canonical factory (or a stored pool registry). Missing check = drain (0x8d2e, 0xf340 `initVRF` variant, Unverified `0x6077`, CoW solver residual WETH, Civfund forged V3 `mint` callback, Unverified6883 fake-pair callback, BNB48/BNB48MEV bots, MEV `0xDd7c` forged auth).

**How to exploit.** Call the callback directly with crafted deltas; the contract pulls tokens from its own balance/allowance to wherever you say. No flash loan needed.

**Unique insight.** MEV bots are the richest victims: they hold inventory + approvals and their callbacks are often copy-pasted without the factory check. When auditing *any* callback, delete the business logic mentally and read only the first 5 lines — if there is no caller authentication, stop reading: it's the bug.

---

## T4. Spot-price oracle manipulation

**Definition.** Mint / borrow / reward / liquidate / buyback / claim amounts are computed from a price the attacker can move inside the same transaction (reserves, `slot0`, `balanceOf(pair)`, Curve `get_virtual_price`, LP `totalHoldings`, `pricePerShare`).

**Root cause.** Spot state is not a price — it is an *offer*. Reading it as a price lets a flash loan (or a donation, or a first-mover deposit) set the exchange rate, transact at the false rate, then unwind.

**VULNERABLE (UwuLend #1 pattern; Polter; BonqDAO `submitValue`; D3XAI `exchange()`; SlurpyCoin `BuyOrSell`):**
```solidity
function collateralValue(address user) public view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves(); // attacker flash-pumps r1 just before
    uint256 price = r1 * 1e18 / r0;                  // false price
    return collateral[user] * price / 1e18;          // borrow limit from thin air
}
```

**FIXED:**
```solidity
uint256 price = IOracle(chainlinkOr TWAP).getPrice(token); // time-weighted + staleness + deviation guards
require(block.timestamp - updatedAt < MAX_STALENESS);
require(price > 0 && answerDeviationBps < MAX_DEV);
```

**How to find.**
1. List every price read (`getReserves/slot0/getAmountsOut/balanceOf(pair)/get_virtual_price/totalHoldings/getRate/exchangeRate`) and follow it to a *state-changing* sink (mint, borrow, redeem, reward, liquidation, presale price, buyback). Read-only display use is fine; transactional use is the bug.
2. Ask: can the source move >2% in one tx? Single-pool reserves/slot0/balances: yes. Curve pool with imbalanced donation: yes (Harvest yPool, Conic, Platypus coverage, BelugaDSP, Overnight NAV, Zunami `totalHoldings`, Gamma `Hypervisor` shares, NewFreeDAO compounding).
3. Lending-specific: collateral priced from LP that includes the protocol's own donated token (LavaLending WrapperOracle, ROE, Midas stMATIC, Lodestar plvGLP, TiFi, APC, EGD staking, NovaX sandwich).

**How to exploit.** Flash-loan → skew pool (big swap or donation) → borrow/mint/claim at false price → unwind skew → repay loan → keep over-minted assets. Capital required: often zero net (flash).

**Unique insight.** The median-of-N-oracles defense fails if ANY leg is spot (UwuLend: 5-leg median with Curve spot legs). And "we use Chainlink" fails on decimals/staleness (T12). Always test the oracle with a 10× skew fork test: if protocol behavior changes, the oracle is the attack surface.

---

## T5. Donation / share-price inflation (ERC-4626 & Compound-fork empty markets)

## T5. Donation / share-price inflation (ERC-4626 & Compound-fork empty markets)

**Definition.** Attacker inflates `exchangeRate = cash/supply` (or `convertToAssets`) by donating to a near-empty market/vault, then deposits tiny value for huge shares (or borrows against the inflated rate), then redeems for everything.

**Root cause.** Share math divides by a supply that can be ~0 while the numerator is attacker-controlled: `shares = deposit * totalSupply / totalAssets`. Donate first (or `selfdestruct`-force ETH, or rebase), and the first depositor's 1 wei owns the vault.

**VULNERABLE (Sonne/Compound-fork; Onyx empty `oTokenRepay`; bZx iToken; Resupply `exchangeRate=0`; Thetanuts `totalSupply()==0`; Wise Lending `pseudoTotalPool`):**
```solidity
function mint(uint256 mintAmount) external returns (uint256 shares) {
    uint256 exRate = (totalCash + totalBorrows - reserves) / totalSupply; // supply ~ 0 → huge
    shares = mintAmount / exRate; // 1 wei → all shares
    totalSupply += shares;
}
```

**FIXED:**
```solidity
uint256 VIRTUAL_SHARES = 1e6; // or virtual offset assets
shares = mintAmount * (totalSupply + VIRTUAL_SHARES) / (totalCash + VIRTUAL_SHARES);
// + min-liquidity lock: first minter's dust shares are burned to address(0)
```

**How to find.**
1. `grep -rn "totalSupply() == 0\|exchangeRate\|convertToAssets\|previewDeposit"` — every share-mint path needs a virtual-offset or dead-share lock (OpenZeppelin 4626 offset, Uniswap V2 MINIMUM_LIQUIDITY pattern).
2. Fork-test battery (2 min): `deposit(1 wei) → donate(1e24) → deposit(1 wei) → redeem all`. Any profit = T5. Run it against every vault/market, including forks (Sonne, Onyx, Hundred #2, MahaLend, MetaLend selfdestruct-donation, Raft `divUp`, HopeLend rounding, DualPools 2-wei dLINK, Yield Strategy `burn()` donation, Venus vTHE donation + `borrowBehalf`, Venus zkSync wUSDM 4626, Stake319 instant-withdraw, Sumermoney `repayBorrowBehalf` refund, Singularity `totalAssets()` mis-config path, Yearn yBOLD first-depositor 25%).
3. ERC-4626 `withdraw/redeem` that skip allowance (RWAVault, Reaper Farm) belong here too: check `_spendAllowance` on every burn path.

**How to exploit.** Donate (direct transfer, `skim`-able token, selfdestruct ETH, or rebase) → mint dust shares at inflated rate → redeem the whole vault. Often < $10 capital.

**Unique insight.** "We have deposits already so we're safe" is false: near-empty *markets within* a big protocol (one illiquid cToken, one fresh vault, one idle strategy) are empty markets. Audit every market, not every protocol. Donation-prevention code can itself be gamed (Strata Tranches) — verify with the battery test, not by reading the guard.

---

## T6. Reentrancy — classic, ERC777/721 hooks, read-only, cross-function

**Definition.** State is read or value leaves before effects are committed, and an external call (token hook, untrusted callee, or even a *view* into mid-update state) re-enters.

**Root cause.** Checks-Effects-Interactions violated, OR the "view" itself is the vulnerability (read-only reentrancy: Curve/Balancer LP price read mid-`remove_liquidity`), OR the hook token standard (ERC777 `tokensReceived`, ERC721 receiver, ERC1155) hands control to the attacker mid-function.

**VULNERABLE (LendfMe 2020-04; Cream/AMP cross-market ERC777; EarningFarm ETH-push-before-burn; SMOOFS `safeTransferFrom` callback):**
```solidity
function withdraw(uint256 amount) external nonReentrantThisOnly {
    uint256 bal = balanceOf(msg.sender);
    IERC777(token).send(msg.sender, amount, ""); // hook → attacker re-enters withdraw() with stale bal
    balances[msg.sender] = bal - amount;           // too late
}
```

**FIXED:**
```solidity
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;   // effects FIRST
    total -= amount;
    emit Withdraw(msg.sender, amount);
    IERC20(token).safeTransfer(msg.sender, amount); // interaction LAST; guard the whole family incl. views
}
```

**How to find.**
1. `grep -rn "\.send(\|\.call{value\|safeTransfer\|\.transfer(" ` — for each, check: is ALL state (including reward debt, share totals, oracle snapshots) updated BEFORE it? Cross-function: does a *view* (`pricePerShare`, `getRate`, `balanceOf`-derived) read state another function updates mid-flight (dForce/Curve `remove_liquidity`, Sentiment/Balancer, Sturdy, Conic RO, Market.xyz/Hundred-clone, Silo XAI)?
2. Token-hook matrix: any `deposit/borrow/repay/withdraw/claim/stake` touching ERC777/721/1155/404/fee-on-transfer tokens needs `nonReentrant` + CEI (LendfMe imBTC, UniswapV1-imBTC, Cream yUSD, n00d SushiBar fork, NBLGAME `onERC721Received`, ParticleTrade forged-lien mint, THB `claimReward` ERC721, JAY `buyJay` fake-721, Unicly PointFarm 1155, ThunderBurr `makeBid` stale refund, Revest FNFT, Paraluni MasterChef malicious token, DFX `flash()`, Auctus `acoToken`, Agave `liquidationCall`, Hundred ERC-667, Bacon ERC-1820, SpankChain LCOpenTimeout, XSURGE bonding curve, DeltaPrime cross-function `claimReward`, JoeAgent LP custody, Clober `_burn` hook, Bego empty-sig mint path is T8 but same shape).
3. ETH-push-before-burn (EarningFarm `EFVault`, R0AR `EmergencyWithdraw`, Hegic `withdrawWithoutHedge`) and EIP-7702 `BatchCall` (QNT) are reentrancy by delegation — trace `msg.sender` capabilities after every external call.

**How to exploit.** Deploy EvilToken (ERC777 with `tokensReceived` → re-call `withdraw`) or Evil721 (receiver → re-call `claim`); loop until pool drains. Read-only: enter during victim's Curve/Balancer callback and read the inflated LP valuation for borrow/mint.

**Unique insight.** `nonReentrant` on the *entry* function is not enough — read-only reentrancy exploits functions that were never "entered". Guard the *state* (snapshot/mutex around the whole pool action including views), and treat every `balanceOf()`-derived price during a callback as hostile.

---

## T7. Reward-accounting bugs (MasterChef debt, repeatable claims, self-transfer)

**Definition.** Rewards paid from stale checkpoints, un-updated debt on transfer/unstake, repeatable stateless claims, or self-referential farming (referral to self, register N times, zero-value triggers).

**Root cause.** Reward math `pending = user.amount * accPerShare - rewardDebt` has three moving parts; any path that changes `amount`/supply/recipient without syncing all three mints free rewards. Stateless claims (`claim()` with no spent-mark) are infinitely repeatable.

**VULNERABLE (WIFCOIN time-ungated `claimEarned` loop; Level duplicate-epoch `claimMultiple`; Penpie fake-market `getRewardTokens`):**
```solidity
function claimEarned() external { // no time gate, no debt update
    uint256 reward = staked[msg.sender] * accPerShare / 1e18 - rewardDebt[msg.sender];
    token.transfer(msg.sender, reward); // rewardDebt never updated → call again forever
}
```

**FIXED:**
```solidity
function claimEarned() external updatePool {
    uint256 reward = staked[msg.sender] * accPerShare / 1e18 - rewardDebt[msg.sender];
    rewardDebt[msg.sender] = staked[msg.sender] * accPerShare / 1e18; // sync BEFORE payout
    require(block.timestamp >= lastClaim[msg.sender] + EPOCH, "gated");
    lastClaim[msg.sender] = block.timestamp;
    token.safeTransfer(msg.sender, reward);
}
```

**How to find.**
1. `grep -rn "rewardDebt\|accPerShare\|lastPayout\|claim(" ` — verify EVERY mutation path (deposit, withdraw, transfer, emergencyWithdraw, migrate, self-transfer) updates debt *before* payout. Missing on transfer = Equilibria VaultEPendle drain, Pythia receipt-token reset, Popsicle Fragola LP-transfer skip, PRXVT transferable receipt.
2. Repeatability battery: call `claim/register/distribute/harvest` twice in one tx — second call must revert or pay 0 (SheepFarm `register`, Dumbo `distribute`, NCD self-mint, MONA self-referral node farm, WUSD `_englove` sybil, BlastFOMO clone-churn, Grizzifi self-referral chain, INcufi `swapCommision`, SNK JIT-child referral, BCT self-funding referral, ChiSale self-referral, Revamp self-referral, EGGX flash-mint NFT airdrop, Pandora `transferFrom` underflow).
3. Zero-value/edge triggers: zero-amount 1155 batch inflating tiers (RoyalRoyalties), zero-share redeem drain (YIEDL), zero-value `transferFrom` inflation (EXcommunity), `amount==0 ⇒ take all` (Erc20transfer), empty-claim paths (OTSea `claim` re-arm, Sorra partial-withdraw recompute, LPMine time desync, EHIVE stake-before-earn, OmniEstate stale-variable over-claim, Zero Staking struct-delete wipe).
4. Pool-desync flavors: `lastPayout` stale drip (Bankroll ×3, Gangster OG Vault, Dyson `harvest` sandwich, Beefy MooCAKE harvest sandwich, Swamp `earn` sandwich), donation-fed rewards (EST `skim`-fed drip, SinstakeZombie flash-donation, JHY 100× over-credit, ZongZi burnToHolder), debt-not-on-transfer above.

**How to exploit.** No flash loan needed: stake → claim → (transfer receipt to fresh address | self-refer | re-register | unstake-without-debt-reset) → claim again. Loop until pool empty. Capital: dust.

**Unique insight.** Rewards are the #1 "looks correct in isolation" bug: each function is fine, but the *combination* (stake→transfer→claim, deposit→donate→claim) breaks. Your test harness must fuzz *pairs* of actions, not single functions. Self-transfer (`transfer(you,you,1)`) is the cheapest universal probe — LABUBU, SSS, APIG, GPU self-doubling all fall to it.

---

## T8. Broken access control (unprotected init/mint/burn/setter)

**Definition.** A privileged function (`initialize`, `mint`, `burn`, `setOwner/Router/Registry`, `withdrawFees`, `upgrade`) callable by anyone.

**Root cause.** Missing `onlyOwner`/`onlyRole`/initializer guard, or a proxy whose implementation was never initialized (front-runnable), or a setter that trusts the caller (GFOX `setMerkleRoot`, LixiVault `Settings.setBatchAddress`, SubQuery).

**VULNERABLE (Parity first hack 2017 — the archetype; Telcoin `CloneableProxy`; BBT `setRegistry+mint`; MARA buy-proxy mint; BTC24H `claim`; WAL-E re-init):**
```solidity
function initWallet(address[] _owners, uint _required, uint _daylimit) public { // NO GUARD
    initDaylimit(_daylimit); initMultiowned(_owners, _required); // attacker becomes owner → drains
}
```

**FIXED:**
```solidity
bool private _initialized;
modifier initializer() { require(!_initialized, "init"); _; _initialized = true; }
function initWallet(address[] o, uint r, uint d) external initializer { ... }
// + initialize the IMPLEMENTATION itself at deploy; + `disableInitializers()` in constructors.
```

**How to find.**
1. `grep -rn "function init\|initialize(\|function mint\|function burn\|function set.*Owner\|function set.*Router\|function set.*Registry\|onlyOwner" ` — every state-changing privileged fn must have a modifier; every proxy must guard init AND the implementation must be pre-initialized (Parity ×2, Audius storage-collision re-init, Optimism Wintermute Safe front-run, DAO Maker `init→emergencyExit`, 88mph NFT `init`, CEXISWAP `initialize`+UUPS, UERII public mint, PHIL `simpleToken`, MELO `mint`, VINU `addLiquidityETH`, DCF `buyTokens`+shadowing, Goldseed landNFT forwarder, FPR `setAdmin`, NGFS privilege chain, INUMI `setMarketingWallet`, Shezmu vault `mint`, MAMO `giveawayOne`, UFT tiny-LP treasury misprice, 98Token public swap, Pledge `swapTokenU`, Erc20transfer `transferFrom` drain, YDT `proxyTransfer`, X319 `claimEther`, AIRWA `setBurnRate`, BITDOG `changeRouterVersion`, IRYSAI tax-wallet `transferFrom`, YziAI hardcoded-manager `transferFrom`, NOON public `_transfer`, CFToken public `_transfer`, GHT public `transferFrom`, BNBX public `transferFrom`, NOVO skipped-allowance `transferFrom`, SNOOD allowance bypass, Redacted `transferFrom` logic, TecraSpace swapped keys, tCDP wrong-slot debit, MC AI tax-wallet bypass, HPay `setToken` restake-junk, SwapX caller-recipient, ULME `buyMiner` spends stranger USDT, MEV `removeAdmin` fleet seizure).
2. Factories/clones: `create2`/minimal-proxy whose `initialize` is public and front-runnable (Four.meme pre-initialized V3 pool, TokenFactory fake router, `0xD4F1` OwnableUpgradeable).
3. Timelock/governance-adjacent setters with leaked/dead keys (Levyathan deployer key, PAID upgrade key, Adshares minter key, AROS `claimSigner` key, Ronin 5-key multisig, Harmony 2-of-5).

**How to exploit.** Call it. `initialize()` → become owner → `mint`/`upgrade`/`withdraw`. One tx, zero capital. For front-run variants, watch mempool for deployment and initialize first.

**Unique insight.** Access-control bugs are "boring" but #5 by count because every fork, factory clone, and V2-deploy re-introduces them. The AI check is trivially automatable: list all external/public state-changing functions, list their modifiers, flag any with none — then verify each flag is *actually* privileged (mint/burn/set/withdraw/upgrade/selfdestruct/delegatecall).

---

## T9. Signature replay / permit / EIP-712 / ERC-6492 / ERC-2771 spoofing

**Definition.** Signatures usable twice, on another chain/contract, by another relayer, or with attacker-rewritten parameters; `_msgSender()`/recipient/`from` spoofed via multicall/forwarder; ZK proofs forged via broken verifier math.

**Root cause.** Signed message omits nonce/expiry/chainid/contract/`msg.sender` binding; `ecrecover` to `address(0)` compared against admin; ERC-2771 `_msgSender()` extracted from attacker-controlled calldata suffix; 6492 `allowSideEffects` executes arbitrary calls during "validation".

**VULNERABLE (Exactly `DebtManager` permit-spoof; AzukiDAO unenforced `signatureClaimed`; LegendaryMoneyMon `ecrecover→0==admin`):**
```solidity
function claim(bytes calldata sig) external {
    address signer = ecrecover(hash, v, r, s); // no nonce, no expiry, no chainid
    require(signer == admin, "bad");          // if sig invalid → signer == address(0); if admin == 0 → pass!
    _mint(msg.sender, amount);                  // replayable forever, cross-chain
}
```

**FIXED:**
```solidity
bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(TYPEHASH, msg.sender, amount, nonces[msg.sender]++, block.chainid, address(this), expiry)));
require(block.timestamp <= expiry, "exp");
address signer = ECDSA.recover(digest, sig);
require(signer == admin && signer != address(0), "bad");
```

**How to find.**
1. `grep -rn "ecrecover\|isValidSig\|permit(\|_msgSender()\|ERC2771\|6492\|allowSideEffects" ` — for each: list every field in the signed struct; missing nonce/expiry/chainid/contract-address/caller-binding = replayable (Atomic signature replay, TCH replay loophole, 0x0DEX forged LSAG + stale `_lastWithdrawal`, SYMMIO nonce-free Muon sig, Remora missing-nonce `buyTokenOCP` + unrestricted `setAllowlist`, Sequence partial-session replay, Securitize/GTE/AmpleEarn/Sofamon/HYBUX cross-contract replay, zkSync SSO 1271 no-binding, SXT duplicate-signer, Recall missing-duplication, Barter balance-nonce, 1inch Fusion suffix underflow, Crosswise forwarder `_msgSender` spoof, HNet/DominoTT/TIME ERC2771-multicall pool-burn, Odos 6492 `allowSideEffects=true` arbitrary call, Solady 6492 side-effect drain, AnyswapV4Router permit-fallback on non-enforcing tokens, Multichain `anySwapOutUnderlyingWithPermit`, Meter `transferWithPermit` guard flaw, RICE signature-less `setMasterContractApproval`, Quixotic unsigned-`buyer` drain).
2. ZK/verifier math: check pairing checks and trusted-setup constants (`FoomCash gamma==delta` forgery, AZTEC missing-pairing + `confidentialApprove` replay inversion).
3. Presale/claim Merkle roots: permissionless `setMerkleRoot` (GFOX) or single-leaf forgery (SuperRare `updateMerkleRoot`) = signature layer bypassed entirely.
4. 3-minute test: capture a valid sig, replay it twice / from another address / on a forked chainid — any success = critical.

**How to exploit.** Sniff one honest signature (or craft `ecrecover→0`), replay across accounts/chains/contracts, or append an ERC-2771 suffix to impersonate the pool/victim. Cost: gas only.

**Unique insight.** The deadliest variant is *parameter confusion*, not missing nonce: Exactly's permit acted "on behalf of any account" because `_msgSender` came from the permit itself. Whenever msg.sender is *derived* (2771, multicall, meta-tx, permit, 6492), ask: "who chose these bytes?" If the answer is the caller, the authentication is theater.

---

*(continues — T10–T14 next)*

---

## T10. Governance takeover

**Definition.** Attacker gains proposal/voting/upgrade power (flash-loaned votes, abandoned governor, thin-quorum DAO, self-answered referendum) and upgrades or drains the treasury.

**Root cause.** Voting power is checkpointed too late (or not at all), quorum is tiny relative to flash-loanable supply, timelock delay is zero, or governance was abandoned but still wired to funds.

**VULNERABLE (Beanstalk flash-loan self-pass 2022; Term Finance thin-gtmvETH + zero-cooldown; StrongBlock abandoned governor; ZKPanther Reality.eth module; BarnBridge abandoned DAO):**
```solidity
function propose(address[] targets, bytes[] datas) external returns (uint256 id) {
    id = _propose(targets, datas); // voting power read at VOTE time, not proposal time
} // attacker: flash-borrow 70% supply → propose(maliciousUpgrade) → vote → execute → repay, one tx/block window
```

**FIXED:**
```solidity
// checkpoint/snapshot voting power at PROPOSAL creation; votingDelay >= 1 block (flash-loan proof);
// quorum as % of TOTAL supply with timelock delay > market-manipulation window; no zero-delay upgrades of value-holding contracts.
```

**How to find.** `grep -rn "propose(\|queue(\|execute(\|votingPower\|getVotes\|quorum"` — check: snapshot block vs vote block (Aragon EarlyExecution flashloan-vulnerable), quorum % (Build Finance low-quorum drain, Fortress Loans capture + poisoned oracle, TOP Aragon instant-execution + BPool drain, Xave SafeSnap/Reality takeover, Audius storage-collision re-init of live proxies, Curio fake-`DSChief` + `vat.suck` mint, Beanstalk BIP-39 facet omission, IQ AI 4%-quorum win, Ajna ExtraordinaryFunding caller-supplied voters, Panther/StrongBlock/Term/ZKPanther abandoned-or-thin governors).

**How to exploit.** Flash-borrow governance token → delegate → propose upgrade-to-drain → vote → queue → execute (often same-tx or next block) → repay loan. Needs only flash-loan depth > quorum.

**Unique insight.** "Abandoned" governance is live governance: if the governor contract can still call the treasury, someone will. During triage, trace *outgoing* calls from every governor/timelock/Safe module, not just incoming proposals.

---

## T11. Bridge / cross-chain message forgery

**Definition.** Mint/release/unlock on the destination chain without a real lock/burn on the source — forged validator set, unverified `retryMessageIn`/express path, missing source-amount checks.

**Root cause.** The destination trusts a message whose authenticity it never verifies (self-signed validator set, permissionless relayer entrypoint, express path skipping verification, `lzCompose` stealing composed transfers).

**VULNERABLE (Nomad zero-root 2022 — the archetype; MAP `retryMessageIn` 1e33 mint; Verus no-amount-validation import; New Market Trading Axelar-express Safe-module forgery):**
```solidity
function process(bytes32 root, bytes calldata message) external {
    require(confirmAt[root] > 0, "unproven"); // Nomad: confirmAt[0] == 1 at deploy → root 0x00..00 is "proven"
    _mint(message.recipient, message.amount);   // any forged message with root 0 passes
}
```

**FIXED:**
```solidity
require(confirmAt[root] > block.timestamp && root != bytes32(0), "unproven");
require(_isValidatorQuorum(signatures, message), "no-quorum");
// express/fast paths must escrow, not mint; relayer entrypoints restricted to the endpoint.
```

**How to find.** `grep -rn "lzReceive\|retryMessageIn\|expressExecute\|process(\|mint.*message\|nonblockingLzReceive"` — ask: who can call it, what proves the source chain state, does the fast path skip the proof (Squid express delegate, AK1111 permissionless `nonblockingLzReceive1`, Canto asD permissionless `lzCompose`, ChainSwap self-signed `receive` ×2, HYPR uninitialized L1StandardBridge → messenger spoof, FEG relayer-allowlist pollution, Oku/Olas arbitrary-token bridge paths, Sweep-n-Flip stuck ERC721, ArkProject revert-mismatch, YieldFi CCIP `uint32-vs-uint64` decode + missing source validation, Toki silent-burn recipient bytes, Tanssi free `sendCurrentOperatorsKeys` spam, Stake.Link reSDL stale-approval theft, Decent router/gas-channel flaws, Maia depositNonce poisoning + `retrySettlement` award theft, Connext reconcile-vs-pay mismatch, Optimism-interop deterministic-token theft, AnyswapV4 underlying-transfer drain, Ronin/Harmony key-compromise bridges — keys are T22 but the code flaw is unverified trust).

**How to exploit.** Craft the message yourself (fake amount/recipient), call the destination entrypoint directly. If a quorum is needed, check whether the validator set is attacker-settable or the root defaults to proven.

**Unique insight.** Test the bridge *backwards*: start at the mint/release function and walk toward verification. Most bridge bugs are found in 60 seconds this way because the mint side is small and the verification side is assumed, not read.

---

## T12. Oracle decimal / stale / wrapper / median bugs

**Definition.** Correct source, wrong interpretation: decimals mis-scaled, stale price accepted, wrapper/LP treated as the underlying, or a "robust median" with a manipulable leg.

**Root cause.** Price consumers assume 18 decimals / fresh data / 1:1 backing that the code never enforces.

**VULNERABLE (Blueberry decimal mismatch ~$1.4M; MorphoBlue PAXG 1e12 scale error; Kipseli USD-scale misread as token units; MBU 1e18× mint):**
```solidity
uint256 price = oracle.latestAnswer(); // 8 decimals, used as 18 → collateral 1e10× overvalued
uint256 value = collateral * price / 1e18; // should be / 1e8
```

**FIXED:**
```solidity
(, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
require(block.timestamp - updatedAt <= MAX_STALENESS && answer > 0);
uint256 price = uint256(answer) * 1e18 / (10 ** oracle.decimals()); // normalize EXPLICITLY
```

**How to find.** `grep -rn "latestAnswer\|latestRoundData\|decimals()\|1e8\|1e18"` near price math — verify decimal normalization per-feed (Blueberry, MorphoBlue PAXG, Kipseli cbBTC, MBU deposit, SHIDO ×1e9 claim, OLPC `decimalsValue`, Gondi `uint160` truncation, Astrolab role-revoke math, Forte float128 family, Gains pre-v9 spread, BoJ reserve-index fee compounding, Moonwell cbETH/wrsETH incidents, NLX multi-fetch arbitrage, Pyth exponent/payable variants, DIA Spectra fee-drop DoS, CAP Labs staleness-vs-validity + vault/interest/fee variants, Vader TWAP collapse, API3 single-oracle control, EigenLayer lost withdrawals, NUTS `getPrice` overflow >$100k, RegnumAurum index skew, Etherspot userOp mismatch).
Stale checks: any `updatedAt` ignored or global staleness rejecting valid feeds (inverse DoS). Wrapper checks: LP/4626 shares priced at face value (LavaLending WrapperOracle, ROE, Midas, Lodestar, TiFi — see T4).

**How to exploit.** Borrow against the over-scaled collateral (decimals), or wait/force staleness then transact at the frozen price. No flash loan usually needed — just arithmetic.

**Unique insight.** Decimal bugs survive audits because reviewers "know" Chainlink is 8 decimals and the token is 18 — until one feed isn't. Write the normalization as a *tested* helper (with a unit test per feed), never inline math.

---

## T13. Precision / rounding / overflow / underflow

**Definition.** Value leaks or bricks through integer division order, truncation casts, share-rounding asymmetry, or classic overflow (pre-0.8 / unchecked).

**Root cause.** `a/b*c` instead of `a*c/b`; `uint128/uint32/uint16/uint8` casts of larger values; first-depositor rounding; fee-on-zero-supply paths.

**VULNERABLE (BEC `batchTransfer` overflow 2018 — the archetype; Velocore `feeMultiplier` overflow; Umbrella `withdraw` underflow; Sperax elapsed-time underflow):**
```solidity
uint256 amount = uint256(cnt) * value; // cnt attacker-controlled → overflow → bypass balance check
require(balances[msg.sender] >= amount); // passes with wrapped amount
for (uint i = 0; i < receivers.length; i++) balances[receivers[i]] += value; // infinite mint
```

**FIXED:** `pragma ^0.8` (checked arithmetic by default) + explicit `require(cnt <= 20)` bounds + mulDiv for division-first math.

**How to find.** `grep -rn "unchecked\|uint128\|uint64\|uint32\|uint16\|/=\|/ 1e"` — trace casts (Matez `uint128` free stake, Alkimiya `uint128(shares)` over-payout, RWf(x) underflow, Gondi `uint160`, Oku `uint160`, Terplayer ceil-underflow, Remora `uint64` payout overflow + `uint32` pledge brick, Notional `uint16` batchNonce brick, Ajna bucket underflow, DittoETH `&&`-vs-`||` accounting, Canto gauge underflow, Livepeer underflow, MuteBot/Nimbus `10000-vs-1000` K-scaling, LinkDao K mis-scale, Uranium 100× K-slack, Swapos 10-wei drain, Nimbus/Nowswap scaling, DeFiPlaza zero-reserve swap, FoomCash `gamma==delta`, Forte sqrt/eq/packedFloat/Ln family, Blueberry `szDecimals` 100× underprice, Elytra missing-1e18 scale, Etherspot partial-invoice lock, Yuzu fee-in-poolSize inflation, Yuzu fixed-pre-yield payout, f(x) dust-redeem tick-DoS, GTE dust-order book block, Hinkal tree `!=`-vs-`<=` overwrite, Hinkal half-full root lock, Nouns off-by-one, MuseumOfMahomes `>=`, Y2K deposit-fee bypass queue, Yield Ninja unrounded first-share, Manifest 0-share first deposit, KittenSwap `getRewardForPeriod` future-period claim, Resolv `safeTransferFrom`-vs-`safeTransfer` fee grief, Sablier Flow overflow-brick stream, Aera wrong-swap-amount guardian bypass, Prime `testFinalizeSettlement`, Centrifuge manager theft, Statusl OOG-slash evasion).
Also: divide-before-multiply (Remora `FiveFiftyRule`, Ammplify H-11 geometric-mean overcharge), fee-on-zero-supply, dust-driven DoS (GTE 1-wei graduation/burn-overestimate/free-LP, RipIt prize-count over-reserve, Suzaku zero-stake division).

**How to exploit.** Pass oversized counts/amounts (overflow), dust values (rounding), or boundary ids (off-by-one) and observe free mints/bricked pools. Pre-0.8 forks: `cnt * value` overflow is a one-tx infinite mint (BEC, SMT `transferProxy`).

**Unique insight.** Rounding bugs are *directional*: attacker-profitable rounding always sits on a path where the attacker chooses the transaction size (deposit/withdraw/borrow/redeem). Fix by rounding *against* the caller on every such path (mint rounds down, withdraw rounds up) and fuzzing with 1-wei / 2-wei / type-max inputs.

---

## T14. Flash-loan callback hijack & MEV-bot self-drain

**Definition.** The contract's own flash-loan/callback entrypoint (`receiveFlashLoan`, `callFunction`, `pancakeCall`, `executeOperation`) is callable by anyone and moves the contract's *own* funds/approvals to attacker-chosen destinations.

**Root cause.** Same as T3 but the victim is the bot/vault itself: callback authenticated by nothing, `assetTo`/recipient/amount taken from calldata instead of storage.

**VULNERABLE (BNB48 `pancakeCall` inventory drain; BADCODE dYdX `callFunction` max-approval drain; Unverified670471 Balancer-forwarded victim repayment; MoonHacker unauthenticated AAVE callback):**
```solidity
function pancakeCall(address sender, uint amount0, uint amount1, bytes calldata data) external {
    (address token, address to, uint amount) = abi.decode(data, (address, address, uint));
    IERC20(token).transfer(to, amount); // anyone calls this; contract's own balance leaves
}
```

**FIXED:**
```solidity
address private constant PANCAKE_PAIR = 0x...; // or factory-verified pool
function pancakeCall(address, uint, uint, bytes calldata data) external {
    require(msg.sender == PANCAKE_PAIR, "only-pair");
    require(_initiatedFlash[msg.sender] ...); // reentrancy + initiator binding
}
```

**How to find.** `grep -rn "FlashLoan\|callFunction\|pancakeCall\|executeOperation\|assetTo"` — if the callback sender/recipient/amount are decoded from `data` rather than stored before the loan, it's hijackable (BNB48, BADCODE, 670471, MoonHacker, MEV `0x28d9` `assetTo`, MEV `0xDd7c` forged V3 auth, QIXI free-mint repayment token, EFLeverVault `flashLoan(0x2)` inflate-balance, UnprotectedArbBot forwarder, JaredFromSubway bait-wrapper approvals, SHELL permissionless arb recipient, `0xa47b1` unauthenticated `receiveFlashLoan`, MEV `0x8c2d` harvester, MEV `0xa247` `removeAdmin` fleet seizure, AAVEBoost `proxyDeposit` subsidy).

**How to exploit.** Call the callback directly (no loan needed) with `to = attacker, amount = entire balance`. Repeat per token.

**Unique insight.** Bots are unaudited protocols with treasuries: they hold inventory, infinite approvals, and copy-pasted callback code. If you see a private-key-operated contract with a public callback, treat it as a live bounty — the key holder's OpSec is your exploit window.

---

*(continues — T15–T19 next)*

---

## T15. NFT / marketplace / presale / airdrop / vesting logic

**Definition.** NFTs bought for 0 quantity, free-minted via broken sale math, rental/escrow double-spent, presale priced below the live AMM, vesting released early, airdrops farmed by sybils.

**Root cause.** Sale/claim math trusts caller-supplied counts/addresses/prices (`price * qty` with `qty=0`, `msg.value`-funded purchase from contract balance, merkle root settable, time checks missing).

**VULNERABLE (TreasureDAO zero-quantity free buy; PegaBall `buyGamesFrom` self-funded from contract balance; NFTG 13× misprice):**
```solidity
function buy(uint256 tokenId, uint256 qty) external payable {
    uint256 cost = pricePerItem[tokenId] * qty; // qty = 0 → cost = 0
    require(msg.value >= cost);                 // passes with 0 ETH
    for (uint i = 0; i < qty; i++) {}           // nothing minted?
    nft.transferFrom(seller, msg.sender, tokenId); // but the single NFT still moves — free
}
```

**FIXED:**
```solidity
require(qty > 0 && qty <= MAX_PER_TX, "qty");
require(msg.value == pricePerItem[tokenId] * qty, "exact"); // exact, not >=
```

**How to find.** `grep -rn "quantity\|qty\|buy(\|mint(\|claim(\|presale\|merkleRoot\|release(" ` — test every sale/claim with 0, 1, max+1, and double-claim; verify `msg.value` funds from the *caller* (PegaBall self-fund, ChiSale full-`msg.value` revenue-share, wkeyDAO fixed-vs-AMM arb, AISOTH same-tx buy+claim dump, SUT fixed-price inventory, Axioma mispriced presale, Minto unvalidated `paymentToken`, MicDao fixed-rate-vs-manipulated-AMM, LaunchZone victim-side swap, StackMarket zero-slippage buy, PresaleV5 `slot0` pricing, BTC20 `buyWithEthDynamic`, Four.meme migration front-run, Pump pre-listing seeding drain, StepHero `claimReferral` reentrancy, xLOOT duplicate-id epoch re-claim, GoldReserve 1155 profit reset, SheepFarm `register` free gems ×2, BlastFOMO/WUSD/Grizzifi/INcufi/SNK/BCT/ChiSale/Revamp referral & sybil farms, Babyloogn zero-NFT stake airdrop, EGGX flash-mint NFT airdrop, BAYC vaulted-BAYC flash-claim, DN404 vesting-proxy re-init, LuckyTiger/RedKeys/ATM-BlindBox/HenloKart predictable randomness, DG accountability trees (Hinkal), Vesting escrow bricking (Rio), `batchRelease`-before-transfer (Treasury Vesting), TokenOps revoke-freeze, CryptoLegacy rebase-mix vesting, Abacus bond/token/ether variants, Liquity zero-ICR strand, Y2K rollover grief, Sperax elapsed-underflow first-depositor drain, RipIt/SpinLottery prize-lock mismatch, Majority game-session family (free cross-game, bond loss, locked refunds/fees/rewards), Nalakuvara fixed-payout AMM drain, WhereIsMyDragonTreasure recipe<reward, BadGuys `chosenAmount` wallet-bypass, Quixotic unsigned-buyer, NFTTrader `editCounterPart` reentrancy, RuggedArt self-staked purchase, Unicly 1155 points theft, TheNFTV2 burned-NFT re-pull, ParticleTrade forged-lien mint, TSURU unguarded `onERC1155Received` free-mint, BlockchainBets 1155 stake/transform inflation, Sandbox public `_burn`, Foundation sale-revenue theft, Behodler double-`transferAndCall`, Streaming `recoverTokens` variants, Putty double-fill, Recall checkpoint family, Oku approval/order/nonce-reentrancy family, DittoETH flag/order-id/short-record family, Polynomial Kangaroo/hedge/fee family, Ajna position-NFT spam + moveLiquidity freezes, MuteBot dMute array-push, Timeswap fee-zero + tokenId-collision).

**How to exploit.** Buy(0), claim twice, register N wallets, mine `block.timestamp`-randomness off-chain and only play winning seeds. Presales: compare presale price vs live AMM — buy low, dump same block.

**Unique insight.** Presale/airdrop code is written last and audited least, yet it holds the most *unconditional* value (free tokens). Always audit the sale before the staking: a 13× misprice (NFTG) beats any reentrancy.

---

## T16. Proxy / upgrade / Diamond re-initialization

**Definition.** Implementation, clone, or Diamond facet re-initialized or upgraded by an attacker (uninitialized implementation front-run, public `initialize`, unrestricted `diamondCut`/`upgradeTo`, storage-collision re-call).

**Root cause.** `initializer` missing/once-only-not-enforced; implementation contract itself left uninitialized; `upgradeTo`/`diamondCut` exposed; storage layout collision across upgrades.

**VULNERABLE (Pike Finance UUPS hijack; Audius storage-collision re-call; Burve SimplexDiamond open `diamondCut`):**
```solidity
function initialize(address owner_) public { // called on the IMPLEMENTATION, no guard
    _owner = owner_; // attacker front-runs → owns implementation → upgradeTo(drain)
}
function upgradeTo(address impl) public { require(msg.sender == _owner); _impl = impl; }
```

**FIXED:**
```solidity
constructor() { _disableInitializers(); } // implementation can never be initialized
function initialize(address o) external initializer {} // versioned `reinitializer(n)` for V2
function upgradeTo(address i) external onlyOwner {} // UUPS: auth in implementation too
```

**How to find.** `grep -rn "initialize(\|upgradeTo\|diamondCut\|delegatecall"` — for every proxy: (a) is the implementation initialized/disabled? (b) is `initialize` front-runnable on clones (Telcoin CloneableProxy, Optimism Safe, DAO Maker, 88mph NFT, CEXISWAP, Affine `upgradeTo`, 0x452E25-style)? (c) does `upgradeTo/diamondCut` have access control on *both* proxy and implementation (Pike, Aurellion Diamond re-init, Renegade re-init delegate, OpenLeverage RewardVaultDelegator re-init, WXETA facet init, SwappStaking unchecked-`transferFrom` is T7 but same family)? (d) storage-gap collision across versions (Audius, Sablier PRBProxy temp-owner + colliding plugin sigs, Beanstalk BIP-39 facet omission, Fractionalize timelock, Mellow native-withdraw brick)?

**How to exploit.** Front-run `initialize` on a fresh implementation/clone → set self as owner → `upgradeTo` malicious impl (or call privileged fns directly). One tx.

**Unique insight.** The implementation contract is a contract too — if it has an open `initialize`, the whole proxy system is already owned. Check implementations first, proxies second.

---

## T17. Self-liquidation / bad-debt / donate-to-reserves

**Definition.** Attacker engineers their own (or a victim's) liquidation/borrow to extract reserves: donate to inflate `donateToReserves`-style accounting, self-liquidate at a false price, or leave bad debt the protocol socializes.

**Root cause.** Liquidation/borrow math that lets the liquidator and borrower be the same economic actor, or reserve accounting that counts donations as profit.

**VULNERABLE (Euler `donateToReserves` $197M; Kashi stale-rate self-liquidation; DYAD self-liquidation flash-protection bypass):**
```solidity
function liquidate(address violator, ...) external {
    // no check that liquidator != violator/borrower; discount + bonus accrue to attacker
    _seize(collateral[violator]); _repay(debt[violator]); // self-deal at manipulated price
}
function donateToReserves(address u, uint amt) external { reserves[u] += amt; } // inflates share price → borrow more
```

**FIXED:**
```solidity
require(liquidator != borrower && liquidator != violatorController, "no-self");
// donations: track `donated` separately; never let donations raise borrowable collateral value in the same block (donation TWAP / same-block borrow ban).
```

**How to exploit.** Supply collateral → (donate/manipulate to inflate its value) → borrow max → trigger self-liquidation with discount → walk away with reserves. Euler: donate → self-liquidate → drain.

**How to find.** `grep -rn "liquidate\|donateToReserves\|selfLiquidat\|restructureBadDebt"` — test every liquidation path with liquidator==borrower; every reserve/donation path with same-block borrow (Euler, Kashi, DYAD, Impermax `restructureBadDebt` wipe, Radiant `rayDiv` empty-market + rounding, Silo `openLeveragePosition` reroute-to-borrow, SiloFinance 2025 `GenericRoute` arbitrary call, OpenLeverage 1inch-callback self-liquidation, Arcadia reentrant self-liquidation, ParaSpace same-tx supply→borrow + cAPE mis-accounting, UniLend health-factor self-withdraw, XCarnival withdrawn-collateral re-pledge, Frankencoin challenge/position games, Ajna pool SDK quirks, Licredity proxy-self-liquidation + afterSwap back-run + swap-and-pop + decreaseDebtShare quartet, Ostium discount-socialization + fee-routing, Folks borrow/health/mixing + utilization-guard trio, Amplify/Notional/Kinetiq/Karak/Stakehouse/Suzaku/Reserve/Renzo/RegnumAurum index-and-share families).

**Unique insight.** Liquidation is *supposed* to be adversarial — so tests rarely model the liquidator and borrower cooperating. Always add the collusion test: same EOA (or two EOAs, one tx) on both sides.

---

## T18. Reflection / deliver / dividend / rebase loops

**Definition.** Elastic/reflect tokens where `deliver()`, burn, `skim`, self-transfer, or rebase changes the global rate (`_rTotal`/`index`) without moving real value, minting phantom balance the AMM then pays out.

**Root cause.** Reflection math `balance = _rOwned * _tTotal / _rTotal` breaks when `_rTotal` shrinks (burn/deliver) while pool `_rOwned` doesn't, or rebase/dividend checkpoints go stale on transfer/join.

**VULNERABLE (HODL `deliver` reserve drain; XAI pair-to-self `skim` mint; Starlink fee-vs-`skim`):**
```solidity
function deliver(uint256 tAmount) public {
    (uint256 rAmount,,,,,) = _getValues(tAmount);
    _rOwned[msg.sender] -= rAmount; _rTotal -= rAmount; // rate up for EVERYONE incl. the pair
    _tFeeTotal += tFee; // pair's token balance now worth more → skim() extracts real WBNB
}
```

**FIXED:** Exclude the pair (and dead/zero) from reflection (`_isExcluded[pair] = true`), never let burns/delivers touch `_rTotal` for excluded balances, and snapshot dividend checkpoints on *every* balance change including mints/burns.

**How to find.** `grep -rn "deliver(\|_rTotal\|reflection\|rebase(\|index =\|distribute.*[Dd]ividend"` — then: (a) can anyone call `deliver`/burn/rebase permissionlessly (HODL, MCC, XAI, HCT, Starlink, BIGFI shrinking-without-space, OLIFE rate collapse, OUSD supply<balances, GAIN path-`balanceOf` rebase, QTN `skim`-loop rebase, BEVO/BRA/GDS/SHOCO/TINU/Thoreum/UpSwing/JumpFarm/QuantumWN/HeavensGate/FloorDAO/NeverFall/Caterpillar-value-preservation/Normie-`skim`-recycle/MINER-404/`skim`/fractional variants)? (b) does the pair earn reflections (if yes → `skim` prints money)? (c) dividend checkpoints stale on join/transfer (NovaBox join, JHY 100× CAKEDividends, OSN instant `setBalance→processAccount`, SinstakeZombie donation)? (d) rebase accounting flip on pre-credited EOA (Sperax `isContract`), rebase-mix vesting (CryptoLegacy), rebase-call staleness (NUTS oldD>newD), rebaseable-vesting unfairness, buffer-rebase staleness?

**How to exploit.** `deliver`/burn dust → pair's effective balance inflates → `skim()` the difference → repeat. Or self-transfer to double balances (SSS, APIG, GPU, LPC overwrite, DEEZNUTZ DN404, MINER 404). Capital: dust.

**Unique insight.** If the token has *any* global-rate variable and the pair is not excluded from it, assume T18 until a fork test proves otherwise. The 30-second test: `deliver(1)` (or self-transfer 1 wei) → `pair.skim()` → did anything come out?

---

## T19. ERC-404 / DN-404 / ERC-314 asymmetries

**Definition.** Hybrid NFT↔FT standards where mint/burn/transfer paths disagree on amounts, exemptions, or timing — fractional transfers mint/burn NFTs asymmetrically, `skim` re-inflates, buy-path mints at skewed prices.

**Root cause.** Two accounting systems (ERC20 balances + ERC721 supply) updated in different functions with different rounding/exemptions; AMM `sync`/`skim` interacts with only one.

**How to find.** `grep -rn "404\|ERC314\|_mintERC721\|_burnERC721\|minted.*NFT\|swap.*314"` — test: fractional transfer dust (MINER V3 asymmetry + self-transfer `skim` inflation), flash-mint NFTs → claim per-NFT airdrop → burn (EGGX), self-transfer inflation in reflection-fork (DeezNutz), unguarded vesting-proxy re-init (DN404), mint-2×-from-reserve buy skew (AIZPT314), flash-swap LP inflation via post-swapout snapshot (BIFKN314), sell-triggered pool burn (MBU/LFI-style 314s), buy-mint skew + dividend loops (tips §52), MetaDragon P404 permissionless NFT-burn→ERC20, Pandora `transferFrom` underflow.

**How to exploit.** Flash-mint the maximum NFTs (or fractional units) → claim every per-unit reward → burn/return in the same tx. Or dust-`addLiquidity` right after a flash-swap snapshot for pool-dominating LP (BIFKN314).

**Unique insight.** 404/314 tokens are *designed* exoticism — the exotic path (fractional↔NFT conversion) is where the invariant breaks. Fuzz every conversion edge with 1-wei and max-value inputs; the happy path always works.

---

*(continues — T20–T24 + appendices next)*

---

## T20. Unit / scale / math-library bugs

**Definition.** Correct formula, wrong units: wei-vs-token sums, tick spacing, sqrt/log/float helpers, fee denominators (540 sec vs 540 days), spread/impact inconsistency.

**How to find.** `grep -rn "sqrt\|log\|float\|tick\|540\|365 days\|10 **\|1e"` — verify every constant's unit in a comment + test (Gradient mixed-unit LP shares (wei+tokens summed 1:1), WECO `offsetPoints` unit mismatch, FluidLocker `getUnlockingPercentage` 540-vs-540-days ×2, Uniswap-hooks tick-misalignment infinite loop, Forte Float128 sqrt/eq/packedFloat/Ln quartet, Blueberry `szDecimals`, Elytra scale collapse, Gains spread-vs-impact, NUTS overflow feeds, VND-adjacent truncations in T13). Property-test math libs with adversarial extremes (0, 1, max, mid-range mantissas).

**Unique insight.** Math-library bugs are forever-bugs: once deployed in a shared lib (Float128, tick math), every integrator inherits them. When you audit a fork, diff the math lib against upstream first.

---

## T21. DoS / griefing / frontrunning / time-warp

**Definition.** Attacker bricks others' withdrawals/claims/votes/launches without stealing directly (or steals via the brick): unbounded loops, 1-wei donations, vote-window games, predictable randomness, gas-underestimation.

**How to find.** `grep -rn "for (\|block.timestamp\|deadline\|random\|vote\|finalize\|execute(" ` — unbounded arrays/loops (NextGen, Gridly `bringUnusedETH`, Recall compact, Timeswap tokenId collision), 1-wei sync/donate bricks (GTE graduation, Superform 1-wei clone, Harmonix 1-wei finalize, Malicious-actor 1-wei state overwrite, Stakehouse unprotected-transfer pool move), vote/finalize games (BMX double-batch unstake, BOB re-stake lock, carryVoteForward double-vote, Ammplify finalize double-count, H-1/H-4 gauge/subscribe gas + auto-vote windows, Single-holder payout grief, Remora forwarder `deleteUser`, LooksRare force-end prize steal, Megapot cap/gas games, Party veto-skip, IQ 4% win, Ajna spam + freezes, Frankencoin/DYAD liquidation denial, Rio settle-impossible, Canto gauge/vote strandings, Notional bricked withdrawals, Strata stuck withdrawals, Y2K rollover grief, Stakehouse stuck-ETH/LP families, Reserve/StRSR era wipes, RipIt/SpinLottery selection bricks, Suzaku boundary/division/double-count trio, Manifest restricted-deposit + 0-share duo, Coinflip pending-stake drain, Colbfinance deposit/withdraw loop, Multipli same-block sandwich, Statusl slasher/OOG/commit-reveal/p Pause-reward quintet, Ostium fee-receive insolvency is T17 but same test), predictable randomness (LuckyTiger, RedKeys, ATM BlindBox seed-settle, HenloKart race-cancel, Majority sessions), MEV/slippage-zero paths (Cork `amountOutMin=0` trio, Entangle DexWrapper, PresaleV5 `slot0`, StackMarket zero-slippage, Thestandard zero-slippage, `0x0dex` forged-LSAG is T9 but same money).
Time-warps: ABCCApp `addFixedDay` vesting warp, Vesting `changeStablecoin` decimal DoS, `calculatedPayout` overflow brick, Remora pledge overflow quartet, MergeTgt cap DoS, THORWallet lock-bypass + cap, Sweep premature-createPair + LayerZero irrecoverable + ERC721-bridge-fail trio, YieldFi CCIP decode-revert, Wormhole satoshi-never-credited revert, OpenLeverage 2300-stipend freeze, Pino native-ETH strand, Hyperlend first-supply, Radius expired-token ledger, Terplayer ceil-underflow, Threshold tBTC revert, Gigaverse soulbound brick, Soulbound mint/burn brick, Order-book dust/tick/link/fee GTE quartet, Backstop-tick freeze, Dust-order block, Tenbin revenue-ignores-losses + direct-deposit-mislabel + nonce-replay trio, Superform controller/receiver + cancel-accumulator + hooks-root trio, Super DCA duplicate-pool + unclamped-time duo, Superfluid Fontaine never-stops-flows, KittenSwap gauge/bribe/vote deactivation-loss octet, Remora lock-migration grief + entity-allowance + pending-payout trio, Renzo xezETH desync, Reserve custom-redemption revert, Pearl victim-share redeem, Curve-withdraw strand, Pino, Astrolab cancel-burns-other, Blueberry never-cleared-redeem + caller-vs-owner + fee-double-sub + donated-unredeemable quartet, Elytra burn-on-request + TVL-counts-pending + no-transfer-read + claimable-without-decrement + allocation-tracker quintet, Epoch forfeit-rescale, Etherspot partial-invoice lock, Euler double-count-migrated-stake, f(x) redeem-append DoS, Fluid uncapped-withdraw is T17-adjacent, Hinkal tree-full + overflow duo, Harmonix early-finalize + 1-wei-DOS duo, Hyperstable extra-power, IntentX zero-address-wipe, Karak snapshot-bricking + slash-event-revert + stale-balance duo, Kinetiq confirmWithdrawal-brick + receive-restake + precision-truncation + rate-calc + rate-unused + locked-cast + unstake-fail septet, Level heartbeat, MetaMask enforcer-bypass, Ouroboros `buildsPOL` forever-lock, Prime strategy-removal + testFinalize, Puffer partial-failure, Pyth payable/exponent, Plume payout-array, Common nonce-less sig, Connext pay-vs-credit, Discover referral, FactoryDAO blacklist-block, Abacus bond/closure/mapping/transfer quartet, Origin marketplace/finalization/migration trio, Vader mint/mintSynth/redemption trio, Streaming arbitraryCall/recoverTokens trio, THORWallet merge/cap duo, Treasury `batchRelease`, Timelock proposal-takeover + unbounded-loop duo, OUSD liquidate-ignore + transfer>balance + supply<balances + reentrant-mintMultiple quad, Pool-no-code-input, Yield-batched-flow theft, Non-module-delegatecall-success, Payable-delegatecall-value-reuse, 88mph-base-alias burn, Mass empty-account-call-success, HyVM CALLCODE-destroy, Stake-link stale-approval + insolvent-update duo, TraitForge buyer-burn/airdrop + percent + infinite-generations + cap-reset + modifier-block quintet + H-01 cross-generation mint, MuteBot front-run-bond + order-replay pair, Ajna delegation-rewards + NFT-spam + moveLiquidity-freeze duo + H-05/H-06 bucket/bankrupt duo, Connext Portal-repay + TOFT-leverageDown + Canto-lzCompose trio, Blueberry TVL + approved-withdrawal duo, Forte sqrt-revert-control + unwrap-eq-fail duo, InfiniFi gateway-balance + approve-circumvention duo, Kinetiq LST precision, DIA fee-drop, ERC20-treasury-lock, Beanstalk removeLiquidity/invariant/RO-reentrancy trio + Silo stem + facet-omission, Dhedge cross-domain-replay + too-few-tokens duo, Sudoswap re-enter-drain + locked-minOutput duo, Threshold mintList-early-return, Lucidly params-brick, LoopFi deposit-invariant, LoopVaults vesting-sandwich, SXT duplicate-signer, Unlocking-penalty formula, Swapit-helper harvest, Stake-link instant-burn-strand, Surge unstake-wipes-rewards, Shiny off-chain-underwater + blacklist-irrevocable duo, Session-key-consumed-by-other, Reduced-price-excess-trapped, Prime removed-strategy, Predictable-address front-run, Roots collateral-overwrite, Roots queueDropBoost, Sablier Flow overflow-brick, Sablier proxy temp-owner + colliding-plugins, Utopia pool-to-1 + FFIST pool-to-1wei duo, WGPT self-removeLiquidity, BBX stuck-burn, DCF pair-reserve-burn, H2O skim-self-mint, UPENG/UPeng burn-sync, SWT burn-sync is T1 but same test, VDS 5×-mint/1:1-refund, PTM public-addLiquidity, SB F external-balance-write, SamPrisonman, RNS uniform-currency-fee, LeverSIR transient-slot drain, Stake319 1R0R self-cap, MultiTransferSwap refund-loop, FlyLong balance-forger, ETHFIN holder-count, BBT registry-mint, ARK rate-limit-free burn, Binemon marketing-sweep arb, INTrospection repricing, MO self-recycling burn, CURIO DAO-suck + mint, Freedom slippageless-treasury-buy, DAO SoulMate permissionless SetToken redeem, Citadel redeem-oracle, Barley double-count-bond, Abracadabra rebase-desync + rounding-up-debt, Zoomer upfront-reward, Tapioca interest-locked-remove + pearlmit-only + force-lend + self-call-OFT + malicious-helper + Aave-locked + swapper-brick + BPT-scale + fake-BigBang + unclaimed-GLP + no-approval + solvency-share + partial-allowance + oTAP-steal + leverageDown-wrapper + portal-repay septet-plus, Beanstalk-BIP39 is T16 but same file, Collective JSON-injection + delegatee-block duo + quorum-inflation, Oku procure-pull + cancel-modify + target-execute + approval-reset + truncation quintet, DittoETH stale-`updatedAt` + closed-record-lock + `&&`-corruption + unexitable-partial + flag-override + id-65000-overwrite + front-run-flag + exit-loss + 65k-market-break nonet, Polynomial division-brick + storage-without-removal + missing-totalFunds + burnable-shorts + uneven-fees + liquidate-burn + over-hedge septet, Kangaroo naming aside, Ajna moves, MuteBot, Timeswap, Frankencoin cooldown-skip + addr0-DoS + overflow-deny + reward-drain quad, EigenLayer `++i`-misplace + heap-stale + cap-zero + unsettleable-withdrawal quad, Rio heap + self-undelegate + settle-impossible + cap-zero quad, Gondi distribute + front-run-repay + pendingWithdrawal + tokenId-check + buyout-skip + triggerFee-theft sextet, Renzo TVL-queue-balance, Notional TradeType-flip + zero-slippage-PT + batch-overlap + `uint16`-brick + 1SY==1YT + hardcoded-`use_eth` sextet, Mellow native-brick + multi-accrual + timestamp-mismatch + pre-fee-burn quad, Remora allowlist + nonce + div-mul + resolve-grief + decimals-swap + stablecoin-DoS + forwarder-wipe + payout-overflow octet, KittenSwap future-period + unset-reward + open-creation + self-reward + zero-reset + skipped-epoch + deactivation-loss + killed-replay + missing-period + carry-vote + same-block-brick + arbitrary-split duodecet, Karak unslashable + snapshot-DoS + unregistered-slash + validator-count quad, Init fillOrder-front-run + hook-no-auth + tokenOut-rewrite + 1-debt-frontrun + stuck-repay + stealable-wLP sextet, DittoETH above, Canto veRWA underflow + strand + self-lock + grief-reward quad + asD-lzCompose + dual-Tx + Portal + TOFT above, ParaSpace data-corruption + rate-on-liquidation + self-unliquidatable + lowTVL-borrow + struct-corruption + wrong-pair-value + credit-drain + recovery-bypass + `uint8`-truncate nonet, Stakehouse unstake-snapshot + stuck-bring + idleETH-loss + pre-burn-reduce + hook-unburnable + processor-theft + curator-drift + sender-DoS + lockable-rewards + GiantLP-transfer-move decet, Vultisig fee-unclaimable + index-zero-whitelist + single-sided-ILO-block trio, Serious double-`createPool` + foreign-price-init duo, Kelp dust-freeze, Notional-Lev-Kelp above, Curve `UnderlyingBurner` zero-slip sandwich, EmptySet hard-coded-maker drain, BoJ reserve-index is T12 but same week, Arcadia spot-`swapData`, Civfund forged-mint, Carson thin-reserve, Buffer direction-at-close + timestamp-unvalidated ×2 + early-lock quartet, Buffer coupon-irretrievable, BufferBinary early-lock, ApeDAO `goDead`, Bamboo permissionless-pool-siphon, AzukiDAO replay is T9 but same week, Bao donation-rate, BNO withdraw-without-debt-reset, Pawnfi unrestricted-`collectRate`, NST dangling-approve, MyAi victim-funded-`MultiSender`, `0x7657` approval-drain, Compounder `get_virtual_price`, CFC self-burn-sync, Cellframe migration-ratio, BUNN `deliver`-K-spoof, Biswap unauthorized-`migrate`, Midas near-empty-donation, DDCoin double-escrow-drain, Fantasm decimal-mint, Agave `liquidationCall`, Rikkei `setOracleData`, Rari USDC-off-ETH-feed, Gym `LiquidityMigrationV2` self-spend, Elephant Trunk-feedback + buyback, CFToken public-`_transfer`, DEUS `Swapin` + LP-misprice, WDOGE skim-sync, Zeed tri-credit-skim, Saddle virtual-price round-trip, Build low-quorum, Umbrella underflow-withdraw, OneRing missing-guard + cheap-`depositSafe`, LiFi facet-callTo, Hundred ERC-667, Bacon 1820, Auctus arbitrary-`exchange`, API3 single-report median, Poolz `getArraySum` overflow, Thena reentrant-unstake-convert, SafeMoon public-burn, Euler donate-self-liquidate is T17 but same month, DKP 100-USDT-whole-reserve, DBW 18-clone double-claim, BIGFI shrink-without-space, yToken APR-routing + bZx-donation is T5 but same week, Swapos 10-wei, Yearn-yToken is T5, Sentiment RO is T6, Silo rate-manip is T4, Sushi-RP2 callback-hijack is T2, Paribus cross-market is T6, Rubicon first-depositor + uncollateralized-last + prior-collateral-reuse + precision-leverage + bad-slippage + uncancelable + malicious-offer + migration-underpay octet, Hundred-#2 empty-market, MetaPoint wallet-`approve`, OLIFE reflection-collapse, Axioma below-market-presale).

**Triage shortcut:** for any user-facing state machine (sale/queue/vote/lock/bridge/game), run the *dirty-dozen* inputs: `0, 1, 2-wei, max, max+1, twice, front-run, back-run, same-block, other-account, other-chain, self`. One of the twelve breaks a surprising share of the 1,624.

**Unique insight.** DoS is underrated because it "doesn't steal" — but a bricked withdrawal queue + a secondary market (or a liquidation, or a settlement) converts every freeze into a discount purchase. Always ask "who profits while this is stuck?"

---

## T22. Key-compromise primitives & owner backdoors

**Definition.** The code *works as written* but hands one key the power to drain everything: owner burn/mint/tax-wallet `transferFrom`, unlimited mint on compromise, multisig with too few signers.

**How to find.** `grep -rn "onlyOwner.*mint\|onlyOwner.*burn\|taxWallet\|marketingWallet\|manager.*transferFrom\|multisig\|getSigners"` — distinguish malice (SKP `ownerBurnLiquidityPairTokens` + 96.8% whitelist treasury, SQ backdoor + self-mint rewards, Levyathan timelock-gated hijack, PAID upgrade key, Adshares minter key, AROS `claimSigner`, Ronin/Harmony multisigs, Mars-protocol style Ford) from design (tax wallets that can only receive). Red flags: owner can burn *others'* tokens (SafeMoon-style `burn(from)` public = T1+T22), tax/fee wallet coded as `transferFrom` spender (IRYSAI, MCAI), `manager` hardcode in `transferFrom` (YziAI), upgradable owner = single EOA.

**Unique insight.** Backdoors are found by reading *who can move whose money*, not by reading comments. `onlyOwner` on a function moving *user* funds is the smell; `onlyOwner` on a function moving *protocol* funds is normal. Confuse the two and you either miss the rug or flag the treasury.

---

## T23. Lending health-factor & liquidation bypass

**Definition.** Borrowers evade liquidation or corrupt the health check: stale exchange rates, `redeemFresh` cross-market reentrancy, liquidation that increases the position, disabled-lender configs still usable, dust borrows resetting indexes.

**How to find.** `grep -rn "healthFactor\|liquidat\|exchangeRate.*repay\|redeemFresh\|usageIndex\|positionIndex"` — test: self-liquidation (T17), liquidation-that-increases-position (Plutus-style H-1), stale-rate borrow (Abracadabra Kashi, Kashi-style), disabled-config reuse (Lumin H-01), double-spend post-liquidation (Lumin C-01), evade-and-bridge (LEND H-3), borrow-immediately-after-redeem (LEND), wrong-`srcToken`/wrong-balance updates (LEND liquidation family), dust-reset indexes (RegnumAurum), omitted XP (DYAD), unfailable liquidation (StabilityPool never-holds-crvUSD), 1-debt frontrun prevention (INIT), underestimation (Folks loan-health), mixing stable/variable (Folks), missing utilization guard (Folks fresh-pool), minted-unbacked-by-rounding (Monolith), interest-skipping borrows (RegnumAurum, LEND subsequent-borrows, Licredity decreaseDebtShare), avoid-interest-for-lenders (Elytra-style), self-triggered back-runs (Licredity), wrong seize amounts (LEND lToken seize), overpay-early-redeemers (LEND CoreRouter), stale-rate supply (Blueberry HyperVaultRouter missing-index + TVL inflation + fee-double-sub + never-deduct + withdraw-bypass + getRate-szDecimals sextet; Blueberry approved-withdrawals; Blueberry donated-unredeemable; Blueberry in-flight-USDC escrow), Morpho direct-borrow-misprice + collateral-inflate + reward-theft trio, Notional Dinero/PT/SYzny trio + v4 redeemNative freeze, Ajna bucket/bankrupt duo, Silo 2025 leverage-reroute, Euler HookTarget double-count, Fluid uncapped-supply-withdrawal, Gains decrease-twice + spread-escape + holding-fee trio, Hyperlend first-supply, Ostium discount/fee duo, PrimeVaults removed-strategy, ParaSpace lowTVL-borrow + recovery-bypass, Venus vTHE + zkSync wUSDM, StakeStone same-block-instantWithdraw surplus-skim, Sentiment RO, Conic RO, dForce RO, Sturdy RO, Market RO, Midas curveRO, Lodestar plvGLP, TiFi, APC, EGD, NovaX, ROE, Citadel, Barley bond-double-count, Peapods `depositFromPairedLpToken` forced-swap + `flash+bond` free-mint, Revert allowance-routing, CowSwap `envelope` maxint-`allowedLoss`, DODO fake-quoteToken + empty-`swapData` + missing-`msg.value` + output≠target + nonEVM-refund quintet, Oku procure/order/target/approval/truncation quintet, Symmio acceptMunicipal truncated, Lumin duo, Maia tail, Frankencoin quad, EigenLayer quad, Rio quad, Gondi sextet, Renzo queue-balance, Init sextet, DittoETH nonet, Polynomial septet, Ajna moves, Timeswap, MuteBot, Ajna buckets, Canto, ParaSpace nonet, Stakehouse decet, Vultisig trio, Serious duo, Kelp, Curve sandwich, EmptySet, BoJ, Arcadia, Civfund, Carson, Buffer quartet+coupon+binary, ApeDAO, Bamboo, AzukiDAO, Bao, BNO, Pawnfi, NST, MyAi, 0x7657, Compounder, CFC, Cellframe, BUNN, Biswap, Midas, DDCoin, Fantasm, Agave, Rikkei, Rari, Gym-migration, Elephant, CFToken, DEUS, WDOGE, Zeed, Saddle, Build, Umbrella, OneRing, LiFi, Hundred-667, Bacon-1820, Auctus, API3-median, Poolz-overflow, Thena-convert, SafeMoon-burn, Euler-donate, DKP-reserve, DBW-clones, BIGFI-space).

**Unique insight.** Lending code has *two* prices (collateral value, debt value) and *two* times (accrue moment, check moment). Bugs live in the four combinations. Test all four: stale-collateral×fresh-debt, fresh×stale, donated-collateral, and interest-skipping windows.

---

## T24. Stablecoin / CDP / peg games

**Definition.** Mint unbacked stablecoins (or drain their backing) via price-input games, empty-collateral `frob`, free vault closure, NAV inflation, or surplus/auction mis-math.

**How to find.** `grep -rn "frob\|mint.*stable\|peg\|NAV\|totalHoldings\|surplusAuction\|debtAuction\|stabilityPool"` — test: Maker PSM free-closure + UNIV2DAIUSDC mispriced-`frob` duo, DEI infinite-allowance `burnFrom`, Sperax pre-credited-EOA rebase flip, Overnight Synapse-NAV inflation, Zunami SDT-donation `totalHoldings`, Conic crvUSD-imbalance + ETH-spot + ETH-RO trio, Platypus insolvent-withdraw + second-hack `withdrawFromOtherAsset` + coverage-ratio-loop (BelugaDSP same gene), USM/FUM mid-price fund/defund, Liquity V2 urgent-redemption cherry-pick duo + zero-ICR strand + `amountOutMin=0` MEV trio, Open Dollar surplus-miscalc + debtless-auction duo, Frankencoin free-mint-reserve-drain + overflow-deny + cooldown-skip + addr0-DoS quad, Ajna funding-drain + voter-theft, tCDP wrong-slot drain, Vader synth-spot-drain + TWAP-collapse + arbitrary-mint duo, Streaming gov-drain, DEI-burnFrom, YDT proxyTransfer is T2 but same till, Bedrock 1:1-ETH-as-BTC mint, HYDT manipulated-`initialMint`, Resupply `exchangeRate=0` uncollateralized-borrow, crvUSD-adjacent LlamaLend band games (Curve Inverse sDOLA mass-liquidation), DRLVaultV3 self-referential-slippage minimum-out, TokenHolder `sell()`-arbitrary-call is T2 but same vault, DeltaPrime unwhitelisted-`claimReward` + cross-function is T6 but same loan, Raft `setIndex`-inflation + `divUp`, MahaLend/MetaLend/Onyx/Hundred-#2/Sonne empty-market quintet, `0VIX` vGHST-donation, CompoundFork-uSUI spot, cUNI stale-anchor discount, AMM-anchored II, UwULend median-legs, BonqDAO Tellor-cheap-stake, Inverse yvCurve-3Crypto, Lodestar plvGLP, TiFi, EGD, NovaX, ROE, Citadel, Barley-bond, Peapods-bond, MonoX self-swap, Ploutoz bZx-fork-oracle, Wault pro-rata-WEX, Popsicle no-debt-sync, Index-reweight mint/redeem, Visor delegated-`transferERC20` free-shares, Nerve stale-`baseVirtualPrice` round-trip, Grim reentrant-`depositFor`, Qubit zero-address-whitelist, Anyswap-underlying-drain, Sandbox public-burn is T8 but same week, Build-quorum is T10 but same week, Treasure-0qty is T15 but same market, Redacted-allowance is T8, Revest-FNFT is T6, Ronin-keys is T22, Auctus-`exchange` is T2, API3-median is T12, Bacon-1820 is T6, Compound-sweep is T8, Fantasm-decimal is T12, Hundred-667 is T6, LiFi-facet is T2, OneRing-guard is T6, Umbrella-underflow is T13, Build-quorum is T10.

**Unique insight.** Every stablecoin is a lending market with one collateral and a hardcoded price of $1 — so the entire T4/T5/T12/T17/T23 playbook applies with the price fixed. Audit the *backing valuation*, never the peg assertion.

---

## Appendix A. Universal Foundry PoC skeletons

**A1. Donation / share-inflation battery (T5) — run against EVERY vault/market:**
```solidity
function testDonationBattery() public {
    vault.deposit(1 wei);                       // victim seed (or use live state)
    token.transfer(address(vault), 1e24);       // donate (or skim/rebase/selfdestruct)
    vault.deposit(1 wei);                       // attacker dust at inflated rate
    vault.redeemAll();                          // profit > dust = BUG
    assertLe(profit, dust, "share-price manipulable");
}
```
**A2. Burn+sync probe (T1/T18):** `sell(1); pair.skim();` — skim proceeds = desync. Then loop `sell()` and assert pair WBNB strictly decreases with token reserve non-increasing.
**A3. Callback-auth probe (T3/T14):** call `uniswapV3SwapCallback(1,1,"")` / `pancakeCall(...)` directly from an EOA — any token movement = critical.
**A4. Arbitrary-call probe (T2):** `run([{target: token, data: transferFrom(victim, me, 1)}])` with a planted victim approval — success = critical.
**A5. Oracle-skew test (T4/T12):** flash-skew the source pool 10× → perform mint/borrow/claim → unwind. Behavior change = oracle is transactional.
**A6. Double-claim battery (T7/T15):** `claim(); claim();` + `transfer(me,me,1); claim();` + register/claim from N fresh addresses. Second payout > 0 = bug.
**A7. Sig-replay battery (T9):** replay captured sig twice / from another sender / with modified chainid. Any extra success = critical.
**A8. Self-deal battery (T17/T23):** liquidate your own position; borrow immediately after donating; vote on your own proposal with flash-delegated power.

---

## Appendix B. AI-agent hunting checklist (copy-paste prompt)

```text
For EVERY external/public function in scope, answer:
1. Who can call it? (auth modifier? initializer? anyone?)
2. What numbers does it trust? (reserves/slot0/balances/supply/rate/oracle — movable in 1 tx?)
3. What addresses does it call? (caller-chosen target/calldata? callback authenticated?)
4. What state changes AFTER an external call or token hook? (CEI? reward debt? snapshots?)
5. What happens on empty/dust/zero/duplicate input? (0 qty, 1 wei, max, twice, self-transfer?)
6. What does the signature bind? (nonce/expiry/chainid/contract/caller?)
For each YES-risky answer, write the 10-line Foundry fork test from Appendix A and run it.
A finding is REAL only with a passing PoC showing value movement. No PoC = no report.
Order: T1 sync/skim → T2 arbitrary-call → T3 callbacks → T4/T12 oracles → T5 share-math → T6 CEI/hooks → T7 double-claim → T8 modifiers → T9 sig-fields → T10 quorum/snapshot → T11 mint-side verification → T13 casts/rounding → T14 bot-callbacks → T15 sale-math → T16 init/upgrade → T17 self-deal → T18 deliver/rebase → T19 404-edges → T20 units → T21 dirty-dozen → T22 owner-moves-whose-money → T23 four price×time combos → T24 backing valuation.
```

---

## Appendix C. Report-count by family (evidence of priority)

~360 T1 · ~290 T4 · ~190 T2 · ~165 T7 · ~150 T8 · ~130 T6 · ~95 T9 · ~85 T5 · ~60 T18 · ~50 T3 · remainder across T10–T17/T19–T24. Total 1,624 reports, 2017-07 → 2026-08. Heaviest single pages: KittenSwap duodecet, Stakehouse decet, LEND-V2 icositet, Remora octet, Gondi sextet, Notional sextet, DittoETH nonet, ParaSpace nonet, Polynomial septet, Kinetiq septet, Tapioca septet-plus, Oku/DODO quintets, Statusl quintet, Elytra quintet, Blueberry sextet, GTE quartets, Ammplify nonet, Alchemix icositet, TraitForge quintet+1, Majority sessions, RipIt/SpinLottery, Suzaku trio, Tenbin trio, Superform trio, Harmonix duo, Hinkal duo, Y2K duo, Frankencoin/DYAD/EigenLayer/Rio quads+ — each a reusable checklist for its protocol genus (ve-forks, restaking, cross-chain-lending, prediction markets, perps, LSTs, 4626 vaults, launchpads, gaming/NFT-fi).

*End of guideline. Hunt in priority order, prove with PoCs, and re-run Appendix A batteries on every fork — the 1,625th report will be a repeat of one of the 24 types above.*

