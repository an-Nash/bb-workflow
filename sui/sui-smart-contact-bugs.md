# Vulnerabilities of DApps, AMMs, and DeFi Protocols Built on SUI

Below is a research-style vulnerability taxonomy for protocols built on the **Sui blockchain** using **Move**. It covers smart-contract bugs, protocol/economic attacks, AMM-specific issues, NFT/marketplace risks, oracle problems, and operational/security weaknesses.

> **Important:** Sui’s Move-based object model prevents or reduces many classic EVM vulnerabilities — for example, delegatecall storage collisions, many reentrancy patterns, and unchecked integer overflows. However, DeFi on Sui still has serious risk areas: **object ownership**, **shared-object contention**, **Programmable Transaction Block composition**, **oracle manipulation**, **AMM math**, **access control**, **admin/upgrade risk**, and **economic design flaws**.

---

# 1. High-Level Sui-Specific Risk Model

Sui differs from EVM chains in several ways that change the vulnerability landscape.

## Sui advantages

| Area | Effect |
|---|---|
| Move language | Resource-oriented, no arbitrary dynamic dispatch, stronger type safety |
| Object model | Assets are explicit objects, not just balances in a contract mapping |
| Checked arithmetic | Integer overflow/underflow usually aborts rather than silently wrapping |
| Atomic transactions | A Programmable Transaction Block either fully succeeds or fully fails |
| Immutable packages by default | Deployed packages cannot be changed unless upgradeability is explicitly configured |

## Sui-specific risk areas

| Risk Area | Why It Matters |
|---|---|
| Object ownership | Assets can become locked if sent to the wrong object/address or if withdrawal logic is missing |
| Shared objects | Shared pool objects can become congestion points or griefing targets |
| PTB composability | Attackers can combine many calls atomically: borrow, swap, manipulate, liquidate, repay |
| Dynamic fields | Misused dynamic fields can cause DoS, unauthorized state changes, or accounting errors |
| Coin/TreasuryCap handling | Mishandling `TreasuryCap` can allow infinite minting |
| Type/witness misuse | Fake tokens, incorrect type constraints, or badly designed capabilities can break protocol assumptions |
| Oracle dependence | Sui DeFi often relies on Pyth, Switchboard, pool prices, or off-chain indexers; misuse is dangerous |

---

# 2. Smart-Contract / Move Vulnerabilities

## 2.1 Missing or Broken Access Control

### Description
Sensitive functions are callable by unauthorized users.

### Examples
- Anyone can mint tokens.
- Anyone can pause the protocol.
- Anyone can change fees.
- Anyone can drain treasury.
- Anyone can upgrade the package.
- Anyone can delete a shared pool object.

### Sui relevance
In Sui Move, authorization is often implemented using:
- Capability objects
- Admin witness objects
- `TreasuryCap`
- Owned policy objects
- `tx_context::sender`
- Object ownership checks

If these are missing or incorrectly checked, the function may be publicly exploitable.

### Potential impact
- Token inflation
- Treasury theft
- Protocol shutdown
- Rug pull
- Parameter manipulation

### Mitigation
- Require capability objects for admin actions.
- Check `tx_context::sender` against authorized address or object owner.
- Use multisig or timelock for sensitive actions.
- Separate roles: minting, pausing, upgrading, fee changes.
- Add event emission for admin actions.

---

## 2.2 Incorrect Capability or Witness Design

### Description
Sui Move often uses “witness” types and capability objects to authorize actions. If the witness/capability is copyable, droppable, or not one-time, it can be abused.

### Examples
- Admin capability has `copy`, allowing unlimited duplication.
- Witness object has `drop`, allowing it to be discarded accidentally.
- One-time witness is not actually one-time.
- Capability is transferred to an unrecoverable address.
- Capability is stored in a shared object without authorization checks.

### Potential impact
- Unauthorized minting
- Unauthorized upgrades
- Loss of admin control
- Protocol takeover

### Mitigation
- Admin capabilities should usually not have `copy`.
- Use one-time witness patterns correctly.
- Avoid giving sensitive capabilities `drop` unless intended.
- Store admin capabilities in multisig-controlled accounts.
- Emit transfer events for capability changes.

---

## 2.3 Unsafe Struct Ability Configuration

Move structs can have abilities:

| Ability | Meaning |
|---|---|
| `copy` | Value can be duplicated |
| `drop` | Value can be discarded |
| `store` | Value can be stored/transferred |
| `key` | Value is an on-chain object with an ID |

### Vulnerability
Incorrect abilities can create serious bugs.

### Examples
- A receipt or claim ticket has `copy`, allowing duplicate claims.
- A token has `drop`, allowing accidental destruction.
- A non-transferable receipt has `store`, making it transferable when it should not be.
- A critical object lacks `key`, preventing proper ownership tracking.
- An asset object lacks `store`, preventing users from moving funds.

### Potential impact
- Duplicate claims
- Locked assets
- Accidental burns
- Unauthorized transfers
- Broken composability

### Mitigation
- Carefully choose abilities for each struct.
- Receipts/tickets should usually not be copyable.
- Assets intended to be transferable need appropriate abilities.
- Test ability behavior explicitly.

---

## 2.4 Type Confusion and Fake Token Types

### Description
A protocol may incorrectly trust token metadata such as name, symbol, or decimals instead of the canonical coin type.

### Sui context
Sui coins are represented as `Coin<T>`, where `T` is a unique type tied to a package ID. However, anyone can create a token with the same name or symbol.

### Examples
- A DApp displays a fake “USDC” token.
- A lending market accepts any coin with symbol “SUI”.
- A wallet UI trusts metadata instead of coin type.
- A protocol uses string comparison for token authorization.

### Potential impact
- Phishing
- Fake deposits
- UI spoofing
- Incorrect accounting
- User fund loss

### Mitigation
- Always identify tokens by canonical coin type, e.g. `0x...::usdc::USDC`.
- Maintain an on-chain or governance-controlled allowlist.
- Do not authorize assets based on symbol/name strings.
- Verify metadata through trusted registries.

---

## 2.5 Unsafe Generic Functions

### Description
Move generics are powerful, but if constraints are too loose, a function may accept unintended types.

### Examples
- A generic vault accepts any asset type.
- A generic reward distributor does not validate the reward coin type.
- A pool function accepts arbitrary witness types.
- A staking contract accepts fake receipt types.

### Potential impact
- Accounting corruption
- Fake deposits
- Unauthorized claims
- Broken invariants

### Mitigation
- Constrain generic types using witness/capability patterns.
- Validate coin types against allowlists.
- Avoid accepting arbitrary types in financial functions.
- Use phantom type parameters carefully.

---

## 2.6 Object Ownership and Transfer Mistakes

### Description
Sui assets are objects. If an object is transferred to the wrong owner, or to an object that cannot release it, funds may be locked.

### Examples
- Tokens sent to a package address.
- Tokens sent to a shared object with no withdrawal function.
- NFT sent to a contract that cannot transfer it back.
- User sends asset to an object ID instead of a wallet address.
- Protocol transfers object to `0x0` or invalid recipient.
- Withdrawal function assumes caller owns an object but does not verify correctly.

### Potential impact
- Permanent fund loss
- Locked liquidity
- Locked NFTs
- Broken withdrawals

### Mitigation
- Validate recipient addresses.
- Provide recovery functions where possible.
- Avoid requiring users to send assets manually to contract objects.
- Clearly distinguish wallet addresses and object IDs in UI.
- Test transfers to contracts, shared objects, and multisigs.

---

## 2.7 Dynamic Field Misuse

Sui supports dynamic fields and dynamic object fields.

### Vulnerability
Dynamic fields can be abused or misconfigured.

### Examples
- Unauthorized user adds/removes dynamic fields.
- Key collisions cause legitimate operations to abort.
- Unbounded dynamic fields create gas/DoS issues.
- Critical state is stored in dynamic fields without access control.
- Protocol scans dynamic fields and can be griefed by junk fields.
- Dynamic field keys are user-controlled and can cause unexpected aborts.

### Potential impact
- Denial of service
- State corruption
- Unauthorized withdrawals
- Increased gas costs
- Locked objects

### Mitigation
- Restrict who can add/remove dynamic fields.
- Use controlled key types.
- Avoid unbounded iteration over dynamic fields.
- Do not rely on scanning all child objects for accounting.
- Test field collision and removal behavior.

---

## 2.8 Shared Object Risks

### Description
Sui objects can be owned or shared. DeFi pools are often shared objects so many users can interact with them.

### Vulnerabilities
- Shared objects can be mutated by anyone if logic allows.
- Shared objects can become congestion points.
- Attackers may spam transactions against a shared object.
- Shared object deletion can break dependent protocols.
- Shared object state may be manipulated within a single PTB.

### Examples
- A shared liquidity pool object is spammed to increase latency/cost.
- A shared config object is modified by unauthorized users.
- A shared object is deleted by admin or bug, freezing dependent funds.
- A protocol assumes shared object state is stable during a transaction, but another Move call modifies it.

### Potential impact
- Denial of service
- Failed transactions
- Manipulated state
- Locked funds
- MEV extraction

### Mitigation
- Minimize shared-object mutation surface.
- Use owned objects where possible.
- Add rate limits or economic costs to shared-object interactions.
- Avoid deleting critical shared objects.
- Re-validate state after external calls.

---

## 2.9 Programmable Transaction Block Composition Attacks

### Description
Sui PTBs can call many Move functions atomically. This is powerful but dangerous if protocol invariants are only temporarily enforced.

### Example attack pattern
1. Flash-borrow assets.
2. Deposit into pool.
3. Manipulate pool price.
4. Use manipulated value as collateral.
5. Borrow another asset.
6. Reverse the swap.
7. Repay flash loan.
8. Profit from undercollateralized borrowing.

### Vulnerability
The protocol may check invariants inside one function but not at the end of the full transaction.

### Potential impact
- Price manipulation
- Collateral inflation
- Reward farming
- Liquidation manipulation
- Treasury drain

### Mitigation
- Enforce invariants at transaction boundaries.
- Use “hot potato” receipts correctly.
- Avoid relying on intermediate state.
- Model atomic multi-call attacks during testing.
- Add slippage, oracle, and collateral checks.

---

## 2.10 Hot Potato / Receipt Pattern Failures

### Description
A “hot potato” is a struct that must be consumed in the same transaction. It is often used for flash loans, temporary receipts, or proof-of-action objects.

### Vulnerabilities
- Receipt can be forged.
- Receipt can be copied.
- Receipt can be dropped.
- Receipt can be satisfied by another protocol’s receipt.
- Receipt destruction is not enforced.
- Receipt is stored instead of consumed.

### Potential impact
- Unrepaid flash loans
- Duplicate claims
- Bypassed repayment logic
- Broken atomic workflows

### Mitigation
- Receipts should generally not have `copy`, `drop`, or `store`.
- Use module-private creation/destruction.
- Bind receipts to specific protocol types.
- Test invalid receipt paths.

---

## 2.11 Entry vs Public Function Exposure

### Description
Move functions can have different visibility and entry behavior.

### Vulnerability
A function intended for internal use may be exposed publicly.

### Examples
- Internal accounting function is callable by users.
- Admin initialization function remains callable after setup.
- A helper function bypasses access control.
- A public function assumes it is only called from trusted module code.

### Potential impact
- Unauthorized state changes
- Bypassed fees
- Broken accounting
- Privilege escalation

### Mitigation
- Use the narrowest visibility possible.
- Mark user-facing functions as entry only when intended.
- Separate internal helpers from public APIs.
- Audit function visibility carefully.

---

## 2.12 Initialization Bugs

### Description
Sui modules may use an `init` function during package publication. Problems occur when initialization is incomplete, repeated, or front-runnable.

### Examples
- Critical parameters not initialized.
- Admin capability not transferred correctly.
- Initialization function callable after deployment.
- Protocol starts with unsafe default parameters.
- Initialization depends on external state not yet available.

### Potential impact
- Admin misconfiguration
- Broken markets
- Unsafe defaults
- Protocol takeover

### Mitigation
- Ensure `init` runs atomically with publish.
- Validate all parameters.
- Emit initialization events.
- Avoid post-publish initialization if possible.
- Use timelocked governance for parameter changes.

---

## 2.13 Arithmetic, Rounding, and Precision Errors

### Description
Move generally aborts on overflow/underflow, but DeFi protocols still suffer from rounding, truncation, and precision issues.

### Examples
- LP shares minted with truncation favoring attackers.
- Interest accrual rounds down consistently.
- Swap output rounds in favor of the pool but breaks user expectations.
- Division before multiplication causes precision loss.
- Very small amounts cause division-by-zero-like edge cases.
- Fixed-point math uses insufficient precision.

### Potential impact
- Value leakage
- LP exploitation
- Dust accumulation
- Insolvent pools
- Failed withdrawals

### Mitigation
- Use fixed-point math libraries carefully.
- Multiply before divide where safe.
- Define rounding direction intentionally.
- Test with tiny and huge amounts.
- Use invariant testing for solvency.

---

## 2.14 Denial-of-Service via Abort Conditions

### Description
Move functions abort when invalid conditions occur. If attackers can force aborts, legitimate users may be blocked.

### Examples
- Function iterates over an unbounded vector.
- User-supplied input causes arithmetic abort.
- Pool state becomes temporarily invalid.
- Dynamic field key collision causes abort.
- Withdrawal requires exact coin amount but coin object is split.
- Shared object is locked or congested.

### Potential impact
- Frozen withdrawals
- Failed liquidations
- Failed trades
- Increased gas costs
- Protocol downtime

### Mitigation
- Avoid unbounded loops.
- Paginate operations.
- Handle zero/dust amounts.
- Use conservative gas budgeting.
- Test adversarial inputs.

---

## 2.15 Unbounded Vectors and Gas Exhaustion

### Description
If a contract stores large vectors and loops over them, operations can become too expensive.

### Examples
- Reward distribution iterates over all users.
- Airdrop claims require scanning all claims.
- Validator/settlement logic loops over all positions.
- Marketplace cancels all listings in one transaction.

### Potential impact
- Functions become unusable.
- Admin operations fail.
- Users cannot claim or withdraw.
- Protocol becomes economically unviable.

### Mitigation
- Use pull-based claims.
- Avoid global iteration.
- Use maps/dynamic fields with bounded access.
- Design for incremental settlement.

---

## 2.16 Unsafe Randomness

### Description
Some DApps use randomness for games, NFTs, lotteries, or reward selection.

### Vulnerabilities
Using predictable or manipulable randomness:
- Transaction digest
- Timestamp
- Epoch number
- Sender address
- Object ID
- Validator-influenced values

### Potential impact
- NFT mint manipulation
- Lottery exploitation
- Game outcome prediction
- Reward farming

### Mitigation
- Use verifiable randomness where available.
- Use commit-reveal schemes if appropriate.
- Do not rely on block/tx values for high-value randomness.
- Add economic limits to random-value extraction.

---

## 2.17 Upgradeability and Admin Rug Risk

### Description
Sui packages can be immutable or upgradeable depending on upgrade capabilities.

### Vulnerabilities
- Upgrade cap controlled by a single EOA.
- No timelock.
- No multisig.
- Upgrade can change token accounting.
- Upgrade can drain funds.
- Upgrade cap not renounced when promised.

### Potential impact
- Rug pull
- Malicious logic injection
- Loss of user trust
- Total fund loss

### Mitigation
- Use multisig for upgrade authority.
- Add timelocks.
- Emit upgrade events.
- Limit upgrade scope if possible.
- Renounce upgradeability when appropriate.
- Publish audit reports and upgrade policies.

---

# 3. Coin and Token-Specific Vulnerabilities

Sui uses `Coin<T>` and `Balance<T>` for fungible tokens.

## 3.1 TreasuryCap Mismanagement

### Description
`TreasuryCap<T>` allows minting and burning of a coin type.

### Vulnerabilities
- TreasuryCap stored in insecure wallet.
- TreasuryCap not frozen or renounced.
- Mint function lacks caps.
- Mint function lacks access control.
- TreasuryCap transferred to shared object with weak authorization.

### Potential impact
- Infinite minting
- Hyperinflation
- Exchange/dex manipulation
- Total token collapse

### Mitigation
- Freeze or renounce minting when appropriate.
- Use multisig/timelock for TreasuryCap.
- Add mint caps and rate limits.
- Emit mint/burn events.

---

## 3.2 Coin Metadata Spoofing

### Description
Anyone can create a coin with a familiar name or symbol.

### Examples
- Fake `USDC`
- Fake `SUI`
- Fake project token
- Fake LP token

### Potential impact
- Phishing
- User deposits fake assets
- Wallet UI confusion
- Social engineering

### Mitigation
- Verify canonical coin type.
- Use trusted token lists.
- Display full coin type in UI.
- Warn users on unverified assets.

---

## 3.3 Zero-Value and Dust Coin Handling

### Description
Coin objects can be split and merged. Protocols may fail with zero-value or dust coins.

### Examples
- User deposits zero-value coin.
- Protocol mints zero LP shares.
- Withdrawal fails due to dust amount.
- Accounting divides by total supply when supply is zero.
- Reward distribution fails with dust balances.

### Potential impact
- Failed deposits/withdrawals
- Locked funds
- Rounding exploitation
- DoS

### Mitigation
- Reject zero amounts where appropriate.
- Handle first deposit carefully.
- Use minimum LP share minting.
- Test dust scenarios.

---

## 3.4 Balance Accounting vs Actual Coin Objects

### Description
A protocol may track balances in fields while actual coin objects differ.

### Vulnerabilities
- Accounting field does not match actual `Balance<T>`.
- Protocol assumes no external donations, but objects can be transferred.
- Fees are taken incorrectly.
- Coin objects are locked in child objects.
- Protocol scans owned coin objects instead of using internal accounting.

### Potential impact
- Insolvency
- Incorrect withdrawals
- Donation attacks
- Locked funds

### Mitigation
- Prefer internal `Balance<T>` accounting.
- Do not rely on externally donated objects.
- Reconcile accounting where possible.
- Avoid scanning arbitrary owned objects for critical logic.

---

## 3.5 Custom Token Transfer Hooks

### Description
Some protocols may implement custom assets with transfer fees, restrictions, or rebasing behavior.

### Vulnerabilities
- Protocol assumes 1:1 transfer amount.
- Fee-on-transfer tokens break accounting.
- Rebasing tokens desynchronize balances.
- Restricted tokens cannot be liquidated.

### Potential impact
- Bad debt
- Failed liquidations
- Pool insolvency

### Mitigation
- Support only standard `Coin<T>` assets unless explicitly designed otherwise.
- Measure received amount after transfer.
- Maintain allowlists.
- Avoid rebasing tokens in lending pools.

---

# 4. AMM-Specific Vulnerabilities

AMMs on Sui are exposed to both smart-contract bugs and economic attacks.

---

## 4.1 Constant Product Math Errors

### Description
Most AMMs use `x * y = k` or a related invariant.

### Vulnerabilities
- Incorrect fee calculation.
- Rounding favors attacker.
- Output amount not checked against minimum.
- Reserve updates occur before/after fees incorrectly.
- K invariant not preserved.
- Swap amount exceeds reserve.

### Potential impact
- Pool drainage
- Value leakage
- Failed swaps
- LP losses

### Mitigation
- Use audited AMM math.
- Enforce minimum output amounts.
- Define rounding direction safely.
- Test edge cases: tiny swaps, huge swaps, empty pool, single-sided liquidity.

---

## 4.2 Slippage and Minimum Output Failures

### Description
If a DApp does not enforce slippage protection, users can receive far less than expected.

### Attack
- Attacker front-runs a large swap.
- Victim swap executes at bad price.
- Attacker back-runs for profit.

### Potential impact
- Sandwich attacks
- Poor execution price
- User fund loss

### Mitigation
- Require user-defined minimum output.
- Show price impact clearly.
- Use slippage defaults conservatively.
- Consider private order flow or batching where appropriate.

---

## 4.3 First Depositor / LP Share Inflation Attack

### Description
In some AMM designs, the first liquidity deposit determines initial LP supply. Attackers may manipulate this.

### Attack pattern
1. Attacker deposits minimal liquidity.
2. Attacker inflates pool reserves through donation or manipulation.
3. LP share pricing becomes distorted.
4. Later depositors receive incorrect shares.

### Potential impact
- LP share inflation
- Loss for depositors
- Pool manipulation

### Mitigation
- Use minimum initial LP mint.
- Use virtual reserves or virtual supply.
- Prevent direct donation from affecting accounting.
- Test first-deposit edge cases.

---

## 4.4 Donation / Reserve Manipulation

### Description
If pool accounting can be affected by directly sending assets to the pool, attackers may manipulate reserves.

### Sui relevance
Sui objects can own other objects. If a pool incorrectly treats externally received coin objects as reserves, it may be manipulable.

### Potential impact
- Price manipulation
- LP share distortion
- Oracle manipulation
- Reward manipulation

### Mitigation
- Use internal `Balance<T>` fields.
- Ignore externally donated objects for pricing.
- Do not compute reserves by scanning arbitrary child objects.

---

## 4.5 Using AMM Spot Price as Oracle

### Description
Using a pool’s instantaneous price as a price oracle is dangerous.

### Attack
1. Attacker flash-borrows assets.
2. Swaps large amount to move pool price.
3. Protocol reads manipulated price.
4. Attacker borrows/liquidates/claims based on fake price.
5. Attacker reverses swap.

### Potential impact
- Lending insolvency
- Liquidation manipulation
- Reward exploitation
- Stablecoin depeg attacks

### Mitigation
- Use external oracles such as Pyth or Switchboard.
- Use TWAP with sufficient window.
- Combine multiple sources.
- Add circuit breakers.
- Do not use low-liquidity pool prices for collateral valuation.

---

## 4.6 TWAP Manipulation

### Description
TWAP is safer than spot price but still manipulable under certain conditions.

### Vulnerabilities
- TWAP window too short.
- Liquidity too low.
- Attacker can maintain skewed price across multiple observations.
- Observation updates are infrequent.
- TWAP source is a single pool.

### Potential impact
- Gradual price manipulation
- Collateral overvaluation
- Incorrect liquidations

### Mitigation
- Use longer TWAP windows.
- Use deep liquidity pools.
- Combine with external oracles.
- Monitor deviation between spot and TWAP.

---

## 4.7 Add/Remove Liquidity Proportionality Errors

### Description
Adding or removing liquidity must preserve pool ownership proportions.

### Vulnerabilities
- Single-sided withdrawal allowed incorrectly.
- LP burn does not return proportional assets.
- Rounding favors remover.
- Fees not accounted for during removal.
- LP supply tracked incorrectly.

### Potential impact
- LP theft
- Pool insolvency
- Impermanent loss amplification
- Value leakage

### Mitigation
- Enforce proportional deposit/withdrawal.
- Use audited LP mint/burn formulas.
- Test edge cases with fees and dust.

---

## 4.8 Fee Calculation Bugs

### Description
Fees may be calculated incorrectly.

### Examples
- Swap fee not deducted before output calculation.
- Protocol fee and LP fee confused.
- Fee accumulator overflows or truncates.
- Fee withdrawal drains pool.
- Fee switch can be changed without governance.

### Potential impact
- LP losses
- Protocol revenue loss
- Pool insolvency

### Mitigation
- Separate LP fees from protocol fees.
- Use fixed-point math.
- Cap fees.
- Governance-control fee changes.

---

## 4.9 Stableswap / Multi-Asset Invariant Bugs

### Description
Stableswap-style AMMs use more complex invariants involving amplification parameters.

### Vulnerabilities
- Incorrect amplification parameter.
- Newton-Raphson iteration fails or converges incorrectly.
- Rounding errors in large balances.
- Imbalanced pools cause unstable pricing.
- Amplification changes are manipulated.

### Potential impact
- Depeg amplification
- Pool drainage
- Bad trades
- Liquidation cascades

### Mitigation
- Use battle-tested stableswap math.
- Bound amplification parameters.
- Test extreme imbalance scenarios.
- Add pause/circuit breaker.

---

## 4.10 MEV, Front-Running, and Sandwich Attacks

### Description
Sui can still have MEV, especially around shared objects and transaction ordering.

### Vulnerabilities
- Large swaps are visible before execution.
- Liquidations can be front-run.
- Shared pool transactions can be ordered advantageously.
- Bots can sandwich user transactions.

### Potential impact
- Worse user execution
- Extracted value
- Liquidation manipulation

### Mitigation
- Slippage protection.
- Private transaction submission where possible.
- Batch auctions.
- MEV-aware protocol design.
- Monitor mempool/RPC leakage.

---

# 5. Lending / Money Market Vulnerabilities

Although your question mentions DApp/AMM/DeFi generally, lending markets are a major DeFi category.

## 5.1 Oracle Manipulation

### Vulnerabilities
- Stale price feeds.
- Wrong feed ID.
- Incorrect decimals/exponent.
- Ignoring confidence interval.
- Using pool price as oracle.
- No fallback oracle.

### Impact
- Undercollateralized borrowing
- Wrong liquidations
- Bad debt

### Mitigation
- Use Pyth/Switchboard correctly.
- Check staleness and status.
- Normalize decimals.
- Use confidence intervals.
- Add circuit breakers.

---

## 5.2 Health Factor / Liquidation Math Errors

### Vulnerabilities
- Liquidation threshold calculated incorrectly.
- Rounding favors borrower or liquidator excessively.
- Liquidation bonus drains collateral too quickly.
- Partial liquidation logic broken.
- Liquidations fail during high volatility.

### Impact
- Bad debt
- Unfair liquidations
- Protocol insolvency

### Mitigation
- Formalize health factor invariants.
- Test volatile price scenarios.
- Use conservative liquidation parameters.
- Allow partial liquidations.

---

## 5.3 Interest Rate Model Bugs

### Vulnerabilities
- Interest accrual overflow.
- Time manipulation.
- Incorrect compounding.
- Rate curve misconfiguration.
- Utilization rate division by zero.
- Interest not updated before borrow/repay.

### Impact
- Incorrect debt
- Insolvent markets
- Reward manipulation

### Mitigation
- Update interest indexes before state changes.
- Use fixed-point math.
- Cap rates.
- Test extreme utilization.

---

## 5.4 Flash Loan Collateral Attacks

### Description
Because Sui transactions are atomic, an attacker can borrow, deposit, borrow against collateral, and repay within one transaction.

### Vulnerability
Protocol may treat deposited assets as valid collateral before ensuring the full transaction is solvent.

### Impact
- Uncollateralized extraction
- Price manipulation
- Liquidation manipulation

### Mitigation
- Enforce solvency at transaction end.
- Prevent same-block/same-tx borrowing against freshly deposited volatile collateral if needed.
- Use oracle-based pricing, not pool spot pricing.

---

## 5.5 Borrow/Supply Cap Failures

### Vulnerabilities
- Caps not enforced.
- Caps can be changed by unauthorized users.
- Caps are checked before manipulation but not after.
- Caps use stale exchange rates.

### Impact
- Excessive exposure
- Oracle attack amplification
- Insolvency

### Mitigation
- Enforce caps atomically.
- Governance-controlled cap changes.
- Monitor utilization.

---

# 6. NFT / Marketplace / DApp Vulnerabilities

## 6.1 Listing Authorization Bugs

### Vulnerabilities
- Anyone can cancel someone else’s listing.
- Seller can withdraw NFT after sale.
- Buyer can claim NFT without paying.
- Listing object is not properly owned/escrowed.

### Impact
- NFT theft
- Failed settlements
- Marketplace insolvency

### Mitigation
- Escrow NFTs in marketplace objects.
- Verify seller ownership.
- Verify payment before transfer.
- Emit listing events.

---

## 6.2 Price and Payment Type Confusion

### Vulnerabilities
- Listing price uses wrong coin type.
- Buyer pays with fake token.
- Decimals mismatch.
- Price is zero due to uninitialized field.
- Payment is sent to wrong recipient.

### Impact
- Loss of seller proceeds
- Fake purchases
- UI spoofing

### Mitigation
- Canonical coin type checks.
- Explicit decimal handling.
- Reject zero/negative prices.
- Use escrow.

---

## 6.3 Royalty / Transfer Policy Bypass

### Sui context
Sui has transfer policies and Kiosk-style marketplace infrastructure, but misconfiguration can bypass intended restrictions.

### Vulnerabilities
- Transfer policy not enforced.
- Royalty enforcement optional.
- Kiosk lock misconfigured.
- Marketplace ignores policy rules.
- NFT can be transferred outside intended marketplace.

### Impact
- Royalty evasion
- Broken collection rules
- Marketplace fragmentation

### Mitigation
- Use standard transfer policy infrastructure.
- Test policy enforcement.
- Audit Kiosk integration.
- Clearly communicate enforceability to users.

---

## 6.4 Fake Collections and Metadata Spoofing

### Vulnerabilities
- Fake NFT collection with same name/image.
- Off-chain metadata mutable.
- Image URI controlled by attacker.
- Collection not verified.

### Impact
- Phishing
- User purchases worthless assets
- Brand damage

### Mitigation
- Verify collection publishers.
- Use immutable metadata where possible.
- Display collection ID.
- Maintain trusted registries.

---

## 6.5 Auction Timing Manipulation

### Vulnerabilities
- No anti-sniping mechanism.
- Timestamp dependence.
- Bid cancellation abuse.
- Minimum bid increment not enforced.
- Auction settlement not atomic.

### Impact
- Unfair auctions
- Bid theft
- Failed settlement

### Mitigation
- Add anti-sniping extensions.
- Enforce bid increments.
- Escrow bids.
- Use reliable time sources cautiously.

---

# 7. Oracle Vulnerabilities

## 7.1 Stale Price Feeds

### Description
Oracle price updates may be stale.

### Impact
- Incorrect liquidations
- Bad collateral valuation
- Arbitrage exploitation

### Mitigation
- Check update time.
- Reject stale prices.
- Use heartbeat-aware feeds.

---

## 7.2 Wrong Feed ID

### Description
Using the wrong price feed ID can cause catastrophic mispricing.

### Examples
- Using testnet feed on mainnet.
- Using ETH/USD instead of SUI/USD.
- Using deprecated feed.

### Mitigation
- Hardcode verified feed IDs.
- Use governance-controlled feed registry.
- Validate feed metadata.

---

## 7.3 Incorrect Decimals / Exponent Handling

### Description
Pyth and other oracles may use exponents.

### Vulnerability
Protocol treats price as integer without adjusting exponent.

### Impact
- Massive mispricing
- Insolvency

### Mitigation
- Normalize all prices to common decimals.
- Test with real oracle payloads.

---

## 7.4 Ignoring Confidence Intervals

### Description
Some oracle prices include confidence values.

### Vulnerability
Protocol uses price even when confidence is too wide.

### Impact
- Manipulated or uncertain pricing accepted.

### Mitigation
- Reject prices with excessive confidence interval.
- Use conservative price bounds.

---

## 7.5 Single Oracle Dependency

### Vulnerability
One oracle failure compromises protocol.

### Mitigation
- Use multiple sources.
- Add fallback logic.
- Pause on large deviation.

---

# 8. Governance Vulnerabilities

## 8.1 Flash Loan Governance Attacks

### Description
If voting power is based on current token balance, attackers may borrow tokens to vote.

### Impact
- Malicious proposals pass.
- Treasury drained.
- Parameters changed.

### Mitigation
- Snapshot voting power.
- Require voting escrow or staking.
- Add timelocks.
- Use quorum and veto guards.

---

## 8.2 Proposal Execution Bugs

### Vulnerabilities
- Proposal can execute arbitrary calls.
- Proposal bypasses timelock.
- Proposal payload not validated.
- Admin capability transferred without review.

### Mitigation
- Restrict proposal actions.
- Use timelocks.
- Emit proposal payloads.
- Require multisig execution.

---

## 8.3 Low Participation / Quorum Manipulation

### Vulnerabilities
- Quorum too low.
- Whale dominance.
- Voter apathy exploited.

### Mitigation
- Reasonable quorum.
- Timelocks.
- Emergency veto.
- Transparent voting dashboards.

---

# 9. Bridge and Cross-Chain Vulnerabilities

If a Sui DeFi protocol uses bridges, additional risks apply.

## 9.1 Message Replay

### Vulnerability
A cross-chain message is processed more than once.

### Impact
- Duplicate minting
- Double withdrawals

### Mitigation
- Track processed nonces.
- Use unique message IDs.
- Validate source chain/domain.

---

## 9.2 Insufficient Finality Checks

### Vulnerability
Protocol accepts source-chain transactions before finality.

### Impact
- Reorg-based minting
- Invalid deposits

### Mitigation
- Require sufficient confirmations.
- Use finality-aware relayers.

---

## 9.3 Multisig / Validator Compromise

### Vulnerability
Bridge minting controlled by weak multisig.

### Impact
- Infinite minting
- Treasury theft

### Mitigation
- High threshold multisig.
- Hardware wallets.
- Timelocks.
- Rate limits.

---

## 9.4 Lock/Mint Accounting Errors

### Vulnerability
Minted assets exceed locked assets.

### Impact
- Bridge insolvency

### Mitigation
- On-chain accounting.
- Supply caps.
- Regular proofs-of-reserve.

---

# 10. Denial-of-Service and Availability Risks

## 10.1 Shared Object Congestion

### Description
Popular DeFi pools are shared objects. High demand can cause contention.

### Impact
- Delayed transactions
- Higher costs
- Failed liquidations
- Poor UX

### Mitigation
- Shard liquidity where possible.
- Use owned-object flows when possible.
- Optimize shared-object access.

---

## 10.2 Transaction Spam / Griefing

### Vulnerability
Attackers spam a shared object or protocol function.

### Impact
- Legitimate users delayed.
- Validators burdened.
- Protocol appears down.

### Mitigation
- Economic costs.
- Rate limiting.
- Monitoring.
- Adaptive fees.

---

## 10.3 RPC / Indexer Dependency

### Vulnerability
DApps rely on off-chain indexers for balances, prices, or history.

### Impact
- Incorrect UI.
- Failed transactions.
- Manipulated displays.
- Phishing through stale data.

### Mitigation
- Use multiple RPC/indexer providers.
- Validate critical data on-chain.
- Show sync status.

---

# 11. Wallet, Client, and User-Facing Vulnerabilities

## 11.1 Transaction Preview Spoofing

### Vulnerability
DApp shows one action but requests another signature.

### Impact
- User signs malicious transaction.
- Asset theft.

### Mitigation
- Transparent transaction previews.
- Human-readable PTB decoding.
- Wallet-level simulation.

---

## 11.2 Malicious Object Injection

### Vulnerability
Users may be prompted to interact with malicious objects.

### Impact
- Phishing.
- Approval-like confusion.
- Loss of NFTs/tokens.

### Mitigation
- Verify object IDs.
- Warn on unverified contracts.
- Use allowlists.

---

## 11.3 Fake Token/NFT Phishing

### Vulnerability
Attackers create fake tokens/NFTs with legitimate-looking metadata.

### Impact
- Users interact with fake assets.
- Funds lost.

### Mitigation
- Verified token lists.
- Collection verification.
- Full type/address display.

---

## 11.4 Sponsored Transaction Abuse

### Description
Sui supports transaction sponsorship, allowing apps to pay gas.

### Vulnerabilities
- Sponsorship backend signs arbitrary transactions.
- No rate limits.
- No action allowlist.
- Attacker drains sponsor gas budget.

### Impact
- Gas sponsorship wallet drained.
- Abuse of gasless features.

### Mitigation
- Restrict sponsored transaction types.
- Rate limit users.
- Simulate transactions before signing.
- Use spending caps.

---

# 12. Operational and Infrastructure Vulnerabilities

## 12.1 Private Key Compromise

### Vulnerability
Admin, treasury, multisig signer, or backend keys compromised.

### Impact
- Fund theft
- Malicious upgrades
- Treasury drain

### Mitigation
- Hardware wallets.
- Multisig.
- Least privilege.
- Key rotation.
- Monitoring.

---

## 12.2 Dependency / Supply Chain Risk

### Vulnerability
Protocol depends on third-party Move packages.

### Impact
- Vulnerable dependency exploited.
- Malicious package version.

### Mitigation
- Pin dependencies.
- Audit dependencies.
- Use trusted publishers.
- Review package IDs.

---

## 12.3 Configuration Drift

### Vulnerability
Mainnet configuration differs from testnet/audit version.

### Examples
- Wrong oracle feed.
- Wrong admin address.
- Wrong fee parameter.
- Wrong coin type.

### Mitigation
- Infrastructure-as-code.
- On-chain config verification.
- Deployment checklists.

---

## 12.4 Monitoring and Incident Response Gaps

### Vulnerability
Protocol lacks alerts for abnormal behavior.

### Impact
- Exploit continues unchecked.
- Delayed response.

### Mitigation
- Monitor large mint/burn.
- Monitor oracle deviations.
- Monitor liquidity changes.
- Monitor admin actions.
- Have pause/emergency plan.

---

# 13. Economic Design Vulnerabilities

## 13.1 Unsustainable Incentives

### Vulnerability
Rewards exceed real yield.

### Impact
- Token dump.
- Liquidity flight.
- Death spiral.

### Mitigation
- Model token emissions.
- Use real yield where possible.
- Add vesting.

---

## 13.2 Liquidity Fragmentation

### Vulnerability
Too many pools split liquidity.

### Impact
- High slippage.
- Easier manipulation.
- Poor UX.

### Mitigation
- Consolidate canonical pools.
- Incentivize deep liquidity.

---

## 13.3 Impermanent Loss Misunderstanding

### Vulnerability
Users deposit without understanding LP risk.

### Impact
- User losses.
- Reputation damage.

### Mitigation
- Clear UI warnings.
- LP analytics.
- Risk disclosures.

---

## 13.4 Liquidation Spiral Risk

### Vulnerability
Lending protocols may suffer cascades during volatility.

### Impact
- Bad debt.
- Fire sales.
- Depeg events.

### Mitigation
- Conservative collateral factors.
- Circuit breakers.
- Debt limits.
- Stability pools.

---

# 14. Sui-Specific Attack Scenarios

## Scenario A: Atomic Pool Price Manipulation

1. Attacker flash-borrows large asset amount.
2. Swaps into low-liquidity Sui pool.
3. Pool spot price becomes distorted.
4. Lending protocol reads distorted price.
5. Attacker borrows against overvalued collateral.
6. Attacker reverses swap.
7. Attacker repays flash loan.
8. Protocol left with bad debt.

### Key weakness
Using manipulable spot price or weak oracle.

---

## Scenario B: Shared Object Griefing

1. Popular AMM pool is a shared object.
2. Attacker submits many low-value transactions.
3. Legitimate swaps queue behind attacker transactions.
4. Users experience delays or failed transactions.

### Key weakness
Shared-object contention and lack of economic throttling.

---

## Scenario C: TreasuryCap Theft

1. Admin TreasuryCap stored in single EOA.
2. EOA private key compromised.
3. Attacker mints unlimited tokens.
4. Attacker dumps into liquidity pools.

### Key weakness
Centralized admin key management.

---

## Scenario D: Fake Coin Phishing

1. Attacker creates token named “USDC”.
2. Wallet displays symbol “USDC”.
3. User deposits fake token into DApp.
4. DApp credits value incorrectly if it trusts symbol.

### Key weakness
Token identification by metadata instead of canonical type.

---

## Scenario E: Dynamic Field DoS

1. Protocol stores user positions in dynamic fields.
2. Attacker creates many junk fields or causes key collisions.
3. Protocol function iterates over fields.
4. Function becomes too expensive or aborts.

### Key weakness
Unbounded iteration and poor dynamic field design.

---

## Scenario F: LP Share Rounding Exploit

1. Pool has low liquidity or manipulated reserves.
2. Attacker exploits rounding in LP mint/burn.
3. Attacker extracts value from LPs.

### Key weakness
Imprecise LP accounting.

---

# 15. Vulnerability Summary Table

| # | Vulnerability | Category | Severity | Sui Relevance |
|---|---|---|---|---|
| 1 | Missing access control | Smart contract | Critical | High |
| 2 | TreasuryCap misuse | Token | Critical | High |
| 3 | Oracle manipulation | DeFi | Critical | High |
| 4 | AMM spot price used as oracle | AMM/DeFi | Critical | High |
| 5 | PTB atomic composition attacks | Sui-specific | High | High |
| 6 | Shared object griefing | Sui-specific | Medium/High | High |
| 7 | Dynamic field DoS | Sui-specific | Medium/High | High |
| 8 | Object ownership/locked funds | Sui-specific | High | High |
| 9 | Fake coin/NFT metadata spoofing | Token/UI | Medium/High | High |
| 10 | LP share inflation | AMM | High | Medium |
| 11 | Slippage/sandwich attacks | AMM/MEV | Medium/High | Medium |
| 12 | Rounding/precision errors | DeFi math | High | High |
| 13 | Unsafe struct abilities | Move | High | High |
| 14 | Capability/witness misuse | Move | Critical | High |
| 15 | Upgradeability rug pull | Governance | Critical | Medium |
| 16 | Flash loan attacks | DeFi | High | High |
| 17 | Liquidation math bugs | Lending | High | Medium |
| 18 | Interest rate model bugs | Lending | High | Medium |
| 19 | Governance flash loan attacks | Governance | High | Medium |
| 20 | Bridge replay/mint errors | Cross-chain | Critical | Medium |
| 21 | Sponsored tx abuse | Wallet/backend | Medium | High |
| 22 | RPC/indexer manipulation | Off-chain | Medium | Medium |
| 23 | Unbounded vectors/gas DoS | Smart contract | Medium/High | High |
| 24 | Randomness manipulation | DApp | Medium | Medium |
| 25 | NFT escrow/listing bugs | Marketplace | High | Medium |

---

# 16. Security Checklist for Sui DeFi Protocols

## Smart Contract Checklist

- [ ] All admin functions require capability or authorized sender.
- [ ] Admin capabilities are not copyable unless intended.
- [ ] TreasuryCap is secured, frozen, or renounced where appropriate.
- [ ] Token types are validated by canonical type, not symbol.
- [ ] Struct abilities are intentionally chosen.
- [ ] Receipts/hot potatoes cannot be forged, copied, or dropped.
- [ ] Public/entry function visibility is minimized.
- [ ] Dynamic fields are access-controlled.
- [ ] No unbounded loops over user-controlled collections.
- [ ] Arithmetic rounding direction is explicit.
- [ ] Zero/dust amounts are handled.
- [ ] Object transfers validate recipients.
- [ ] Upgrade authority uses multisig/timelock.
- [ ] Events emitted for sensitive actions.

---

## AMM Checklist

- [ ] Swap output has minimum slippage protection.
- [ ] Pool math preserves invariant.
- [ ] Fees are calculated correctly.
- [ ] LP mint/burn is proportional.
- [ ] First deposit attack mitigated.
- [ ] Pool price not used as sole oracle.
- [ ] TWAP window is sufficiently long.
- [ ] Liquidity concentration monitored.
- [ ] Donation attacks do not affect accounting.
- [ ] MEV risks are documented.

---

## Oracle Checklist

- [ ] Feed IDs verified.
- [ ] Decimals/exponents normalized.
- [ ] Staleness checks enforced.
- [ ] Confidence intervals checked.
- [ ] Fallback oracle exists.
- [ ] Circuit breaker on extreme deviation.
- [ ] Oracle source governance-controlled.

---

## Operational Checklist

- [ ] Multisig for admin keys.
- [ ] Hardware wallets for signers.
- [ ] Monitoring for mint/burn anomalies.
- [ ] Monitoring for oracle deviations.
- [ ] Emergency pause mechanism.
- [ ] Incident response plan.
- [ ] Bug bounty program.
- [ ] Dependency/package ID verification.
- [ ] Deployment configuration review.
- [ ] Regular audits and invariant testing.

---

# 17. Conclusion

The most important vulnerability categories for Sui-based DApps, AMMs, and DeFi protocols are:

1. **Access control and admin capability misuse**
2. **Oracle and price manipulation**
3. **AMM math and LP accounting errors**
4. **Atomic PTB composition attacks**
5. **Shared-object congestion and griefing**
6. **Dynamic field and object ownership mistakes**
7. **Fake token/NFT metadata spoofing**
8. **Unsafe Move struct ability design**
9. **Upgradeability and governance risks**
10. **Operational security failures**

Sui’s Move language and object model improve safety compared with many EVM-style environments, but they do not eliminate DeFi risk. The strongest protocols combine **formal invariant testing**, **audits**, **oracle robustness**, **economic limits**, **monitoring**, and **secure key/governance management**.
