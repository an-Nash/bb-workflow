---
name: sui-move-vulnerability-hunting
description: >
  Comprehensive vulnerability hunting skill for Sui Move smart contracts
  (DApps, AMMs, DeFi protocols). Covers root causes, vulnerable code patterns,
  exploitation vectors, unique insights, detection heuristics, and bounty-verified
  findings derived from real-world audits and paid bug bounty reports. Activates
  on .move files and Sui package directories.
version: 2.0.0
author: Security Research
tags:
  - sui
  - move
  - defi
  - smart-contract
  - bug-bounty
  - vulnerability-hunting
  - bounty-verified
triggers:
  - "*.move"
  - "Move.toml"
  - "sui move build"
  - "Sui DeFi"
  - "AMM Move"
---
```

## Overview

Sui Move eliminates entire vulnerability classes that plague Solidity (reentrancy, unchecked arithmetic overflow, dynamic dispatch exploits). However, real-world audits and **paid bug bounty reports** reveal that **subtle logic errors, reference semantics misunderstandings, access control misconfigurations, and object-model-specific pitfalls** remain exploitable and have led to losses exceeding **$200M+** (Cetus) and **$1.1M+** (Aftermath Finance).

This skill covers **15 critical vulnerability categories** observed in production Sui Move protocols. For each category, it provides the root cause, vulnerable code patterns, exploitation methodology, unique insights, **bounty-verified case studies**, and detection heuristics.

**Critical principle:** Move's type system guarantees what *type* a value is, but it does **not** verify that the value's **business meaning** matches what the code assumes. Every vulnerability below exploits this gap.

**Bounty-verified protocol note:** The Sui Foundation’s bug bounty program has paid out over **$2.37 million** in cumulative rewards since its launch in April 2023, progressively expanding scope from core consensus to Bridge infrastructure and, in March 2026, the new **bella-ciao VM**. The program currently offers up to **$500,000** for critical findings and $1,000,000 for VM-related critical vulnerabilities. HackenProof now secures **more than 80% of the Move market**, with 25+ Sui ecosystem projects relying on its triage services.

---

## Category 1: Reference vs. Value Assignment (Pointer Reassignment)

### Root Cause

In Move, destructuring a `&mut Struct` creates **references (pointers)** to fields, not values. The assignment operator (`=`) on a reference **reassigns the pointer itself**, not the value it points to. Developers coming from Solidity (where assignment copies values) misread `left = limit` as "copy limit's value into left" when it actually makes `left` point to the same storage location as `limit`, corrupting subsequent writes.

### Vulnerable Code Pattern

```move
public fun mint_and_transfer(
    treasury: &mut Treasury,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext
) {
    let MinterCap { limit, epoch, mut left } = get_cap_mut(treasury, ctx.sender());
    // limit, epoch, left are all &mut u64 (POINTERS)

    if (ctx.epoch() > *epoch) {
        left = limit;           // ❌ WRONG: left now points to limit's storage
        *epoch = ctx.epoch();
    };
    assert!(amount <= *left, EMintLimitExceeded);
    *left = *left - amount;     // This modifies MinterCap.limit, not .left!
    // ... mint tokens ...
}
```

**Correct version:** `*left = *limit;`

### Exploitation

1. Attacker calls `mint_and_transfer` after epoch boundary.
2. The `left` pointer is redirected to `limit`'s storage location.
3. The subsequent `*left = *left - amount` subtracts from `limit` instead of `left`.
4. The mint limit check passes indefinitely because `left` was never decremented at its intended location.
5. Attacker mints unlimited tokens.

### Unique Insights

- **Mental model trap:** In Solidity, `left = limit` copies a value. In Move, it reassigns a pointer. The compiler does **not** warn about this because both sides are `&mut u64` and the assignment is type-valid.
- **Detection heuristic:** Search for patterns where a `mut` variable destructured from a `&mut` struct is assigned another reference variable **without** the `*` dereference operator. Every assignment to a reference-typed variable should use `*var = *other_var` to modify the pointed-to value.
- **Bounty-verified impact:** Lombard Finance audit finding — minting permanently broken.

### Bug Bounty Hunting Checklist

- [ ] Destructure `&mut` structs and trace every assignment to reference-typed locals
- [ ] Flag `ref_var = other_ref_var` (no `*`) as suspicious
- [ ] Verify the `*` operator is used on both sides: `*ref_var = *other_ref_var`
- [ ] Check if `mut` is used in destructuring patterns (`let S { mut x } = ...`)

---

## Category 2: Type Parameter Mismatch (Generic Type Confusion)

### Root Cause

Move's generics guarantee **type safety** but not **type correctness for business logic**. A function generic over `CoinType` will accept **any** `Coin<CoinType>`, even if the function's internal logic (e.g., pool selection, fee calculation) assumes a specific coin type. If the function does not validate that the provided type parameter matches the expected configuration, an attacker can substitute a different coin type to steal funds.

### Vulnerable Code Pattern

```move
public fun deposit<CoinType>(
    pool: &mut Pool,
    coin: Coin<CoinType>,
    ctx: &mut TxContext
) {
    // Missing: assert!(type_name::get<CoinType>() == pool.expected_coin_type);
    let value = coin::value(&coin);
    let shares = value * pool.total_shares / pool.total_deposits;
    // ... credit shares to sender ...
    coin::put(&mut pool.balance, coin);  // Stores wrong coin type!
}
```

### Exploitation

1. Attacker identifies a function that is generic over `CoinType` but does not validate the type against the pool's expected configuration.
2. Attacker creates a worthless `Coin<ScamCoin>` with the same decimal precision.
3. Attacker deposits `ScamCoin` into a pool configured for `SUI`.
4. The pool credits shares based on the deposited value (which may be inflated arbitrarily since the attacker controls `ScamCoin`).
5. Attacker withdraws real `SUI` using the inflated shares.

### Unique Insights

- **The "type safety ≠ type correctness" gap:** Move guarantees you have a `Coin<X>`, not that `X` is the right coin for this context. Business logic must perform the validation.
- **Detection heuristic:** For every generic function, check whether the `CoinType` parameter is validated against a stored type descriptor (e.g., `TypeName`, `type_info::type_of<CoinType>()`, or a whitelist). If not, it's a candidate.
- **Bounty-verified impact:** Navi Protocol — attacker stole funds via wrong pool by substituting a type parameter.
- **Combined with PTBs:** An attacker can use a Programmable Transaction Block to construct a `Coin<Fake>` and pass it to the generic function in the same transaction, bypassing any front-end restrictions.
- **Aptos type-confusion (adjacent ecosystem):** Hexens identified a “stale-cache bug” leading to a type-confusion vulnerability in Aptos Move that could have exposed ~$70 billion in assets.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all functions with generic `CoinType` or `phantom` type parameters
- [ ] For each, verify the type is validated against expected configuration
- [ ] Check `phantom` types — missing phantom parameters can cause type confusion
- [ ] Trace type parameter flow across module boundaries
- [ ] Look for `type_name::get`, `type_info::type_of`, or whitelist checks

---

## Category 3: Access Control Gaps (Capability & Permission Validation)

### Root Cause

Sui Move uses **capability-based access control**: privileged operations require passing a capability object (e.g., `AdminCap`, `UpdateAuthority`). However, if the capability object is a **shared object** or if the function **fails to validate the return value** of a permission check, unauthorized callers can invoke privileged functions.

### Vulnerable Code Pattern

```move
public fun update_v2(
    oracle: &mut Oracle,
    update_authority: &UpdateAuthority,
    price: u64,
    twap_price: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    // ❌ BUG: vector::contains returns bool, but return value is not checked
    vector::contains(&update_authority.authority, &tx_context::sender(ctx));
    version_check(oracle);
    update_(oracle, price, twap_price, clock, ctx);
}
```

The `UpdateAuthority` is a **shared object**, so anyone can pass it. The permission check is performed but its result is **discarded**, making the check useless.

### Exploitation

1. Attacker obtains a reference to the shared `UpdateAuthority` object (anyone can).
2. Attacker calls `update_v2` with arbitrary price and `twap_price` values.
3. The permission check executes but the result is ignored.
4. Oracle price is updated to attacker-controlled values.
5. Attacker performs arbitrage against other protocols relying on this oracle.

### Unique Insights

- **Shared capability objects are dangerous:** A capability object that is `share_object` is accessible to anyone. Only capability objects transferred to specific addresses provide real access control.
- **The discarded-return-value bug:** This is a common pattern — the developer writes the check but forgets to `assert!` or branch on the result. The Move compiler does **not** warn about discarded `bool` return values.
- **`public(package)` is not access control:** One of the most dangerous misconceptions in Sui Move is assuming that `public(package)` visibility provides meaningful access control. It only restricts the *module* from which the function can be called — any module in the same package can invoke it.
- **Admin key compromise amplifies impact:** If the admin capability key is compromised, the attacker can drain the protocol. Access control must be audited at the **key management** level, not just the smart contract level.
- **Bounty-verified impacts:**
  - **Typus Finance** — oracle price manipulation via unchecked permission; price set to 651,548,270 and 1.
  - **Aftermath MarketMaker** — withdraw one coin type while receiving another.
  - **Navi Protocol / Volo Vault** — admin key compromise led to $3.5M loss.
- **Paywalled impact — Switchboard oracle:** A single oracle key compromise froze **four Move-based chains** (Sui, Aptos, IOTA, Movement), causing a DEX on Sui (Full Sail) to confirm loss of user funds in automated vaults.

### Bug Bounty Hunting Checklist

- [ ] Identify all capability objects — check if they are `share_object` vs. address-owned
- [ ] For every permission check, verify the return value is used in an `assert!` or conditional
- [ ] Check for `vector::contains` calls whose result is discarded
- [ ] Look for `AdminCap`, `OwnerCap`, `ManagerCap` patterns and trace who can obtain them
- [ ] Verify that privileged functions require the capability object as a `&` (immutable) or `&mut` parameter, not just a value that could be forged
- [ ] Check governance functions — can they be called by anyone with a shared object?
- [ ] Audit `public(package)` functions — they are callable by ANY module in the same package

---

## Category 4: Receipt / Hot Potato ID Validation (Misrouted Payments)

### Root Cause

Move's **hot potato** pattern creates a struct without `key`, `store`, `copy`, or `drop` abilities, forcing the caller to consume it in the same transaction. This is used for receipts (proof of payment, proof of stake). The vulnerability arises when the receipt **does not encode the type of asset** or the **source pool ID**, allowing an attacker to use a worthless asset to obtain a receipt that unlocks valuable assets.

### Vulnerable Code Pattern

```move
public struct PaymentReceipt has drop {
    amount: u64,
    // ❌ Missing: coin_type: TypeName, pool_id: ID
}

public fun repay_add_liquidity(
    asset_a: FungibleAsset,
    asset_b: FungibleAsset,
    receipt: PaymentReceipt,  // No validation of what's inside
    pool: &mut Pool,
) {
    // ❌ Missing: assert!(receipt.coin_type == pool.coin_type)
    // ❌ Missing: assert!(receipt.amount == asset_a.value())
    // ... process repayment with arbitrary assets ...
}
```

### Exploitation

1. Attacker creates a worthless `ScamCoin` type.
2. Attacker calls a function that generates a `PaymentReceipt` using `ScamCoin` (worthless).
3. Attacker passes the receipt to `repay_add_liquidity` along with real assets.
4. The function accepts the receipt without validating the coin type or amount.
5. Attacker receives real assets (e.g., LP tokens) for worthless payment.

**Alternative (Cetus limit order):** The receipt contains a payment ID but does not validate the **recipient pool**. The attacker redirects payment to their own pool and uses the receipt to claim from the victim pool.

### Unique Insights

- **Receipts must be self-describing:** A valid receipt must encode (1) the asset type, (2) the amount, (3) the source pool/contract ID, and (4) a nonce or sequence to prevent replay.
- **Hot potato alone is insufficient:** The hot potato pattern only prevents the receipt from being dropped or stored. It does not validate what the receipt represents. The **consuming function** must validate all fields.
- **Accidental droppable hot potato:** Adding `drop` to a hot potato struct destroys the guarantee. The compiler does **not** warn about unnecessary abilities. The developer must manually verify that hot potato structs **never** have `drop`, `store`, or `copy`.
- **Bounty-verified impact:** Cetus limit order — theft via misrouted payment.

### Bug Bounty Hunting Checklist

- [ ] Find all structs without `drop`/`store`/`copy`/`key` (hot potatoes)
- [ ] For each, trace which functions accept it and what they validate
- [ ] Check that receipts encode `TypeName`, `ID`, `amount`, and a replay-prevention nonce
- [ ] Verify the consuming function checks the receipt's pool/contract ID against `object::id(pool)`
- [ ] Look for `FungibleAsset` parameters that are not validated against the pool's expected types
- [ ] Check for missing `asset_a.value() == expected_amount` assertions
- [ ] Verify hot potato structs do **not** have `drop` or `copy` abilities

---

## Category 5: Integer Underflow / Overflow in Fee & Reward Calculations

### Root Cause

Move **aborts** on arithmetic overflow (it does not wrap), so traditional overflow exploits are DoS-only. **However**, integer **underflow** in business logic (not arithmetic underflow, which also aborts) occurs when a subtraction produces a negative result that is **not** caught because the operands are arranged such that the result stays within the unsigned range but represents an unintended value — or when a fee calculation uses a **zero** parameter that causes a denominator or subtraction to produce `u256::MAX`-like values through unchecked arithmetic in a library.

**Critical clarification:** Move's integer arithmetic **does not wrap on overflow**. Every overflow — addition, multiplication, or out-of-range downcast — **aborts the transaction at runtime**. This is not a compiler flag; it is how the Move VM executes arithmetic. An arithmetic overflow in Move is a **denial-of-service**, never a fund extraction vector.

### Vulnerable Code Pattern (Aftermath Finance)

```move
// integrator_taker_fees = (taker_fee * integrator_fee_rate) / 1_000_000
// When integrator sets max_taker_fee = 0:
//   integrator_fee_rate = max_taker_fee = 0
//   But the formula subtracts 0 from something or divides by a zero-derived value
//   producing ≈ u256::MAX
public fun calculate_integrator_fees(
    taker_fee: u64,
    integrator_config: &IntegratorConfig,
): u64 {
    // ❌ BUG: if max_taker_fee = 0, this produces underflow/overflow
    let integrator_rate = integrator_config.max_taker_fee;
    let protocol_rate = 1_000_000 - integrator_rate;  // If rate > 1M, underflows
    // ... fee split calculation ...
    (taker_fee * protocol_rate) / integrator_rate  // Division by zero if rate = 0
}
```

### Exploitation

1. Attacker registers as an integrator with `max_taker_fee = 0`.
2. Attacker self-trades between two accounts (one as maker, one as taker/integrator).
3. The fee calculation produces `integrator_taker_fees ≈ u256::MAX`.
4. The protocol credits this massive fee to the attacker's integrator account.
5. Attacker withdraws the inflated collateral.

### Unique Insights

- **Underflow vs. abort:** Move aborts on true arithmetic underflow (`0 - 1`). The Aftermath exploit used **business-logic underflow** — the calculation produced a valid unsigned integer that was semantically wrong because a zero parameter was treated as a negative fee.
- **Zero is dangerous in fee math:** Any fee split formula that divides by a user-configurable rate must guard against zero.
- **Detection heuristic:** For every fee/reward calculation, enumerate all user-controllable parameters. Check for (1) division by a parameter, (2) subtraction of a parameter from a constant, (3) multiplication that could overflow `u64` if the parameter is large.
- **Bounty-verified impact:** Aftermath Finance — $1.14M drained via integer underflow in perp fee calculation.
- **Cetus checked_shlw (adjacent math bug):** A faulty overflow check in `checked_shlw(u256)` — a custom math library function shifting a 256-bit value left by 64 bits — was the root cause of the **$260M Cetus exploit**. This was **not** a Move language flaw; it was a bug in Cetus's custom math library. Verichains' ecosystem scan revealed that **Kriya (~$10M TVL), FlowX (~$4.6M TVL), and Turbo Finance (~$10.3M TVL)** were also exposed to the **same mathematical flaw** in the shared library.

### Bug Bounty Hunting Checklist

- [ ] Identify all fee/reward calculation functions
- [ ] Enumerate user-controllable parameters (fee rates, integrator configs, max limits)
- [ ] Check for division by user-controlled values — can they be zero?
- [ ] Check for `constant - user_value` patterns — can user_value exceed the constant?
- [ ] Verify fee splits sum to 100% regardless of parameter values
- [ ] Check `checked_shlw`, `full_mul`, and other custom math library calls for overflow conditions
- [ ] Verify that a zero fee configuration does not create a negative fee
- [ ] **Bit operations do NOT have automatic overflow checks** — flag all bitwise shifts and masks

---

## Category 6: Oracle Manipulation (Price Feed Integrity)

### Root Cause

Sui DeFi protocols rely on on-chain oracles for price feeds. If the oracle **update function is insufficiently protected**, if the **update cycle is not verified**, or if the **oracle key is compromised**, an attacker can set arbitrary prices and drain the protocol via arbitrage or bad debt.

### Vulnerable Code Patterns

**Pattern A — Unchecked update authority:**
```move
public fun update_v2(
    oracle: &mut Oracle,
    update_authority: &UpdateAuthority,  // Shared, anyone can pass
    price: u64,
    ...
) {
    vector::contains(&update_authority.authority, &sender);  // ❌ Result discarded
    oracle.price = price;
}
```

**Pattern B — No staleness check:**
```move
public fun get_price(oracle: &Oracle, clock: &Clock): u64 {
    // ❌ Missing: assert!(clock.timestamp_ms() - oracle.ts_ms < MAX_STALENESS)
    oracle.price
}
```

**Pattern C — Single-source oracle:**
```move
public fun get_price(oracle: &Oracle): u64 {
    oracle.price  // ❌ No TWAP, no sanity bounds, no fallback
}
```

### Exploitation

1. **Direct manipulation:** Attacker calls unprotected `update_v2` with manipulated price. Then arbitrages against the protocol.
2. **Stale price exploitation:** Attacker waits for price to become stale, then trades against the outdated price before a legitimate update.
3. **Key compromise:** Attacker compromises the oracle signer's key and sets arbitrary prices. Drains all pools relying on that oracle.
4. **Flash loan + oracle manipulation:** Attacker takes a flash loan, manipulates the oracle's price by trading on a DEX that feeds the oracle, borrows against the inflated collateral, repays flash loan, keeps difference.

### Unique Insights

- **Shared update authority is an anti-pattern:** The `UpdateAuthority` object should be **owned by a specific address**, not shared. If it must be shared, the function must validate the caller against the authority list **and use the result**.
- **Staleness is chain-agnostic:** The Switchboard oracle compromise affected Sui, Aptos, IOTA, and Movement because the Move implementation of the oracle lacked proper key management.
- **Bounty-verified impacts:**
  - **Typus Finance** — oracle price manipulation via discarded `vector::contains` result; prices set to 651,548,270 and 1.
  - **Scallop** — $142K via flash loan + oracle manipulation; attacker staked 136,000 sSUI and received credit for **162 trillion points** due to uninitialized `last_index` variable.
  - **Full Sail** — $91K loss, protocol closed after Switchboard oracle key compromise.
- **Detection heuristic:** For every oracle read, check: (1) Is there a staleness check? (2) Is the update function properly permissioned? (3) Is there a TWAP or multi-source validation? (4) Are prices bounded by sanity limits?

### Bug Bounty Hunting Checklist

- [ ] Enumerate all oracle objects and their update functions
- [ ] Check update authority — is it shared? Is the permission check result used?
- [ ] Check for staleness validation (`clock.timestamp_ms() - oracle.ts_ms < threshold`)
- [ ] Check for price sanity bounds (min/max, deviation from TWAP)
- [ ] Check for fallback oracles / multi-source validation
- [ ] Trace oracle price usage in liquidation, borrow, and swap logic
- [ ] Check if oracle updates can be front-run or sandwiched
- [ ] Check for uninitialized reward index variables (`last_index`) that allow retroactive reward claims

---

## Category 7: Cross-Version Reserve Desynchronization

### Root Cause

On Sui, **upgrading a package does not replace the original**. Both versions remain callable on the same shared objects. If V1 and V-latest write **different values** to the same field (e.g., `reserve_x`), calling V1 then V-latest can create a **reserve desynchronization** that inflates LP token calculations.

### Vulnerable Code Pattern

```move
// V1: writes pool.token_x.value()
reserve_x = pool.token_x.value();

// V-latest: writes escrow.token_x.value()
reserve_x = escrow.token_x.value();

// Both versions are callable on the same Pool shared object
// V1 writes the small pool balance
// V-latest reads the deflated reserve_x and divides by it
// → LP tokens inflated by ratio between the two balances
```

### Exploitation

1. Attacker identifies a pool where both V1 and V-latest are callable.
2. Attacker calls V1's swap function on a pool whose main liquidity lives in the escrow.
3. V1 writes `reserve_x = pool.token_x.value()` (small balance).
4. Attacker calls V-latest's `mint` function, which reads the deflated `reserve_x`.
5. The mint calculation divides by the deflated reserve, **inflating LP tokens** by the ratio between the escrow balance and the pool balance.
6. Attacker receives massively inflated LP tokens and withdraws liquidity.

### Unique Insights

- **Upgrades are not replacements:** Sui's package upgrade model keeps old versions callable. Any shared object mutated by multiple versions is a potential desync vector.
- **This is not an arithmetic overflow:** BlueMove initially called it an overflow bug, but Move aborts on arithmetic overflow. The actual mechanism is a **logical desync** between two versions writing different values to the same field.
- **Detection heuristic:** For any Sui package with multiple versions, enumerate all shared objects. For each, list which functions in each version mutate which fields. Flag any field that is written by multiple versions with different expressions.
- **Bounty-verified impact:** BlueMove — **714,000 SUI drained** (approximately $528K) on July 11, 2026. The attack began at 22:13 UTC and completed within 23 minutes. The contracts were immutable — there was no way to patch or freeze.

### Bug Bounty Hunting Checklist

- [ ] Identify all package versions deployed and callable
- [ ] List all shared objects and which fields they contain
- [ ] For each field, trace which functions in which versions mutate it
- [ ] Flag fields mutated by multiple versions with different value expressions
- [ ] Check if older versions are still callable on shared objects (they are, by default)
- [ ] Test cross-version function call sequences on shared objects
- [ ] Check if legacy V2 contracts (like Scallop's V2 spool deployed Nov 2023) remain callable and exploitable

---

## Category 8: Object Ownership & Lifecycle Vulnerabilities

### Root Cause

Sui's object model introduces unique ownership semantics: objects can be **owned by an address**, **owned by another object**, **shared**, or **immutable**. Misconfiguring ownership (e.g., accidentally sharing a private object, or failing to transfer an object to the correct owner) creates access control bypasses or asset loss.

### Vulnerable Code Patterns

**Pattern A — Accidental shared object:**
```move
// Intended: private capability
let cap = AdminCap { id: object::new(ctx) };
transfer::share_object(cap);  // ❌ Should be transfer::transfer(cap, admin_address)
```

**Pattern B — Missing object uniqueness:**
```move
// Sui allows multiple singleton objects of the same type
// If the contract assumes one-per-address, but doesn't enforce it:
public fun create_vault(ctx: &mut TxContext) {
    let vault = Vault { id: object::new(ctx) };
    transfer::transfer(vault, sender(ctx));
    // ❌ No check that sender doesn't already own a Vault
}
```

**Pattern C — Orphaned UID:**
```move
// Object created but never transferred or shared
let obj = MyObject { id: object::new(ctx) };
// ❌ Object is orphaned — it exists but nobody owns it
```

### Exploitation

- **Accidental sharing:** Attacker calls the now-shared capability object to invoke privileged functions.
- **Missing uniqueness:** Attacker creates multiple singleton objects, violating protocol invariants (e.g., multiple vaults, multiple admin caps).
- **Orphaned objects:** Funds sent to orphaned objects are permanently locked.

### Unique Insights

- **Ownership is not access control by default:** An object owned by an address can still be **read** by anyone (though not mutated). If the object contains sensitive data used for authorization, the read access may be a vulnerability.
- **`transfer::share_object` is irreversible:** Once shared, an object cannot be made private again.
- **Detection heuristic:** For every `share_object` call, verify it is intentional. For every `transfer::transfer`, verify the recipient is correct. For every `object::new`, verify the object is transferred or shared before the function returns.
- **Bounty-verified impact:** Multiple audit findings related to accidental sharing of capability objects.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all `share_object` calls — verify each is intentional and the shared object does not contain secrets
- [ ] Enumerate all `transfer::transfer` calls — verify the recipient address
- [ ] Check for missing uniqueness constraints on singleton objects
- [ ] Verify objects are not orphaned (created but never transferred/shared)
- [ ] Check dynamic field usage — uncontrolled dynamic fields can be used to bypass ownership
- [ ] Verify wrapped objects (objects owned by other objects) cannot be extracted without authorization

---

## Category 9: Programmable Transaction Block (PTB) Composability Attacks

### Root Cause

Sui's Programmable Transaction Blocks allow up to **1,024** function calls in a single atomic transaction. This composability is powerful but introduces vulnerabilities when contracts assume that function calls occur in isolation or in a specific order.

### Vulnerable Code Patterns

**Pattern A — Cross-version PTB attack:**
```move
// V0 helper still deployed and callable
public fun build_bar_from_foo(foo: Foo): Bar { ... }

// V1 function accepts Bar but assumes it was built by V1
public fun use_bar(bar: Bar, ...) { ... }

// PTB: call V0's build_bar_from_foo to forge Bar, pass to V1's use_bar
```

**Pattern B — Intermediate state exposure:**
```move
// Function A modifies state, function B reads it
// If PTB calls A then B, the intermediate state is visible
// If B assumes A did not run, or vice versa, logic breaks
```

**Pattern C — Refund/undo within PTB:**
```move
// If PTB has a refund operation, and a later operation fails
// The refund may not be rolled back (atomicity applies to the whole PTB,
// but custom refund logic may execute before the failure point)
```

### Exploitation

- **Cross-version forgery:** Attacker uses PTB to call a deprecated V0 helper that builds an object, then passes it to V1's validation logic which accepts it as legitimate.
- **State manipulation:** Attacker chains multiple DeFi operations in one PTB to manipulate intermediate state.
- **Sandwich attack:** Attacker observes a pending PTB and submits their own PTB that manipulates state before/after.
- **Same-transaction MEV:** An attacker can build a PTB that (1) front-runs the victim's swap, (2) lets the victim's swap execute, (3) back-runs to restore the price, all in one atomic transaction.

### Unique Insights

- **Old versions are attack surfaces:** Deprecated helper functions remain callable forever on Sui. If they can build objects that newer functions trust, the PTB becomes a forgery vector.
- **PTBs do not provide isolation:** Function calls in a PTB share the same transaction context. Any state modified by an earlier call is visible to later calls.
- **Detection heuristic:** For any object type that is passed between functions, trace **all** public functions that can construct that type, including in old package versions. If an old version can construct it with fewer validations, the PTB can forge it.
- **Bounty-verified impact:** `secure-contracts.com` documents "Verifier Bypass via Package Upgrade" as a PTB composability attack.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all package versions and their public functions
- [ ] For every object type, list all functions that construct it
- [ ] Check if old version constructors skip validation that new version consumers assume
- [ ] Test PTB sequences that mix old and new function calls
- [ ] Check for intermediate state assumptions in functions that may be called in a PTB
- [ ] Verify that object construction requires a capability or nonce that old versions cannot forge

---

## Category 10: Hot Potato Misuse (Missing Abilities)

### Root Cause

The **hot potato** pattern uses a struct with **no abilities** (`drop`, `store`, `copy`, `key`). The compiler enforces that this struct must be consumed in the same transaction. However, developers sometimes **accidentally add `drop` or `copy`** to what should be a hot potato, destroying the guarantee. Or they use `has drop` on a receipt that should be non-droppable.

### Vulnerable Code Pattern

```move
// ❌ Should NOT have "drop" — this destroys the hot potato guarantee
public struct PaymentReceipt has drop {
    amount: u64,
    // Missing: coin_type, pool_id
}

// With "drop", the receipt can be discarded without being consumed
// The attacker can take a receipt for a small payment and discard it
// Then separately claim a large payment
```

### Exploitation

1. Attacker obtains a `PaymentReceipt` for a small amount.
2. Because the receipt has `drop`, the attacker can discard it without consuming it.
3. The attacker can then use the **same proof of payment** (transaction hash, signature) to claim a larger amount elsewhere, or the receipt's existence in the transaction is no longer required for the consuming function.

### Unique Insights

- **The compiler does not warn about unnecessary abilities:** Adding `drop` to a hot potato struct is syntactically valid and produces no warning. The developer must manually verify that hot potato structs **never** have `drop`, `store`, or `copy`.
- **`copy` is equally dangerous:** A hot potato with `copy` can be duplicated, allowing multiple consumptions of the same proof.
- **Detection heuristic:** Find all structs with no `key` ability and no `store` ability. Verify they do **not** have `drop` or `copy`. If they do, trace every function that accepts them and check if the hot potato guarantee is actually needed.
- **Bounty-verified impact:** The "Accidental Droppable Hot Potato" pattern is documented in multiple Sui audit findings.

### Bug Bounty Hunting Checklist

- [ ] Find all structs without `key` ability
- [ ] Check if they have `drop`, `store`, or `copy`
- [ ] For each hot potato struct, verify it is **not** droppable/copyable
- [ ] Trace consumption functions — do they rely on the hot potato guarantee?
- [ ] Check if the hot potato is used as a proof of payment or proof of action
- [ ] Verify the hot potato encodes all necessary validation data

---

## Category 11: Slippage & AMM-Specific Vulnerabilities

### Root Cause

AMM protocols are vulnerable to **slippage manipulation**, **front-running**, and **sandwich attacks** if they do not enforce slippage limits or if the limits are too permissive. On Sui, the PTB model allows complex multi-step attacks in a single transaction.

### Vulnerable Code Pattern

```move
public fun swap<F_TOKEN, T_TOKEN>(
    pool: &mut Pool,
    from_coin: Coin<F_TOKEN>,
    min_to_amount: u64,  // ❌ If this is 0 or too low, slippage is not protected
    ctx: &mut TxContext,
): Coin<T_TOKEN> {
    // ... swap logic ...
    assert!(to_amount >= min_to_amount, ESlippage);
}
```

**If `min_to_amount` is passed as `0`** by the user (or by a front-end that doesn't enforce a minimum), the swap executes at any price, allowing MEV extraction.

### Exploitation

1. Attacker observes a pending swap transaction with `min_to_amount = 0`.
2. Attacker submits their own swap in the same PTB or front-runs the victim.
3. Attacker manipulates the pool price before the victim's swap.
4. Victim's swap executes at a worse price.
5. Attacker reverses their trade and keeps the difference.

### Unique Insights

- **PTB composability enables same-transaction MEV:** An attacker can build a PTB that (1) front-runs the victim's swap, (2) lets the victim's swap execute, (3) back-runs to restore the price, all in one atomic transaction.
- **Slippage limits must be enforced by the protocol:** If the protocol allows `min_to_amount = 0`, it is functionally vulnerable to MEV.
- **Detection heuristic:** For every swap function, check if `min_to_amount` can be zero or if it is validated against a protocol-enforced minimum.
- **Bounty-verified impact:** Multiple AMM exploits on Sui involve slippage manipulation.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all swap functions
- [ ] Check if `min_to_amount` / `min_received` can be zero
- [ ] Verify the protocol enforces a minimum slippage bound (e.g., 1–5%)
- [ ] Check if the pool price can be manipulated within the same PTB
- [ ] Test flash-loan + swap + reverse-swap sequences
- [ ] Check for timestamp/epoch dependence in swap pricing

---

## Category 12: Zero-Liquidity Flash Swap (CLMM State Transition Without Token Flow)

### Root Cause

Concentrated Liquidity Market Maker (CLMM) pools assume that moving price through the curve requires token flow. When a pool is initialized but has **zero active liquidity at the current tick**, a flash swap can advance the pool state — cross ticks, change active liquidity, write oracle state — **without consuming input, producing output, or charging a fee**. The swap loop evaluates `amount_in_delta == 0` as trivially true, so the price moves while the trade moves no tokens.

### Vulnerable Code Pattern

```move
public fun flash_swap(
    pool: &mut Pool,
    amount_specified: u64,
    ...
) {
    // ❌ Missing: assert!(pool::liquidity(pool) > 0, insufficient_liquidity)
    let swap_state = init_swap_state(pool);
    // liquidity = 0 → amount_in_delta = 0 → condition trivially true
    // Price advances to next tick without consuming any input
}
```

**Contrast with the flash_loan path**, which correctly enforces:
```move
assert!(pool::liquidity(pool) > 0, error::insufficient_liquidity());
```

### Exploitation

1. Attacker identifies a CLMM pool that is **initialized** (`sqrt_price != 0`) but has **zero active liquidity** at the current tick (all positions are outside the current range).
2. Attacker calls `flash_swap` with a specified amount.
3. The internal `compute_swap_step` uses `get_amount_x_delta` and `get_amount_y_delta` — both return **zero** when liquidity is zero.
4. The required input to reach the target price becomes `amount_in_delta = 0`.
5. The exact-input branch condition `amount_remaining_minus_fee >= amount_in_delta` is trivially true.
6. The step selects `new_sqrt_price = target_sqrt_price` while returning `amount_in = 0`, `amount_out = 0`, `fee_amount = 0`.
7. The price moves even though the trade moved no tokens.
8. **Protocol-level financial consequence:** The same zero-liquidity tick-cross path can push reward accounting beyond the emission end time, after which previously claimable yield becomes **unclaimable** while reward custodian funds remain present and unchanged.

### Unique Insights

- **State progress without economic progress:** A swap loop should preserve at least one of: input is consumed, output is produced, a fee is charged, the remaining amount decreases, or the transaction aborts. The zero-liquidity path violated all five conditions.
- **The missing invariant:** `flash_swap` initialized its internal swap state from `pool::liquidity(pool)` and entered the swap loop without requiring the value to be positive. The related `flash_loan` path **did** enforce this invariant — the inconsistency is the vulnerability.
- **Detection heuristic:** For every swap/CLMM function, check whether it validates `pool.liquidity > 0` before entering the swap loop. Compare with the flash_loan path — if flash_loan validates but flash_swap does not, it's a candidate.
- **Bounty-verified impact:** Momentum CLMM — submitted as High severity (mapped to transaction manipulation, logic attacks, and loss/freezing of unclaimed yield). HackenProof validated the issue but kept the official severity at **Low**, focusing on the zero-liquidity precondition and the absence of demonstrated direct theft. The final reward was **$100**. This is an important lesson: even when a vulnerability is real, the bounty payout depends on the demonstrated **direct financial impact** and the **precondition rarity**. A low-severity classification does not mean the finding is invalid — it means the triage team assessed the exploitability constraints as limiting.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all `flash_swap` / `swap` functions in CLMM pools
- [ ] Check if the function validates `pool.liquidity > 0` before the swap loop
- [ ] Compare with the `flash_loan` path — does it validate liquidity?
- [ ] Check if price can advance without token flow when liquidity is zero
- [ ] Trace reward accounting — can zero-liquidity swaps push rewards past emission end?
- [ ] Check if the pool can be initialized with zero active liquidity at the current tick
- [ ] Verify the swap loop terminates only when: input is consumed, output is produced, fee is charged, remaining amount decreases, or sqrt_price == target

---

## Category 13: Timestamp & Epoch Dependence

### Root Cause

Functions that depend on `Clock` timestamps or `TxContext::epoch()` can be manipulated if the attacker can control when their transaction is executed within a block, or if the protocol does not account for timestamp drift.

### Vulnerable Code Pattern

```move
public fun update_rewards(pool: &mut Pool, clock: &Clock, ctx: &TxContext) {
    let elapsed = clock::timestamp_ms(clock) - pool.last_update_ms;
    let rewards = elapsed * pool.reward_rate;
    pool.accumulated_rewards = pool.accumulated_rewards + rewards;
    pool.last_update_ms = clock::timestamp_ms(clock);
    // ❌ No check that elapsed is positive or within expected bounds
}
```

### Exploitation

1. Attacker manipulates transaction ordering to be first or last in a block, maximizing or minimizing `elapsed`.
2. If `elapsed` can be negative (underflow) or zero, reward calculation may break.
3. Attacker can also "time" their interaction to maximize rewards.

### Unique Insights

- **Move aborts on underflow:** If `clock.timestamp_ms(clock) < pool.last_update_ms`, the subtraction underflows and aborts. This is a DoS vector, not a fund extraction vector.
- **Epoch boundaries are exploitable:** If rewards reset at epoch boundaries, attackers can time transactions to exploit the reset logic.
- **Detection heuristic:** For every timestamp/epoch-dependent function, check: (1) Is there a maximum elapsed bound? (2) Can elapsed be zero? (3) Is the function idempotent within an epoch?
- **Bounty-verified impact:** Multiple Sui audit findings include timestamp dependence as a vulnerability class.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all functions using `Clock` or `TxContext::epoch()`
- [ ] Check for underflow in timestamp subtraction
- [ ] Check for maximum elapsed bounds
- [ ] Check for epoch boundary reset logic
- [ ] Test transactions at epoch boundaries and at the start/end of blocks

---

## Category 14: Uninitialized State Variables (Silent Corruption)

### Root Cause

On Sui, object fields created with `object::new(ctx)` are **not automatically initialized to zero in all code paths**. If a rewards accumulator or index variable is left uninitialized when a new account joins a pool, the account can claim rewards as though it had participated since inception. This is a **silent state corruption** vulnerability — no transaction aborts, no compiler warning.

### Vulnerable Code Pattern (Scallop Protocol)

```move
public struct Spool has key, store {
    id: UID,
    last_index: u256,        // ❌ Never initialized on account creation
    accumulated_rewards: u256,
}

public fun join_pool(pool: &mut Spool, ctx: &mut TxContext) {
    let account = Account {
        id: object::new(ctx),
        // ❌ last_index not initialized → remains at default (0 or uninitialized)
        accumulated_rewards: 0,
    };
    // ...
}
```

### Exploitation

1. Attacker identifies a rewards contract where `last_index` is not initialized when new accounts join.
2. The protocol's reward index has accumulated over **20 months** to roughly **1.19 billion**.
3. Attacker stakes **136,000 sSUI** and receives credit for **162 trillion reward points** due to the uninitialized `last_index` treating the account as if it had participated since inception.
4. Since the rewards distribution system operates on a one-to-one exchange ratio, the attacker extracts the **entire balance of 150,000 SUI** in a single transaction.
5. Attacker transfers stolen assets through a privacy-focused mixing protocol on Sui.

### Unique Insights

- **The bug was 17 months old:** The vulnerable contract was a **V2 spool package deployed in November 2023**. On Sui, smart contracts become immutable once deployed. Previous versions remain active and accessible unless developers implement explicit version-based access restrictions. This architectural characteristic allowed the legacy contract to persist as an exploitable vulnerability.
- **The attacker proposed a white-hat deal:** Following the theft, the attacker contacted the team and offered to return **80% of the stolen funds** in exchange for a white-hat bounty. This is a common post-exploit pattern on Sui — the attacker seeks to convert a theft into a bounty claim, often retaining 20–30% as a "finder's fee."
- **Detection heuristic:** For every struct with an index or accumulator variable, trace all code paths that create instances of that struct. Verify the variable is explicitly initialized in **every** path.
- **Bounty-verified impact:** Scallop Protocol — **$142,000 (150,000 SUI)** stolen on April 26, 2026. The attacker staked 136,000 sSUI and received credit for 162 trillion reward points. The entire pool was drained in a single transaction.

### Bug Bounty Hunting Checklist

- [ ] Enumerate all structs with index/accumulator variables (`last_index`, `reward_per_token`, etc.)
- [ ] Trace every code path that creates instances of these structs
- [ ] Verify the variable is explicitly initialized in **every** path
- [ ] Check if the default initialization (zero) creates an exploitable discrepancy
- [ ] Check if legacy contract versions (like Scallop's V2 spool) remain callable
- [ ] Verify version-based access restrictions are in place for legacy contracts

---

## Category 15: DoS via Memory Exhaustion / Recursive Payloads (Validator-Level)

### Root Cause

While Move's type system prevents many smart-contract-level attacks, the **Sui validator software itself** can be targeted via specially crafted payloads that cause memory exhaustion, infinite loops, or persistent DoS conditions. These are **protocol-level** vulnerabilities, not smart contract vulnerabilities, but they affect all Sui DeFi protocols by taking down the network.

### Vulnerable Pattern (Sui Validator Node DoS — $50K Bounty)

**Attack vector:** An attacker publishes a malicious `CompiledModule` on the blockchain containing an approximately **1KB payload** and executes an entry function with maximum gas (**50 SUI**). Execution leads to a **drastic increase in memory consumption** on the Validator/Full Node. The surge persists for approximately **10 minutes** until an Out-Of-Memory (OOM) exception triggers. During this time, the node becomes incapable of processing new transactions. The recursive behavior means the node remains incapable even **after restarting**, indicating persistent damage.

**Bounty:** $50,000 in SUI tokens awarded to researcher @f4lt via HackenProof (September 2023).

### Unique Insights

- **Recursive DoS is persistent:** Unlike simple memory exhaustion that clears on restart, the HamsterWheel attack (CertiK discovery) induced an **infinite loop** via a ~100-byte payload that persisted across reboots, effectively causing a total network shutdown.
- **The HamsterWheel attack (CertiK, $500K bounty):** Identified and disclosed a series of denial-of-service vulnerabilities in the Sui blockchain. The critical one allowed an attacker to **induce an infinite loop in the validator node** by merely submitting a small payload of approximately 100 bytes. The attack created persistent damage that endured even after the validator network rebooted. Sui network awarded a **$500,000 bounty** to CertiK Skyfall team.
- **Detection heuristic:** For validator software, check for loops that do not have termination conditions based on user input, and for memory allocations that scale with attacker-controlled payload sizes.
- **Bounty-verified impacts:**
  - Sui Validator Node DoS — $50,000 (HackenProof, @f4lt).
  - CertiK HamsterWheel — $500,000 (Sui network).
  - Type-confusion in Aptos Move (adjacent) — Hexens identified a "stale-cache bug" that could have exposed **~$70 billion** in assets. Found using a **$3,000 server** running fuzzing/analysis tools.

### Bug Bounty Hunting Checklist

- [ ] For validator/protocol-level audits: check for recursive payloads, unbounded loops, memory allocation scaling with input size
- [ ] Check if DoS conditions persist across reboots
- [ ] Check for type-confusion in VM-level caches
- [ ] Monitor the bella-ciao VM (new execution layer) for regressions — the Sui Foundation has expanded its bug bounty to cover VM-related critical vulnerabilities at **$100,000–$1,000,000**

---

## Master Hunting Checklist

Use this checklist systematically when auditing any Sui Move protocol:

### Phase 1: Reconnaissance
- [ ] Map all modules, structs, and public functions
- [ ] Identify capability objects (`AdminCap`, `OwnerCap`, etc.)
- [ ] Identify shared objects (`share_object` calls)
- [ ] Identify hot potatoes (structs without `key`)
- [ ] Identify generic functions (`<CoinType>`, `<phantom T>`)
- [ ] Identify oracle dependencies and price feeds
- [ ] Identify AMM pools and swap functions
- [ ] Identify fee/reward calculation functions
- [ ] Map package versions and cross-version callability
- [ ] Identify legacy contracts (deployed >6 months ago) that remain callable
- [ ] Identify structs with index/accumulator variables that may be uninitialized

### Phase 2: Reference & Type Analysis
- [ ] Trace all `&mut` destructuring patterns for pointer reassignment bugs
- [ ] Verify generic type validation against stored configuration
- [ ] Check for missing phantom type parameters
- [ ] Check for `mut` binding shadowing

### Phase 3: Access Control Analysis
- [ ] Enumerate all permission checks and verify return values are used
- [ ] Check for shared capability objects
- [ ] Check for admin key management (off-chain)
- [ ] Check governance function callability
- [ ] Audit `public(package)` functions — they are callable by ANY module in the same package
- [ ] Check if legacy versions of contracts remain callable without restrictions

### Phase 4: Financial Logic Analysis
- [ ] Check fee calculations for zero-denominator, underflow, overflow
- [ ] Check oracle update functions for permission and staleness
- [ ] Check receipt validation for type, amount, pool ID
- [ ] Check slippage limits on swaps
- [ ] Check reward calculation for timestamp/epoch manipulation
- [ ] Check CLMM pools for zero-liquidity state transitions
- [ ] Check for uninitialized reward index variables (`last_index`)
- [ ] Check bitwise operations — they do NOT have automatic overflow checks

### Phase 5: Object Model Analysis
- [ ] Verify object ownership (owned vs. shared vs. immutable)
- [ ] Check for missing object uniqueness constraints
- [ ] Check for orphaned objects
- [ ] Check dynamic field usage

### Phase 6: Cross-Version & PTB Analysis
- [ ] Enumerate all callable package versions
- [ ] For each shared object, map which versions mutate which fields
- [ ] Check for cross-version reserve desync
- [ ] Check for old version constructors that skip validation
- [ ] Test PTB sequences mixing old and new functions

### Phase 7: Protocol-Level (Validator/VM) Analysis
- [ ] Check for recursive payloads / unbounded loops in validator software
- [ ] Check memory allocation scaling with attacker-controlled input
- [ ] Check for type-confusion in VM caches
- [ ] Monitor bella-ciao VM for regressions

---

## Quick Reference: Vulnerability Type → Detection Heuristic

| Vulnerability Type | Primary Detection Signal | Code Pattern | Bounty Example |
|---|---|---|---|
| Reference vs. Value | `ref_var = other_ref_var` without `*` | `let S { mut x } = &mut s; x = y;` | Lombard Finance |
| Type Parameter Mismatch | Generic function without type validation | `fun f<CoinType>(coin: Coin<CoinType>)` | Navi Protocol |
| Access Control Gap | Discarded `vector::contains` result | `vector::contains(...);` (no assert) | Typus Finance |
| Receipt Validation | Hot potato without type/pool ID | `struct Receipt has drop { amount: u64 }` | Cetus limit order |
| Integer Underflow | Division by user-controlled zero | `(a * (1_000_000 - fee)) / fee` | Aftermath Finance ($1.14M) |
| Oracle Manipulation | Shared `UpdateAuthority` or no staleness check | `update_authority: &UpdateAuthority` | Scallop ($142K) |
| Reserve Desync | Multiple versions write same field | V1: `reserve = pool.balance`; V2: `reserve = escrow.balance` | BlueMove (714K SUI) |
| Object Ownership | `share_object` on capability | `transfer::share_object(cap)` | Multiple audits |
| PTB Composability | Old constructor + new consumer | V0 `build_bar()` → V1 `use_bar()` | secure-contracts.com |
| Hot Potato Misuse | Hot potato with `drop`/`copy` | `struct Receipt has drop` | Multiple audits |
| Slippage | `min_to_amount` can be zero | `assert!(to >= 0)` | Multiple AMMs |
| Zero-Liquidity Flash Swap | Swap advances price without token flow | `pool.liquidity == 0` in swap loop | Momentum CLMM ($100) |
| Timestamp Dependence | Unbounded `elapsed` | `clock::timestamp_ms(clock) - last_update` | Multiple audits |
| Uninitialized State | `last_index` not set on account creation | `Account { last_index: /* missing */ }` | Scallop ($142K) |
| Validator DoS | Recursive payload / infinite loop | 100-byte payload → persistent OOM | CertiK ($500K) |

---

## Bounty Program Reference

### Sui Foundation Bug Bounty (via HackenProof)

| Severity | Reward Range | Scope |
|---|---|---|
| Critical | $100,000 – $1,000,000 (VM) / $500,000 (protocol) | Consensus, Bridge, bella-ciao VM |
| High | $50,000 | Protocol infrastructure |
| Medium | $10,000 | Protocol infrastructure |
| Low | $5,000 | Protocol infrastructure |

Cumulative payouts: **$2.37M+** since April 2023.

### Cetus Bug Bounty (via HackenProof)

| Severity | Reward Range |
|---|---|
| Critical | $30,000 – $300,000 |
| High | $3,000 – $30,000 |
| Medium | $100 – $1,000 |
| Low | $10 – $100 |

In-scope: Stealing/loss of funds, unauthorized transactions, transaction manipulation, logic attacks, reentrancy, reordering, over/underflows.

### HackenProof Security Expansion Program (Sui Foundation Partner)

25+ Sui ecosystem projects rely on HackenProof for bug bounty and audit services. Projects include **Walrus Protocol, Bluefin, Scallop**, and others. HackenProof secures **more than 80% of the Move market** and has been the pioneer in Move auditing.

### Historical Bounty Payouts

| Protocol/Vulnerability | Bounty Amount | Discoverer |
|---|---|---|
| Sui Validator Node DoS | $50,000 | @f4lt (HackenProof) |
| HamsterWheel (total network shutdown) | $500,000 | CertiK Skyfall |
| Cetus exploit white-hat offer | $6,000,000 (offered) | Attacker (not paid) |
| Momentum CLMM zero-liquidity flash swap | $100 | Independent researcher |
| Scallop exploit white-hat offer | 80% of $142K (offered) | Attacker (under investigation) |
| BlueMove exploit white-hat offer | 70% of 714K SUI (offered) | Attacker (48-hour deadline) |

---

## References

1. OpenZeppelin, “Critical Bug Patterns in Sui Move: Lessons from Real Audits” (2026-04-29)
2. SlowMist, “Is the Move Language Secure? The Typus Permission-Validation Vulnerability” (2025-10-21)
3. Dedaub, “The Cetus AMM $200M Hack: How a Flawed ‘Overflow’ Check Led to Catastrophic Loss” (2025-05-23)
4. Aftermath Finance Incident Report, “Integer Underflow in Perp Fee Calculation” (2026-04-29)
5. BlueMove Exploit Analysis, “Cross-Version Reserve Desync Drained 714,000 SUI” (2026-08-11)
6. Scallop Protocol Incident, “Reward Accumulator Logic Bug” (2026-04-27)
7. Navi Protocol / Volo Vault Incident, “Admin Key Compromise” (2026-04-22)
8. `secure-contracts.com`, “Type Parameter Griefing” and “Verifier Bypass via Package Upgrade”
9. PantherAudits, `move-auditor` Skill (GitHub), 220+ vulnerability patterns
10. Sui Security Documentation, “Hardened by Design”
11. HackenProof, “Sui Validator Node DOS Bugfix Review” (@f4lt, $50K)
12. CertiK, “Unraveling the HamsterWheel: How CertiK Caught a Critical Bug in Sui” ($500K)
13. Momentum CLMM, “Zero-Liquidity Flash Swap” (HackenProof, $100)
14. Verichains, “Multiple Sui Projects Previously Exposed to Critical Math Bug Found in Cetus Hack”
15. HackenProof, “Sui Foundation Security Expansion Program” (2026-06-10)
16. Immunefi, “Sui Temporary Total Network Shutdown Bugfix Review” (@F4lt, $50K)
17. CoinDesk, “How ethical hackers with just a $3,000 server found a flaw that could've put $70 billion in crypto at risk” (Aptos type-confusion)
18. HackenProof, “Cetus Bug Bounty Program” ($30K–$300K)
19. Sui Foundation, “Bug Bounty Program” (up to $500K)
20. MetaEra / HackenProof, “bella-ciao VM Bug Bounty” ($100K–$1M)

---

