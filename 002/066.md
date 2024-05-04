Itchy Candy Bat

medium

# Bad debt isn't cleared when `earningsAccumulator` is lower than a fixed-pool bad debt

## Summary

When the bad debt from a fixed pool must be cleared but the `earningsAccumulator` value is slightly lower than the debt, it won't clear any amount of debt. If the bad debt amount is big enough, this may cause a bank run, and the last users to withdraw won't be able to because of this uncleared bad debt. 

## Vulnerability Detail

When a loan is liquidated and it has more debt than collateral, that extra debt (bad debt) must be cleared at the end of the liquidation to avoid a discrepancy between the tracked funds and the actual funds. The function in charge of clearing the bad debt is the following:

```solidity

    function clearBadDebt(address borrower) external {
        if (msg.sender != address(auditor)) revert NotAuditor();

        floatingAssets += accrueAccumulatedEarnings();
        Account storage account = accounts[borrower];
        uint256 accumulator = earningsAccumulator;
        uint256 totalBadDebt = 0;
        uint256 packedMaturities = account.fixedBorrows;
        uint256 maturity = packedMaturities & ((1 << 32) - 1);
        packedMaturities = packedMaturities >> 32;
        while (packedMaturities != 0) {
          if (packedMaturities & 1 != 0) {
            FixedLib.Position storage position = fixedBorrowPositions[maturity][borrower];
            uint256 badDebt = position.principal + position.fee;
>>          if (accumulator >= badDebt) {
              RewardsController memRewardsController = rewardsController;
              if (address(memRewardsController) != address(0)) memRewardsController.handleBorrow(borrower);
              accumulator -= badDebt;
              totalBadDebt += badDebt;
              floatingBackupBorrowed -= fixedPools[maturity].repay(position.principal);
              delete fixedBorrowPositions[maturity][borrower];
              account.fixedBorrows = account.fixedBorrows.clearMaturity(maturity);

              emit RepayAtMaturity(maturity, msg.sender, borrower, badDebt, badDebt);
            }
          }
          packedMaturities >>= 1;
          maturity += FixedLib.INTERVAL;
        }
        
        // ...
    }
```

The `clearBadDebt` function first clears the bad debt on the fixed pools using the `earningsAccumulator` on the market. However, when the accumulator is slightly lower than the bad debt on a fixed pool, it should clear the maximum debt possible but it won't clear any bad debt. 

Imagine the following scenario:
1. After a loan is liquidated and the full collateral is seized, it still has 1 ETH (`1e18`) of debt in a fixed pool. 
2. When `clearBadDebt` is called, the earnings accumulator has 0.95 ETH (`0.95e18`) in it, which is less than the bad debt to be cleared.
3. The function, instead of clearing the maximum bad debt possible (i.e. 0.95 ETH), it won't clear any bad debt because the accumulator is slightly lower than the debt to clear. 

This will cause the accrued bad debt to stay in the market, possibly causing a bank run in the long term if enough bad debt isn't cleared. 

## Impact

When the value of `earningsAccumulator` is slightly lower than the bad debt, the protocol won't clear any bad debt. If this happens enough times, the uncleared bad debt will become bigger and it will possibly cause a bank run in the future, and the last users to withdraw won't be able to because of the lack of funds within the protocol. 

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L633

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to clear the maximum amount of bad debt possible when the accumulated earnings are slightly lower than the bad debt to clear. 
