Itchy Candy Bat

medium

# Wrong liquidity checks due to unaccounted profits from fixed pools

## Summary

When a user wants to borrow or withdraw liquidity from the protocol, there's a liquidity check that ensures that there are enough funds to withdraw/borrow. However, all the liquidity checks are wrong because they do not take into account the unrealized profits earned from the fixed pools. 

## Vulnerability Detail

When a user wants to borrow or withdraw liquidity from a market, there's a liquidity check that ensures that there are enough funds in that market to execute that action. When a user wants to borrow (floating or fixed), the check is enforced [here](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L157-L159) and [here](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L303-L305):

```solidity
if (floatingBackupBorrowed + newFloatingDebt > floatingAssets.mulWadDown(1e18 - reserveFactor)) {
  revert InsufficientProtocolLiquidity();
}
```

When a user wants to withdraw liquidity from the floating pool or some fixed pool, the checks are enforced [here](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L387) and [here](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L704):

```solidity
if (floatingBackupBorrowed + floatingDebt > newFloatingAssets) revert InsufficientProtocolLiquidity();
```

However, all these checks are actually wrong because they do not take into account the accrued profits from the fixed pools. These profits are coming from the unassigned earnings of each fixed pool, and they're accrued each time a user calls a function that updates the state of that fixed pool, e.g. `borrowAtMaturity`:

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L293
```solidity
floatingAssets += pool.accrueEarnings(maturity);
```

When the fixed pools haven't been updated in a while and we make a liquidity check, the value of `floatingAssets` will be lower than it should be because it won't be including the assets that come from the profits of fixed pools. 

## Impact

All liquidity checks are wrong because they're using a stale value of `floatingAssets`. This will cause a DoS on all borrow and withdraw functions due to this faulty liquidity check.

## Code Snippet

All the wrong liquidity checks:
- https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L157-L159
- https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L303-L305ç
- https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L387
- https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L704

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to use `totalAssets` instead of `floatingAssets` to make a liquidity check. This will fix the issue because the `totalAssets` function already includes all the unrealized profits from the fixed pools. 
