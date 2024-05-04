Warm Cinnabar Lion

high

# If a maturity expires before an account handles borrow of the RewardsController, it will not have it's share, leading to lost rewards

## Summary

`accountFixedBorrowShares()` is based on the maturities 1 INTERVAl in the future, which may have expired since the `update()` calculated the index.

## Vulnerability Detail

`accountFixedBorrowShares()` calculates the maturities starting on the next interval. If update is called, it gets all fixed debt based on the next INTERVAL. If the time between update and `accountFixedBorrowShares()` is bigger than 1 interval, the maturity would have expired and the rewards would be lost.

## Impact

Lost rewards.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L367

## Tool used

Manual Review

Vscode

## Recommendation

Replace the maturities time to the earnings acummulator or implement a linked list to account all maturities.