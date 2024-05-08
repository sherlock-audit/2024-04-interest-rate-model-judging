Tiny Mulberry Tapir

medium

# Inconsistency in `floatingAssets` updates in the Market contract

## Summary
`floatingAssets` updates are inconsistent across different functions of the Market contract, and they do not calculate the exact floatingAssets for every operation.
## Vulnerability Detail
In the Market contract, the `beforeWithdraw()` and `afterDeposit()` functions trigger `updateFloatingDebt()` before `accrueAccumulatedEarnings()` to update the `floatingAssets` storage. It does not accrue earnings from maturities to the floating pool.
```solidity=
function beforeWithdraw(uint256 assets, uint256) internal override whenNotPaused {
    updateFloatingAssetsAverage();
    depositToTreasury(updateFloatingDebt());
    uint256 earnings = accrueAccumulatedEarnings();
    uint256 newFloatingAssets = floatingAssets + earnings - assets;
    // check if the underlying liquidity that the account wants to withdraw is borrowed
    if (floatingBackupBorrowed + floatingDebt > newFloatingAssets) revert InsufficientProtocolLiquidity();
    floatingAssets = newFloatingAssets;
  }

  function afterDeposit(uint256 assets, uint256) internal override whenNotPaused whenNotFrozen {
    updateFloatingAssetsAverage();
    uint256 treasuryFee = updateFloatingDebt();
    uint256 earnings = accrueAccumulatedEarnings();
    floatingAssets += earnings + assets;
    depositToTreasury(treasuryFee);
    emitMarketUpdate();
  }
```

However, in functions at each maturity (such as `borrowAtMaturity()`), earnings from that specific maturity are accrued to update the floating assets. Earnings from other maturities and accumulated earnings are not accrued into `floatingAssets` during this function. Another point is that `updateFloatingDebt()` is called after earnings are accrued in `borrowAtMaturity()`.
```solidity=
function borrowAtMaturity(
    uint256 maturity,
    uint256 assets,
    uint256 maxAssets,
    address receiver,
    address borrower
  ) external whenNotPaused whenNotFrozen returns (uint256 assetsOwed) {
  ...
  FixedLib.Pool storage pool = fixedPools[maturity];
  floatingAssets += pool.accrueEarnings(maturity);

  ...

  {
    uint256 backupDebtAddition = pool.borrow(assets);
    if (backupDebtAddition != 0) {
      uint256 newFloatingBackupBorrowed = floatingBackupBorrowed + backupDebtAddition;
      depositToTreasury(updateFloatingDebt());
      ...
    }
  }
```

Additionally, in the `clearBadDebt()` function, it calls `accrueAccumulatedEarnings()` before triggering `updateFloatingDebt()` in `noTransferRefund()`. This order is the opposite of the flow in `beforeWithdraw()` for updating `floatingAssets`.
```solidity=
function clearBadDebt(address borrower) external {
  if (msg.sender != address(auditor)) revert NotAuditor();

  floatingAssets += accrueAccumulatedEarnings();
  
  ...
  if (account.floatingBorrowShares != 0 && (accumulator = previewRepay(accumulator)) != 0) {
    (uint256 badDebt, ) = noTransferRefund(accumulator, borrower);
    totalBadDebt += badDebt;
  }
```
## Impact
The inconsistent and imprecise `floatingAssets` may cause incorrect debt calculations and fluctuations in share prices and interest for users
## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L698-L717
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L293-L302
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L622
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L649

## Tool used

Manual Review

## Recommendation
When updating `floatingAssets` in `updateFloatingDebt()`, it should accrue earnings from the accumulator and maturities before calculating debt, to ensure an exact `floatingAssets` for every operation in the market.