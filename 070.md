Itchy Candy Bat

high

# DoS on liquidations when utilization rate is high

## Summary

When a position is liquidated, the liquidator seizes some (or all) of the borrower's assets in compensation for repaying the unhealthy debt. However, when the utilization rate is high in a market, liquidations won't work because of insufficient protocol liquidity.

An attacker could use this bug to frontrun a liquidation transaction by withdrawing assets from a market, bringing the utilization higher and preventing the liquidation. 

## Vulnerability Detail

In liquidation, one of the last steps is to seize the assets from a borrower and give them to the liquidator. The `seize` function calls `internalSeize` to seize the assets from the borrower: 

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L678-L694
```solidity
  function internalSeize(Market seizeMarket, address liquidator, address borrower, uint256 assets) internal {
    if (assets == 0) revert ZeroWithdraw();

    // reverts on failure
    auditor.checkSeize(seizeMarket, this);

    RewardsController memRewardsController = rewardsController;
    if (address(memRewardsController) != address(0)) memRewardsController.handleDeposit(borrower);
    uint256 shares = previewWithdraw(assets);
>>  beforeWithdraw(assets, shares);
      
    // ...
  }
```

The function `internalSeize`, in turn, calls `beforeWithdraw` to update the state of the market before the actual seizing of the assets. The issue is that `beforeWithdraw` checks if the protocol has enough liquidity for the withdrawal of assets:

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L698-L706
```solidity
  function beforeWithdraw(uint256 assets, uint256) internal override whenNotPaused {
    updateFloatingAssetsAverage();
    depositToTreasury(updateFloatingDebt());
    uint256 earnings = accrueAccumulatedEarnings();
    uint256 newFloatingAssets = floatingAssets + earnings - assets;
    // check if the underlying liquidity that the account wants to withdraw is borrowed
>>  if (floatingBackupBorrowed + floatingDebt > newFloatingAssets) revert InsufficientProtocolLiquidity();
    floatingAssets = newFloatingAssets;
  }
```

This check will make the whole liquidation revert when the utilization rate of that market is near the top. An attacker can use this bug to prevent a liquidation of one of his accounts by frontrunning the liquidation and withdrawing liquidity with another account. When that liquidity is withdrawn, the actual liquidation will fail. 

## Impact

When the utilization rate of a market is high, the liquidations will fail, causing bad debt on the protocol if the price moves against the borrower. Liquidations are a core invariant of any lending protocol and should never fail in order to prevent bad debt, and ultimately, a bank run. 

An attacker can use this vulnerability to make his positions not liquidatable by frontrunning a liquidation and withdrawing liquidity from that market with another account. 

## PoC

The following PoC can be pasted in the `Market.t.sol` file and can be run with the following command `forge test --match-test test_fail_liquidation`.

```solidity
function test_fail_liquidation() external {
    // We set the price of the asset to 0.0002 (1 ETH = 5,000 DAI)
    daiPriceFeed.setPrice(0.0002e18);

    // Simulate deposits on the markets
    market.deposit(50_000e18, ALICE);
    marketWETH.deposit(10e18, address(this));

    // Simulate borrowing on the markets
    vm.startPrank(ALICE);
    market.auditor().enterMarket(market);
    marketWETH.borrow(5e18, ALICE, ALICE);
    vm.stopPrank();

    market.borrow(35_000e18, address(this), address(this));

    // Price falls to 0.00025 (1 ETH = 4,000 DAI)
    daiPriceFeed.setPrice(0.00025e18);

    // Position cannot be liquidated due to insufficient protocol liquidity
    vm.prank(BOB);
    vm.expectRevert(InsufficientProtocolLiquidity.selector);
    market.liquidate(address(this), type(uint256).max, marketWETH);
}
```

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L704

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to not call `beforeWithdraw` in a liquidation and add the logic of `beforeWithdraw` in the `internalSeize` function except for the liquidity check.
