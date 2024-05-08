Warm Cinnabar Lion

medium

# Users may reduce their post liquidation health factor by splitting assets in several markets

## Summary

Liquidations are performed on a single market at a time, aiming at a `TARGET_HEALTH`. However, this target will likely be unreachable if the positions of the user are split across several markets.

## Vulnerability Detail

Liquidators calling `Market::liquidate()` pick a `seizeMarket`, and the repay market is the market in which the function is called. 

The protocol aims to liquidate users and reach a certain health target, which should not be possible if a user splits its assets across several markets. The debt and collateral that a liquidator can liquidate are capped by the chosen market individual debt and collateral of the liquidatee.

For example, if the user deposits and borrows in a single market, due to the `adjustFactor`, the liquidator should always be able to make the liquidatee reach the health factor target. In case the user decides to split deposits and borrows in 2 markets, it's likely there won't be enough debt or collateral in the individual chosen markets to seize and repay the required total debt across markets to reach the desired health target.

The following test can be added to `Market.t.sol` to confirm that splitting positions across market will lead to smaller liquidations for users.
```solidity
function test_POC_Game_Liquidation() external {
  // setting the same factor for all markets to be sure that it is not because of it
  auditor.setAdjustFactor(market, 0.9e18);

  vm.startPrank(ALICE);

  // ALICE deposits and borrows DAI
  uint256 assets = 10_000 ether;
  ERC20 asset = market.asset();
  deal(address(asset), ALICE, assets);
  market.deposit(assets, ALICE);
  market.borrow(assets*9*9/10/10, ALICE, ALICE);
  
  // ALICE deposits and borrows weth
  deal(address(weth), ALICE, assets);
  weth.approve(address(marketWETH), assets);
  marketWETH.deposit(assets, ALICE);
  marketWETH.borrow(assets*9*9/10/10, ALICE, ALICE);

  vm.stopPrank();

  skip(1);

  // LIQUIDATION
  deal(address(asset), address(market), 100_000 ether);
  address liquidator = makeAddr("liquidator");
  deal(address(asset), liquidator, 100_000_000 ether);
  vm.startPrank(liquidator);
  asset.approve(address(market), type(uint256).max);
  market.liquidate(ALICE, type(uint256).max, market);
  vm.stopPrank();

  // RATIO is smaller than 1.25, liquidator did not liquidate as much as if it was in
  // a single market
  (uint256 collateral, uint256 debt) = auditor.accountLiquidity(address(ALICE), Market(address(0)), 0);
  assertEq(collateral*1e18 / debt, 1108999999911099183);
}
```

## Impact

Increased bad debt and less liquidation incentives.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L548
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L241-L243
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L248
The limitation of the debt in the repay market as happens when all debt is paid in the repay market and `maxAssets > repaidAssets` [1](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L582), [2](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L593).

## Tool used

Manual Review

Vscode

Foundry

## Recommendation

Implement a cross markets liquidation mechanism to ensure the ratio can reach the target. Instead of specifying one repay market, liquidators could go through all markets, repaying the debt of each market until `maxAssets` is reached.