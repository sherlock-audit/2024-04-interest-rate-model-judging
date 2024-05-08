Crazy Pickle Bee

medium

# Lack of slippage control in Market::liquidate()

## Summary
Liquidator might seize 0 collateral by liquidating one borrow position.

## Vulnerability Detail
If the borrower's collateral price drops down, the borrower's position might be liquidated. The liquidator needs to choose the liquidated market and seized market, liquidate the borrow position in liquidated market and seize the borrower's collateral in seized market.
The vulnerability exists in Auditor::calculateSeize(), contracts will calculate the seized collateral's amount according to the repaid assets' amount. If the borrower does not have enough collateral in seized market, liquidator will take a loss. In normal scenario, liquidators will check the borrower's collateral value before liquidation. However, if several liquidators liquidate one borrow position at the same time, liquidators might take some unexpected loss.

For example:
- Alice as the borrower, take Token A, B as the collateral to borrow Token C.
- Suddenly, Token A's price drop a lot, and Alice becomes liquidatable. 
- Bob, as the first liquidator, try liquidate partial Alice's position, repay Token C for Alice and seize all Token B. Considering TokenA price drop a lot, Alice is still liquidatable.
- Cathy, as the second liquidator, try to liquidate partial Alice's position almost at the same time. So Cathy cannot recognize that Alice's Collateral B's amount becomes to 0. The result is that Cathy pays some debt for Alice, and earn nothing. Cathy has to take the loss, which is not unexpected.

```c
  function liquidate(
    address borrower,
    uint256 maxAssets,
    Market seizeMarket
  ) external whenNotPaused returns (uint256 repaidAssets) {
    if (msg.sender == borrower) revert SelfLiquidation();

    maxAssets = auditor.checkLiquidation(this, seizeMarket, borrower, maxAssets);
    if (maxAssets == 0) revert ZeroRepay();

    Account storage account = accounts[borrower];
    ......

    // reverts on failure
    (uint256 lendersAssets, uint256 seizeAssets) = auditor.calculateSeize(this, seizeMarket, borrower, repaidAssets);
    earningsAccumulator += lendersAssets;

    if (address(seizeMarket) == address(this)) {
      internalSeize(this, msg.sender, borrower, seizeAssets);
    } else {
      seizeMarket.seize(msg.sender, borrower, seizeAssets);
    }
    ...
  }
  function calculateSeize(
    Market repayMarket,
    Market seizeMarket,
    address borrower,
    uint256 actualRepayAssets
  ) external view returns (uint256 lendersAssets, uint256 seizeAssets) {
    LiquidationIncentive memory memIncentive = liquidationIncentive;
    lendersAssets = actualRepayAssets.mulWadDown(memIncentive.lenders);

    // read prices for borrowed and collateral markets
    uint256 priceBorrowed = assetPrice(markets[repayMarket].priceFeed);
    uint256 priceCollateral = assetPrice(markets[seizeMarket].priceFeed);
    uint256 baseAmount = actualRepayAssets.mulDivUp(priceBorrowed, 10 ** markets[repayMarket].decimals);

    seizeAssets = Math.min(
      baseAmount.mulDivUp(10 ** markets[seizeMarket].decimals, priceCollateral).mulWadUp(
        1e18 + memIncentive.liquidator + memIncentive.lenders
      ),
      seizeMarket.maxWithdraw(borrower)
    );
  }

```

## Impact
Liquidators might take some unexpected loss.

## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L545-L614
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L273-L293

## Tool used

Manual Review

## Recommendation
Add one slippage parameter for function liquidate(), liquidator can set his/her expected seized collateral amount.
