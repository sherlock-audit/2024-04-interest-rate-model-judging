Tiny Mulberry Tapir

medium

# Some rewards will be lost if no floating deposits exist in the market

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