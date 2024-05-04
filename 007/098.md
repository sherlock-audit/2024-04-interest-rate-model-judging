Trendy Cedar Wasp

medium

# The claimable rewards amount for borrowers decreases over time

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