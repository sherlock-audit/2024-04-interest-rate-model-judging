Hollow Rouge Pony

high

# Protocol users who deposit and/or withdraw assets in the same block stand to lose reward benefits

## Summary
Users who make multiple reward-worthy transactions in the same block will not get protocol rewards. The protocol documentation does not alert unaware investors of such a design.

## Vulnerability Detail
When users make transactions on a market worthy of rewards eg call borrow, rewards are calculate by the [update function](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/RewardsController.sol#L318):

```solidity
function update(address account, Market market, ERC20 reward, AccountOperation[] memory ops) internal {
    uint256 baseUnit = distribution[market].baseUnit;
    RewardData storage rewardData = distribution[market].rewards[reward];
    {
      uint256 lastUpdate = rewardData.lastUpdate;
      // `lastUpdate` can be greater than `block.timestamp` if distribution is set to start on a future date
      if (block.timestamp > lastUpdate) {
        (uint256 borrowIndex, uint256 depositIndex, uint256 newUndistributed) = previewAllocation(
          rewardData,
          market,
          block.timestamp - lastUpdate
        );
        if (borrowIndex > type(uint128).max || depositIndex > type(uint128).max) revert IndexOverflow();
        rewardData.borrowIndex = uint128(borrowIndex);
        rewardData.depositIndex = uint128(depositIndex);
        rewardData.lastUpdate = uint32(block.timestamp);
        rewardData.lastUndistributed = newUndistributed;
        emit IndexUpdate(market, reward, borrowIndex, depositIndex, newUndistributed, block.timestamp);
      }
    }

    mapping(bool => Account) storage operationAccount = rewardData.accounts[account];
    for (uint256 i = 0; i < ops.length; ) {
      AccountOperation memory op = ops[i];
      Account storage accountData = operationAccount[op.operation];
      uint256 accountIndex = accountData.index;
      uint256 newAccountIndex;
      if (op.operation) {
        newAccountIndex = rewardData.borrowIndex;
      } else {
        newAccountIndex = rewardData.depositIndex;
      }
      if (accountIndex != newAccountIndex) {
        accountData.index = uint128(newAccountIndex);
        if (op.balance != 0) {
          uint256 rewardsAccrued = accountRewards(op.balance, newAccountIndex, accountIndex, baseUnit);// balance.mulDivDown(globalIndex - accountIndex, baseUnit);
          accountData.accrued += uint128(rewardsAccrued);
          emit Accrue(market, reward, account, op.operation, accountIndex, newAccountIndex, rewardsAccrued);
        }
      }
      unchecked {
        ++i;
      }
    }

```
One critical factor that determines rewards to be accrued is the lastUpdate value. This means that if transactions are done within the same block, only the first transaction will accrue rewards. Considering that this protocol design is not clearly documented for users to be aware of, unsophisticated investors will definitely miss reward benefits.  
## Impact
Pedestrian investors who have not dissected the inner workings of the reward system will lose reward benefits if their transaction is bundled in one block.
## Code Snippet
Consider this POC that shows changes in both lastReward, block.timestamp and rewards accrued for a user at different times

```solidity
function testMultipleDepositsSameReward() external {
    marketWETH.deposit(10 ether, address(this));
    marketWETH.borrow(1 ether, address(this), address(this));

    (, uint256 distributionEnd, uint32 lastUpdate) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertEq(lastUpdate,0);
    marketWETH.borrow(20000, address(this), address(this));
    uint256 opRewards = rewardsController.allClaimable(address(this), opRewardAsset);
    assertEq(opRewards,0);
    (, distributionEnd, lastUpdate) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertEq(lastUpdate,0);
    marketWETH.borrow(20000, address(this), address(this));
    opRewards = rewardsController.allClaimable(address(this), opRewardAsset);
    assertEq(opRewards,0);
    (, distributionEnd, lastUpdate) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertEq(lastUpdate,0);
    skip(1600);
    marketWETH.borrow(20000, address(this), address(this));
    opRewards = rewardsController.allClaimable(address(this), opRewardAsset);
    assertTrue(opRewards > 0 );
    (, distributionEnd, lastUpdate) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertTrue(lastUpdate > 0);
    skip(1600);
    marketWETH.borrow(20000, address(this), address(this));
    uint256 opRewards2 = rewardsController.allClaimable(address(this), opRewardAsset);
    assertTrue(opRewards2 > opRewards );
    (, distributionEnd, lastUpdate) = rewardsController.distributionTime(marketWETH, opRewardAsset);
    assertTrue(lastUpdate >= 1600 * 2);   
    
  }
```

## Tool used

Manual Review

## Recommendation
Clearly document that users who expect to reap rewards should not bundle their transactions in one block, or provide a way for users to cancel transaction if their transaction does not earn rewards. 