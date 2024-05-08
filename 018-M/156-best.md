Cheerful Blonde Alligator

high

# Attacker can leverage its position and sandwich oracle updates to exploit vault

## Summary
An attacker can watch the mempool waiting for Chainlink oracle updates to leverage its position and repay the debt with the profit made, making other depositors pay the cost.

## Vulnerability Detail
Chainlink oracles have a 0.5% tolerance before updating their answers. An attacker could use that to exploit the vault with zero risk.

The following Proof of Concept will be made with USD as base unit just to show clearly how the exploit works and the profit is made:

```markdown
Context Data:
WBTC Risk-Adjust factor: 0.86
USDC Risk-Adjust factor: 0.91
The attacker entered both markets in the shared auditor

- Transaction 1:
Attacker WBTC Balance: $100,000
Attacker USDC Balance: $0

	a) Attacker deposits $100,000 of WBTC. 
		Collateral value in WBTC: $100,000 * 0.86 = $86,000
		Attacker WBTC Balance: $0
	
	b) Attacker borrows max available in USDC: $78,260/0.91 = $86,000
		Attacker USDC Balance: $78,260
	
	c) Attacker swaps USDC for WBTC (in some DEX).
		Attacker USDC Balance: $0
		Attacker WBTC Balance: $78,260 * 0.97 = $75,912.2 (0.03 swap fee)
	
	d) Attacker deposits $78,260 of WBTC.
		Attacker WBTC Balance: $0
		Collateral value in WBTC: $178,260 * 0.86 = $153,303.6
		Debt value taken in USDC: $78,260/0.91 = $86,000

- Transaction 2:
Chainlink oracle update! WBTC value increases by 0.5%!

- Transaction 3:
Attacker WBTC Balance: $0
Attacker USDC Balance: $0
Collateral value in WBTC: $187,173 * 0.86 = $160,968,78
Debt value taken in USDC: $78,260/0.91 = $86,000

	a) Attacker withdraws $80,681 in WBTC
		Collateral value in WBTC: $106,492 * 0.86 = $91,583.12
		Attacker WBTC Balance: $80,681
		Attacker USDC Balance: $0
		
	b) Attacker swaps WBTC for USDC (in some DEX).
		Attacker WBTC Balance: $0
		Attacker USDC Balance: $80,681 * 0.97 = $78260.57 (0.03 swap fee)
		
	c) Attacker repays debt in USDC.
		Attacker USDC Balance: $0
		Debt value taken in USDC: $0
		
	d) Attacker withdraws all WBTC
		Attacker WBTC Balance: $106,492

- Resume:
Attacker balance in USD before attack: $100,000
Attacker balance in USD after attack: $106,492
Profit: $6,492 - 6.492% (Way more than just the 0.5% actual increase)
```

As you can see, the attacker managed to leverage its position for free with depositors funds and with zero risk because the attacker knew the price increase was coming by watching the mempool.
## Impact
Attackers will drain Vaults repeatedly.
## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L135-L169
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/8f6ef1b0868d3ea3a98a5ab7e8b3a164857681d7/protocol/contracts/Market.sol#L171-L183
## Tool used

Manual Review

## Recommendation
There are two known solutions to this kind of attack:
- add a deposit fee higher than the 0.5% tolerance
- when a user makes a deposit, enforce a delay that prevents them from withdrawing in a short amount of time

