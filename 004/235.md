Dancing Carrot Barracuda

high

# Future upgrades to chainlink API can brick the protocol

## Summary

 The issue should be under scope as the FAQ for the contest although mentions that chainlink is trusted but broken assumptions and future concerns should be reported.
<img width="810" alt="Screenshot 2024-05-04 at 14 43 32" src="https://github.com/sherlock-audit/2024-04-interest-rate-model-Audinarey/assets/131544007/bf986bd6-c354-4fe6-bd06-c736506b03a3">


> Chainlink is TRUSTED. 

<img width="837" alt="Screenshot 2024-05-04 at 14 45 40" src="https://github.com/sherlock-audit/2024-04-interest-rate-model-Audinarey/assets/131544007/2f7d8019-20fb-47a5-a77c-f25a0e8c153b">


Chainlink itself has warned against the use of [`latestAnswer()`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L329) concerns which the protocol does not take into account considering future upgrade decisions that Chainlink could make on its price oracle APIs.
Moreover, it reports latestAnswer with varying decimals: 18 decimals for crypto quotes and 8 for FX quotes, leading to inconsistency


## Vulnerability Detail
Although the protocol trie to mitigate pricing concern by reverting if 
```solidity
    if (price <= 0) revert InvalidPrice();
```
Considering that owing to future API improvements and upgrades, Chainlink can decide to remove the `latestAnswer()` endpoint entirely or worse yet hard code it to an arbitrary value including zero, major functionalities of the `Market.sol` contract will always revert. Some of these functionalities includes but are not limited to:
[`Auditor::accountLiquidity(...)`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L127). 
[`Auditor::checkLiquidation(...)`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L212)
[`Auditor::calculateSeize(...)`](https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L283-L284). 
`DebtPreviewer::minDeposit(...)`
`DebtPreviewer::previewAssetsOut(...)`

## Impact
The use of an unsupported and deprecated function can brick the protocol or even lead to exploits considering if the protocol does not make an immediate adjustment to the price feed

The issue should be under scope as the FAQ for the contest although mentions that chainlink is trusted but broken assumptions and future concerns should be reported.


## Code Snippet
https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L329

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L283-L284

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L212

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/Auditor.sol#L127


## Tool used
Manual Review

## Recommendation
Follow the direction in the chainlink documentation [here](https://docs.chain.link/data-feeds/api-reference#latestrounddata-1).
