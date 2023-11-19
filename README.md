

# About

This project is meant to describe exploitable bugs detect on Cyfrin stablecoin project which aims to create a stablecoin where users can deposit WETH and WBTC in exchange for a token that will be pegged to the USD. Please find the source code here: https://github.com/DeFiesta/foundry-defi-stablecoin-f23

- [About](#about)
- [AuditReport](#Audit Report)
  - [H1-token with less than 18 decimals can be stolen](#H1)
  - [H2-Strict enforcement of the liquidation bonus is causing prevention of liquidation.](#H2)
  - [H3-small positions can not be liquidated](#H3)
  - [H4-Business Logic: Protocol Liquidation Arithmetic](#H4)
  - [M1-No arbitrum sequencer status check in cainlink feed](#M1)
  - [M2-protocol can consume stale price data or cannot operate on some EVM chains](#M2)
  - [M3-Chainlink oracle will return the wrong price if the aggregator hits minAnswer](#M3)
  - [M4-Anyone can burn DecentralizedStableCoin tokens with burnFrom function](#M4)
  - [M5-Double-spending vulnerability leads to a disruption of the DSC token](#M5)
  - [M6-Lack of fallbacks for price feed oracle](#M6)
  - [M7-Too many DSC tokens can get minted for fee-on-transfer tokens.](#M7)
  - [M8-liquidate does not allow the liquidator to liquidate a user if the liquidator HF < 1](#M8)
  - [M9-Protocol can break for a token with a proxy and implementation contract (like TUSD)](#M9)
  - [M10-DoS of full liquidations are possible by frontrunning the liquidators](#M10)


# Audit Report

## High-01 token with less than 18 decimals can be stolen

The token prices computed by DSCEngine#getTokenAmount FromUsd() and DSCEngine#getUsdValue() don't check for the same decimal numbers. Normally, these methods assume that all tokens have 18 decimals; however, one of the described collateral tokens is WBTC, which has only 8 decimals on Ethereum mainnet.

This 18-decimal assumption creates a discrepancy between the protocol-computed USD value and actual USD value of tokens with non-standard decimals. As a result, any deposited collateral token with fewer than 18 decimals (including WBTC) can potentially be stolen by an attacker.

This line from DSCEngine#getTokenAmountFromUsd() contains scaling adjustments for the price feed's own precision (expressed to 8 decimals), but no such adjustments for the token's own decimals. The return value always has 18 decimals, but it should instead match the token's decimals since it returns a token amount.

```
return (usdAmountInWei * PRECISION) / (uint256(price) * ADDITIONAL_FEED_PRECISION);
```

This line from DSCEngine#getUsdValue() contains the same issue but in the opposite direction. The return value always has the same number of decimals as the token itself, whereas it is supposed to be an 18-decimal USD amount.

```
return ((uint256(price) * ADDITIONAL_FEED_PRECISION) * amount) / PRECISION;
```


## High-02 Strict enforcement of the liquidation bonus is causing prevention of liquidation.

The problem stems from the strict enforcement of the liquidation bonus, hindering liquidation when a user's collateralization sits between 100% to 110%. Despite the necessity for liquidation when a user's health factor drops below a specific threshold, the rigid bonus setup leaves inadequate funds for liquidation, resulting in transaction reversals.

This loophole empowers users to evade complete liquidation, even in critical health factor zones, posing a threat to the protocol's stability and security. The risk intensifies when diverse collateral types are involved, especially if the value of one crashes.

To showcase the vulnerability's impact, a proof of concept and test case were run, spotlighting instances where a liquidator couldn't fully clear a user's debt due to insufficient collateral, resulting in transaction reversals.

My recommendation involves modifying the liquidation bonus calculation when the health factor falls within the 100% to 110% range. By adjusting the liquidation bonus to the highest positive, non-zero value feasible instead of a fixed 1.1 * liquidationAmount, we can address this vulnerability. This adjustment will help mitigate the issue.

### Recommendations

When the health factor is between 100 to 110%, make the liquidation bonus to the maximum possible amount, not the fix amount of 1.1 * liqudationAmount. You can do that by adding the following code to the liquidate() function before calling _redeemCollateral():

```
uint256 totalDepositedCollateral = s_collateralDeposited[user][collateral];
if (tokenAmountFromDebtCovered < totalDepositedCollateral && totalCollateralToRedeem > totalDepositedCollateral) {
    totalCollateralToRedeem = totalDepositedCollateral;
}
```
## High-03 small positions can not be liquidated

There is no incentive to liquidate low value accounts such as 5$ usd value accounts because of gas cost

Liquidators liquidate users for the profit they can make. If there is no profit to be made than there will be no one to call the liquidate function. For example an account has 6$ worth of collateral and has 4 DSC minted. This user is undercollateralized and must be liquidated in order to ensure that the protocol remains overcollateralized. Because the value of the account is so low, after gas costs, liquidators will not make a profit liquidating this user. In the end these low value accounts will never get liquidating, leaving the protocol with bad debt and can even cause the protocol to be undercollateralized with enough small value accounts being underwater.

### PoC

```
function testCriticalHealthFactor() public {
    // Arranging the liquidator
    uint256 liquidatorCollateral = 10e18;
    ERC20Mock(weth).mint(liquidator, liquidatorCollateral);
    vm.startPrank(liquidator);
    ERC20Mock(weth).approve(address(dsce), liquidatorCollateral);
    uint256 liquidatorDebtToCover = 200e18;
    dsce.depositCollateralAndMintDsc(weth, liquidatorCollateral, amountToMint);
    dsc.approve(address(dsce), liquidatorDebtToCover);
    vm.stopPrank();

    // We set the price of WETH to $105 and WBTC to $95
    int256 wethUsdPrice = 105e8;
    MockV3Aggregator(ethUsdPriceFeed).updateAnswer(wethUsdPrice);
    int256 wbtcUsdPrice = 95e8;
    MockV3Aggregator(btcUsdPriceFeed).updateAnswer(wbtcUsdPrice);

    // Alice deposits 1 WBTC and 1 WETH and mints 100 DSC
    uint256 amountWethToDeposit = 1e18;
    uint256 amountWbtcToDeposit = 1e18;
    uint256 amountDscToMint = 100e18;
    vm.startPrank(user);
    ERC20Mock(weth).approve(address(dsce), amountWbtcToDeposit);
    dsce.depositCollateral(weth, amountWbtcToDeposit);
    ERC20Mock(wbtc).approve(address(dsce), amountWethToDeposit);
    dsce.depositCollateralAndMintDsc(wbtc, amountWethToDeposit, amountDscToMint);

    // WBTC crashes in its price will be $0
    int256 wbtcUsdPriceAfterCrash = 0;
    MockV3Aggregator(btcUsdPriceFeed).updateAnswer(wbtcUsdPriceAfterCrash);

    // Now, a liquidator tries to liquidate $100 of Alice's debt, and it will be reverted.
    vm.expectRevert();
    vm.startPrank(liquidator);
    dsce.liquidate(weth, user, amountDscToMint);
    vm.stopPrank();

    // The liquidator tries to liquidate $94.5 of Alice's debt, and it will be reverted.
    uint256 maxValueToLiquidate = 94.5e18;
    vm.expectRevert();
    vm.startPrank(liquidator);
    dsce.liquidate(weth, user, maxValueToLiquidate);
    vm.stopPrank();
}
```

### Recommendations

A potential fix could be to only allow users to mint DSC if their collateral value is past a certain threshold.

## High-04 Business Logic: Protocol Liquidation Arithmetic

The protocol mints a stable coin based on the value of collateral tokens it accepts. The only way to mint this stable coin is through this contract.
To liquidate a users position in order to save the protocol from holding bad debt, the liquidator needs to pay back the dsc owed by the user that has a position at risk.
In order for the liquidator to get this dsc, they would need to mint new dsc from the contract. But the math does not work out.
With a Liquidation Bonus of 10% and an Over Collateralization Rate of 200%, a liquidator will always have their own collateral stuck in the protocol after liquidating a user.
This happens even if the liquidator is able to use the redeemed collateral to mint new dsc and pay back the users debt - should a way for this to be done atomically be available.
This also happens if they are able to purchase it or flashloan it from a dex or other venue prior to calling liquidate.
The math simply does not work.

### Recommendations
These are not all connected, but possibly can be:

  Design some incentives for users to keep using dsc and not sell it, so that they may be able to redeem their collateral.
  Make the collateralization rate and the liquidation bonus arithmetically incentivised so as to allow re-entrancy for a flash loan type of atomic mint within the protocol.
  Allow an alternative stable coin to be used for repayment should dsc not be available.
  Allow a flashmint feature in the Decentralised Stablecoin Contract for no fee, but limited to the value of the redeemed Collateral held at time of flashmint and pay back.



## Medium-01 staleCheckLatestRoundData() does not check the status of the Arbitrum sequencer in Chainlink feeds.

Given that the contract will be deployed on any EVM chain, when utilizing Chainlink in L2 chains like Arbitrum, it's important to ensure that the prices provided are not falsely perceived as fresh particularly in scenarios where the sequencer might be non-operational. Hence, a critical step involves confirming the active status of the sequencer before trusting the data returned by the oracle.

In the event of an Arbitrum Sequencer outage, the oracle data may become outdated, potentially leading to staleness. While the function staleCheckLatestRoundData() provides checks if a price is stale, it does not check if Arbirtrum Sequencer is active. Since OracleLib.sol library is used to check the Chainlink Oracle for stale data, it is important to add this verification. You can review Chainlink docs on L2 Sequencer Uptime Feeds for more details on this. https://docs.chain.link/data-feeds/l2-sequencer-feeds

### Recommendations

There is a code example on Chainlink docs for this scenario: https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code. For illustrative purposes this can be:

```
function isSequencerAlive() internal view returns (bool) {
    (, int256 answer, uint256 startedAt,,) = sequencer.latestRoundData();
    if (block.timestamp - startedAt <= GRACE_PERIOD_TIME || answer == 1)
        return false;
    return true;
}


function staleCheckLatestRoundData(AggregatorV3Interface priceFeed)
        public
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
require(isSequencerAlive(), "Sequencer is down");
       ....//remaining parts of the function
```

## Medium-02 protocol can consume stale price data or cannot operate on some EVM chains

The stale period (3 hours) is too large for Ethereum, Polygon, BNB, and Optimism chains, leading to consuming stale price data. On the other hand, that period is too small for Arbitrum and Avalanche chains, rendering the DSC protocol unable to operate.

In the OracleLib library, the TIMEOUT constant is set to 3 hours. In other words, the staleCheckLatestRoundData() would consider the price data fed by Chainlink's price feed aggregators to be stale only after the last update time has elapsed 3 hours.

Since the DSC protocol supports every EVM chain (confirmed by the client), let's consider the ETH / USD oracles on different chains.

On Ethereum, the oracle will update the price data every ~1 hour.
On Polygon, the oracle will update the price data every ~25 seconds.
On BNB (BSC), the oracle will update the price data every ~60 seconds.
On Optimism, the oracle will update the price data every ~20 minutes.
On Arbitrum, the oracle will update the price data every ~24 hours.
On Avalanche, the oracle will update the price data every ~24 hours.
On some chains such as Ethereum, Polygon, BNB, and Optimism, 3 hours can be considered too large for the stale period, causing the staleCheckLatestRoundData() to return stale price data.

Whereas, on some chains, such as Arbitrum and Avalanche, 3 hours is too small. Specifically, if the DSC protocol is deployed to Arbitrum or Avalanche, the protocol will be unable to operate because the "if (secondsSince > TIMEOUT)" condition will be met, causing a transaction to be reverted in the staleCheckLatestRoundData().

### Recommendations

Even on the same chain, different collateral tokens can have different heartbeats (the period to update the price data on chain). For instance, the heartbeat for the DAI / USD oracle on Ethereum is ~1 hour, whereas the heartbeat for the USDT / USD oracle on the same chain is ~24 hours.

Thus, I recommend using the mapping data type to record the TIMEOUT parameter of each collateral token and setting each token's TIMEOUT with an appropriate stale period.

Furthermore, I also recommend adding a setter function for updating the stale period of each specific collateral token.

## Medium-03 Chainlink oracle will return the wrong price if the aggregator hits minAnswer

Chainlink aggregators have a built-in circuit breaker if the price of an asset goes outside of a predetermined price band.
The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the minPrice instead of the actual price of the asset and vice versa.

### Vulenrability detail

The staleCheckLatestRoundData function in OracleLib.sol is only checking for the stale price. But no checks are done to handle that.

```
 function staleCheckLatestRoundData(AggregatorV3Interface priceFeed)
        public
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            priceFeed.latestRoundData();

        uint256 secondsSince = block.timestamp - updatedAt;
        if (secondsSince > TIMEOUT) revert OracleLib__StalePrice();

        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }
```
There is no function for checking only this as well in the library. The checks are not done in DSCEngine.sol file. There are two instances of that:

```
(, int256 price,,,) = priceFeed.staleCheckLatestRoundData();
```

```
(, int256 price,,,) = priceFeed.staleCheckLatestRoundData();
```

### Recommendations

Consider using the following checks:

```
(uint80, int256 answer, uint, uint, uint80) = oracle.latestRoundData();

// minPrice check
require(answer > minPrice, "Min price exceeded");
// maxPrice check
require(answer < maxPrice, "Max price exceeded");
```

Also some gas could be saved when used revert with custom error for doing the check.

## Medium-04 Anyone can burn DecentralizedStableCoin tokens with burnFrom function

Anyone can burn DSC tokens with burnFrom function inherited of OZ ERC20Burnable contract

### Vulnerability Details

In the DecentralizedStableCoin contract the burn function is onlyOwner and is used by DSCEngine contract, which is the owner of DecentralizedStableCoin contract

### Impact

The tokens can be burned with burnFrom function bypassing the onlyOwner modifier of the burn functions

### Recommendations

Block the burnFrom function of OZ ERC20Burnable contract

## Medium-05 Double-spending vulnerability leads to a disruption of the DSC token

There is a double-spending vulnerability in the DSCEngine contract, leading to a disruption of the DSC token.

### Vulnerability Details

While constructing the DSCEngine contract, the whitelisted collateral tokens will be registered along with their corresponding price feed addresses. However, the registration process does not verify that a token cannot be registered twice.

For instance, assume that the ETH address is inputted in the array tokenAddresses twice, the ETH address will also be pushed into the array s_collateralTokens twice.

```
    constructor(address[] memory tokenAddresses, address[] memory priceFeedAddresses, address dscAddress) {
        // USD Price Feeds
        if (tokenAddresses.length != priceFeedAddresses.length) {
            revert DSCEngine__TokenAddressesAndPriceFeedAddressesMustBeSameLength();
        }
        // For example ETH / USD, BTC / USD, MKR / USD, etc
        for (uint256 i = 0; i < tokenAddresses.length; i++) {
            s_priceFeeds[tokenAddresses[i]] = priceFeedAddresses[i];
@>          s_collateralTokens.push(tokenAddresses[i]);
        }
        i_dsc = DecentralizedStableCoin(dscAddress);
    }
```

Subsequently, when the contract executes the getAccountCollateralValue() to compute users' collateral value, the function will process on the ETH address twice. In other words, if a user/attacker deposits 10 ETH as collateral, the getAccountCollateralValue() will return 20 ETH (in USD value), leading to a double-spending issue.

```
    function getAccountCollateralValue(address user) public view returns (uint256 totalCollateralValueInUsd) {
        // loop through each collateral token, get the amount they have deposited, and map it to
        // the price, to get the USD value
@>      for (uint256 i = 0; i < s_collateralTokens.length; i++) {
@>          address token = s_collateralTokens[i];
@>          uint256 amount = s_collateralDeposited[user][token];
@>          totalCollateralValueInUsd += getUsdValue(token, amount);
@>      }
        return totalCollateralValueInUsd;
    }
```

### Impact

With this double-spending vulnerability, an attacker can deposit ETH to double their collateral value and then mint DSC tokens over the limit (breaking the protocol's health factor invariant).

As a result, the DSCEngine contract will eventually be insolvent, and the DSC token will then be depegged to $0.

### Recommendations

To fix the vulnerability, I recommend adding the require(s_priceFeeds[tokenAddresses[i]] == address(0), "Collateral token was already set"); to guarantee that there could not be any token ever registered twice.

```
    constructor(address[] memory tokenAddresses, address[] memory priceFeedAddresses, address dscAddress) {
        // USD Price Feeds
        if (tokenAddresses.length != priceFeedAddresses.length) {
            revert DSCEngine__TokenAddressesAndPriceFeedAddressesMustBeSameLength();
        }
        // For example ETH / USD, BTC / USD, MKR / USD, etc
        for (uint256 i = 0; i < tokenAddresses.length; i++) {
+           require(s_priceFeeds[tokenAddresses[i]] == address(0), "Collateral token was already set");
            s_priceFeeds[tokenAddresses[i]] = priceFeedAddresses[i];
            s_collateralTokens.push(tokenAddresses[i]);
        }
        i_dsc = DecentralizedStableCoin(dscAddress);
    }
```

## Medium-06 Lack of fallbacks for price feed oracle

The DSC protocol does not implement fallback solutions for price feed oracle. In case Chainlink's aggregators fail to update price data, the protocol will refuse to liquidate users' positions, leading to the protocol's disruption.

### Vulnerability Details

The DSC protocol utilizes the staleCheckLatestRoundData() for querying price data of collateral tokens through Chainlink's price feed aggregators. Nonetheless, if Chainlink's aggregators fail to update the price data, the DSC protocol will not be able to operate. In other words, the function will revert transactions since the received price data become stale.

```
    function staleCheckLatestRoundData(AggregatorV3Interface priceFeed)
        public
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
@>      (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
@>          priceFeed.latestRoundData();

        uint256 secondsSince = block.timestamp - updatedAt;
@>      if (secondsSince > TIMEOUT) revert OracleLib__StalePrice();

        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }
```

### Impact

Without fallback solutions, the DSC protocol will be unable to operate if Chainlink's aggregators fail to update price data.

Consider the scenario that Chainlink's aggregators fail to update price data and collateral tokens' prices dramatically go down, the DSC protocol will refuse to liquidate users' positions. Consequently, the protocol will become insolvent eventually, leading to the protocol's disruption.

### Recommendations

We recommend implementing fallback solutions, such as using other off-chain oracle providers and/or on-chain Uniswap's TWAP, for feeding price data in case Chainlink's aggregators fail.

## Medium-07 Too many DSC tokens can get minted for fee-on-transfer tokens.

The DSCEngine contract overcalculates the collateral when operating with fee-on-transfer tokens, which can lead to too many DSC tokens being minted.

### Vulnerability details

The competition description mentions that while the first use-case for the system will be a WETH/WBTC backed stablecoin, the system is supposed to generally work with any collateral tokens. If one or more collateral tokens are fee-on-transfer tokens, i.e., when transferring X tokens, only X - F tokens arrive at the recipient side, where F denotes the transfer fee, depositors get credited too much collateral, meaning more DSC tokens can get minted, which leads to a potential depeg.

The root cause is the depositCollateral function in DSCEngine:
```
function depositCollateral(address tokenCollateralAddress, uint256 amountCollateral)
        public
        moreThanZero(amountCollateral)
        isAllowedToken(tokenCollateralAddress)
        nonReentrant
    {
        s_collateralDeposited[msg.sender][tokenCollateralAddress] += amountCollateral;
        emit CollateralDeposited(msg.sender, tokenCollateralAddress, amountCollateral);
        bool success = IERC20(tokenCollateralAddress).transferFrom(msg.sender, address(this), amountCollateral);
        if (!success) {
            revert DSCEngine__TransferFailed();
        }
    }
```

AS can be seen in line
```
bool success = IERC20(tokenCollateralAddress).transferFrom(msg.sender, address(this), amountCollateral);
```

the contract assumes that the full amountCollateral is received, which might not be the case with fee-on-transfer tokens.

### Impact

When the contract operates with fee-on-transfer tokens as collateral, too many DSC tokens can get minted based on the overcalculated collateral, potentially leading to a depeg.

### Recommendations

Check the actual amount of received tokens:

```
function depositCollateral(address tokenCollateralAddress, uint256 amountCollateral)
        public
        moreThanZero(amountCollateral)
        isAllowedToken(tokenCollateralAddress)
        nonReentrant
    {
        uint256 balanceBefore = IERC20(tokenCollateralAddress).balanceOf(address(this));
        bool success = IERC20(tokenCollateralAddress).transferFrom(msg.sender, address(this), amountCollateral);
        uint256 balanceAfter = IERC20(tokenCollateralAddress).balanceOf(address(this));
        amountCollateral = balanceAfter - balanceBefore;
        if (!success) {
            revert DSCEngine__TransferFailed();
        }
        s_collateralDeposited[msg.sender][tokenCollateralAddress] += amountCollateral;
        emit CollateralDeposited(msg.sender, tokenCollateralAddress, amountCollateral);
    }
```

## Medium-08. liquidate does not allow the liquidator to liquidate a user if the liquidator HF < 1

The liquidate function does not allow the liquidator to liquidate the borrower if the liquidatorHF < 1.
By liquidating a user, the liquidator is using his own funds that do not impact the liquidator HF directly.
Because the function reverts, the system is preventing a user's to perform an action that should be able to do.

### Vulnerability Details

The liquidate function does not allow the liquidator to liquidate the borrower if the liquidatorHF < 1.
By liquidating a user, the liquidator is using his own funds that do not impact the liquidator HF directly.
Because the function reverts, the system is preventing a user's to perform an action that should be able to do.

### Impact

A liquidator cannot liquidate a user's debt when the liquidator's HF is below 1. The system is preventing a user to perform an action that does not impact his own HF.

### PoC

```
// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {DSCEngine} from "../../src/DSCEngine.sol";
import {DecentralizedStableCoin} from "../../src/DecentralizedStableCoin.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {MockV3Aggregator} from "../mocks/MockV3Aggregator.sol";

contract CannotLiquidateWhenHFTest is StdCheats, Test {
    DSCEngine public dsce;
    DecentralizedStableCoin public dsc;
    HelperConfig public helperConfig;

    address[] public tokenAddresses;
    address[] public priceFeedAddresses;

    address public ethUsdPriceFeed;
    address public btcUsdPriceFeed;
    address public weth;
    address public wbtc;
    uint256 public deployerKey;

    uint256 amountCollateral = 10 ether;
    uint256 amountToMint = 100 ether;
    address public user = address(1);

    uint256 public constant STARTING_USER_BALANCE = 10 ether;
    uint256 public constant MIN_HEALTH_FACTOR = 1e18;
    uint256 public constant LIQUIDATION_THRESHOLD = 50;


    function setUp() external {
        helperConfig = new HelperConfig();

        (ethUsdPriceFeed, btcUsdPriceFeed, weth, wbtc, deployerKey) = helperConfig.activeNetworkConfig();

        tokenAddresses = [weth, wbtc];
        priceFeedAddresses = [ethUsdPriceFeed, btcUsdPriceFeed];

        dsc = new DecentralizedStableCoin();
        dsce = new DSCEngine(tokenAddresses, priceFeedAddresses, address(dsc));

        dsc.transferOwnership(address(dsce));

        if (block.chainid == 31337) {
            vm.deal(user, STARTING_USER_BALANCE);
        }
        
        ERC20Mock(weth).mint(user, STARTING_USER_BALANCE);
        ERC20Mock(wbtc).mint(user, STARTING_USER_BALANCE);
    }

function testLiquidateRevertIfLiquidatorHFBelow() public {
        vm.startPrank(user);
        ERC20Mock(weth).approve(address(dsce), amountCollateral);
        dsce.depositCollateralAndMintDsc(weth, amountCollateral, amountToMint);
        vm.stopPrank();

        // liquidator 
        address liquidator = makeAddr("liquidator");
        ERC20Mock(weth).mint(liquidator, STARTING_USER_BALANCE);

        vm.startPrank(liquidator);
        ERC20Mock(weth).approve(address(dsce), amountCollateral);
        dsce.depositCollateralAndMintDsc(weth, amountCollateral, amountToMint);
        vm.stopPrank();

        // now let's say that price goes down
        int256 ethUsdUpdatedPrice = 18e8; // 1 ETH = $18

        MockV3Aggregator(ethUsdPriceFeed).updateAnswer(ethUsdUpdatedPrice);
        assertLt(dsce.getHealthFactor(user), 1e18);
        assertLt(dsce.getHealthFactor(liquidator), 1e18);


        // Liquidator try to liquidate 1 wei of user's debt but it will revert because of the check
        vm.startPrank(liquidator);
        dsc.approve(address(dsce), 1 ether);

        // system revert because `liquidator` has HF < 1
        vm.expectRevert();
        dsce.liquidate(weth, user, 1 ether);
        vm.stopPrank();


        vm.startPrank(liquidator);

        // Liquidator supply 1000 ether and supply them to have HF > 1
        ERC20Mock(weth).mint(liquidator, 1000 ether);
        ERC20Mock(weth).approve(address(dsce), 1000 ether);
        dsce.depositCollateral(weth, 1000 ether);

        
        uint256 liquidatorHFBefore = dsce.getHealthFactor(liquidator);
        assertGe(liquidatorHFBefore, 1e18);

        // perform liquidation again and prove that HF of liquidator does not change because of the liquidation itself
        dsc.approve(address(dsce), 1 ether);
        dsce.liquidate(weth, user, 1 ether);

        // The liquidator is using his own funds that do not impact the liquidator HF
        assertEq(dsce.getHealthFactor(liquidator), liquidatorHFBefore);
        vm.stopPrank();
    }
}
```

### Recommendations

The system should remove the check _revertIfHealthFactorIsBroken(msg.sender); in the liquidate() function, allowing a liquidator to always be able to liquidate a borrower.

## Medium-09 Protocol can break for a token with a proxy and implementation contract (like TUSD)

Tokens whose code and logic can be changed in future can break the protocol and lock user funds.

### Vulnerability Details

For a token like TUSD (supported by Chainlink TUSD/USD price feed), which has a proxy and implementation contract, if the implementation behind the proxy is changed, it can introduce features which break the protocol, like choosing to not return a bool on transfer(), or changing the balance over time like a rebasing token.

### Impact

Protocol may break in future for this collateral and block user funds deposited as collateral. Also can cause bad loans to be present with no way to liquidate them.

### Recommendations

Developers integrating with upgradable tokens should consider introducing logic that will freeze interactions with the token in question if an upgrade is detected. (e.g. the TUSD adapter used by MakerDAO).
OR have a token whitelist which does not allow such tokens.

## Medium-11. Liquidators can be front-run to their loss

DSC liquidators are prone to oracle price manipulations and MEV front-run attacks

### Vulnerability Details

Sudden token price changes caused by oracle price manipulations and MEV front-run can cause liquidators to get less than expected collateral tokens.

### Impact

Liquidators stand to earn less than expected collateral tokens for deposited DSC

### Recommendations

Function liquidate should have an input parameter uint256 minimumOutputTokens and the function should revert at Ln 253 if

```
require(totalCollateralToRedeem >= minimumOutputTokens, "Too little collateral received.");  
```

## Medium-10. DoS of full liquidations are possible by frontrunning the liquidators

Liquidators must specify precise amounts of DSC tokens to be burned during the liquidation process. Unfortunately, this opens up the possibility for malicious actors to prevent the full liquidation by frontrunning the liquidator's transaction and liquidating minimal amounts of DSC.

### Vulnerability Details

Liquidations play a crucial role by maintaining collateralization above the desired ratio. If the value of the collateral drops, or if the user mints too much DSC tokens and breaches the minimum required ratio, the position becomes undercollateralized, posing a risk to the protocol. Liquidations help in enforcing these collateralization ratios, enabling DSC to maintain its value.

After detecting an unhealthy position, any liquidator can call the liquidate() function to burn the excess DSC tokens and receive part of the user's collateral as reward. To execute this function, the liquidator must specify the precise amount of DSC tokens to be burned. Due to this requirement, it becomes possible to block full liquidations (i.e liquidations corresponding to the user's entire minted amounts of DSC). This can be achieved by any address other than the one undergoing liquidation. This includes either a secondary address of the user being liquidated (attempting to protect their collateral), or any other malicious actor aiming to obstruct the protocol's re-collaterization. The necessity of using any address other than the one undergoing liquidation is due to the _revertIfHealthFactorIsBroken(msg.sender) at the end of the liquidate() function, therefore any other healthy address can be used to perform this attack.

This blocking mechanism operates by frontrunning the liquidator and triggering the liquidation of small amounts of DSC balance. Consequently, during the liquidator's transaction execution, it attempts to burn more tokens than the user has actually minted. This causes a revert due to an underflow issue, as illustrated in the code snippet below.

```
function _burnDsc(uint256 amountDscToBurn, address onBehalfOf, address dscFrom) private {
    s_DSCMinted[onBehalfOf] -= amountDscToBurn; //Undeflow will happen here
    bool success = i_dsc.transferFrom(dscFrom, address(this), amountDscToBurn);
    if (!success) {
        revert DSCEngine__TransferFailed();
    }
    i_dsc.burn(amountDscToBurn);
}
```

### Impact

Full liquidations can be blocked. Therefore liquidators will have to resort to partial liquidations that are less efficient and can leave dust debt in the contract, threatening the heatlh of the protocol.

### Recommendations

Consider allowing the liquidator to pass type(uint256).max as the debtToCover parameter, which will result to liquidating all DSC minted by the target account, regardless of the current balance. See the code below for an example implementation.

```
diff --git a/DSCEngine.orig.sol b/DSCEngine.sol
index e7d5c0d..6feef25 100644
--- a/DSCEngine.orig.sol
+++ b/DSCEngine.sol
@@ -227,36 +227,40 @@ contract DSCEngine is ReentrancyGuard {
      * Follows CEI: Checks, Effects, Interactions
      */
     function liquidate(address collateral, address user, uint256 debtToCover)
         external
         moreThanZero(debtToCover)
         nonReentrant
     {
         // need to check health factor of the user
         uint256 startingUserHealthFactor = _healthFactor(user);
         if (startingUserHealthFactor >= MIN_HEALTH_FACTOR) {
             revert DSCEngine__HealthFactorOk();
         }
         // We want to burn their DSC "debt"
         // And take their collateral
         // Bad User: $140 ETH, $100 DSC
         // debtToCover = $100
         // $100 of DSC == ??? ETH?
         // 0.05 ETH
+        if (debtToCover == type(uint256).max) {
+            (uint256 dscMinted,) = _getAccountInformation(user);
+            debtToCover = dscMinted;
+        }
         uint256 tokenAmountFromDebtCovered = getTokenAmountFromUsd(collateral, debtToCover);
         // And give them a 10% bonus
         // So we are giving the liquidator $110 of WETH for 100 DSC
         // We should implement a feature to liquidate in the event the protocol is insolvent
         // And sweep extra amounts into a treasury
         // 0.05 * 0.1 = 0.005. Getting 0.055
         uint256 bonusCollateral = (tokenAmountFromDebtCovered * LIQUIDATION_BONUS) / LIQUIDATION_PRECISION;
         uint256 totalCollateralToRedeem = tokenAmountFromDebtCovered + bonusCollateral;
         _redeemCollateral(user, msg.sender, collateral, totalCollateralToRedeem);
         // We need to burn the DSC
         _burnDsc(debtToCover, user, msg.sender);

         uint256 endingUserHealthFactor = _healthFactor(user);
         if (endingUserHealthFactor <= startingUserHealthFactor) {
             revert DSCEngine__HealthFactorNotImproved();
         }
         _revertIfHealthFactorIsBroken(msg.sender);
     }
```






