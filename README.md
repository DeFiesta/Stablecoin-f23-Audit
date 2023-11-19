

# About

This project is meant to describe exploitable bugs detect on Cyfrin stablecoin project which aims to create a stablecoin where users can deposit WETH and WBTC in exchange for a token that will be pegged to the USD. Please find the source code here: https://github.com/DeFiesta/foundry-defi-stablecoin-f23

- [About](#about)
- [AuditReport](#AuditReport)
  - [H1-token with less than 18 decimals can be stolen](#H1)
  - [H2-Strict enforcement of the liquidation bonus is causing prevention of liquidation.](#H2)
  - [H3-small positions can not be liquidated](#H3)
  - [H4-Business Logic: Protocol Liquidation Arithmetic](#H4)
  - [M1-No arbitrum sequencer status check in cainlink feed](#M1)
  - [M2-protocol can consume stale price data or cannot operate on some EVM chains](#M2)
  - [M3-Chainlink oracle will return the wrong price if the aggregator hits minAnswer](#M3)


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

