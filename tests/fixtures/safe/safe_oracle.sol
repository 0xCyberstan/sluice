// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/// @notice Reads price from a Chainlink feed with full staleness/sanity checks.
///         No spot-price / single-DEX reads, so oracle-manipulation must stay silent.
contract SafePriceConsumer {
    AggregatorV3Interface public immutable feed;
    uint256 public constant MAX_STALENESS = 3600; // 1 hour heartbeat

    constructor(address _feed) {
        feed = AggregatorV3Interface(_feed);
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = feed.latestRoundData();

        // Staleness check: reject zero/old timestamps and stalled rounds.
        require(answer > 0, "negative price");
        require(updatedAt != 0, "round not complete");
        require(answeredInRound >= roundId, "stale price");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "price too old");

        return uint256(answer);
    }
}
