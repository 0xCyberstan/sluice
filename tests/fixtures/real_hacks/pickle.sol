// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Pickle Finance (Nov 21 2020) — ~$20M drained from the cDAI PickleJar.
// Root cause: the Controller's `swapExactJarForJar`-style routine moved funds
//   between a "from" jar and a "to" jar using a CALLER-SUPPLIED target jar, but
//   skipped the registry/solvency validation (`_validateJarSolvency`, the
//   `_checkJar` family) that every other fund-moving entry point enforced. The
//   attacker registered a fake "jar" with a controlled token, then used the
//   unchecked swap path to make the real jar pull from / settle against the
//   evil jar and withdraw the underlying — moving value without ever proving
//   the counterparty jar was a solvent, registry-blessed jar. The defect is a
//   CONSENSUS outlier: each function is well-formed, but one value-moving
//   function omits the settlement/solvency routine its siblings call.
// Expected detector: missing-solvency-check (SettlementBeforeMutation, Euler class).
//
// NOTE: Pickle's real guard was registry membership + want-token matching; it is
//   named `_validateJarSolvency` here (it asserts the jar is registered AND its
//   reserves cover its shares) so the routine reads as a settlement/solvency
//   check and the consensus invariant is mined from its sibling call sites.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PickleController {
    IERC20 public immutable want;
    mapping(address => bool) public registeredJar; // registry of blessed jars
    mapping(address => uint256) public jarShares;   // share accounting per jar
    mapping(address => uint256) public jarReserves; // underlying backing a jar

    constructor(IERC20 _want) {
        want = _want;
    }

    // Solvency invariant: the jar must be registry-blessed AND its reserves must
    // fully cover its outstanding shares before we move funds in/out of it.
    function _validateJarSolvency(address jar) internal view {
        require(registeredJar[jar], "unregistered jar");
        require(jarReserves[jar] >= jarShares[jar], "insolvent jar");
    }

    function deposit(address jar, uint256 amount) external {
        want.transferFrom(msg.sender, address(this), amount);
        jarReserves[jar] += amount;
        jarShares[jar] += amount;
        _validateJarSolvency(jar);
    }

    function withdraw(address jar, uint256 shares) external {
        jarShares[jar] -= shares;
        jarReserves[jar] -= shares;
        _validateJarSolvency(jar);
        want.transfer(msg.sender, shares);
    }

    function earn(address jar, uint256 amount) external {
        jarReserves[jar] += amount;
        _validateJarSolvency(jar);
    }

    function rebalance(address fromJar, address toJar, uint256 amount) external {
        jarReserves[fromJar] -= amount;
        jarReserves[toJar] += amount;
        _validateJarSolvency(fromJar);
        _validateJarSolvency(toJar);
    }

    // VULNERABLE: moves funds between a "from" jar and a caller-controlled
    // `toJar` but SKIPS _validateJarSolvency — so an attacker passes an
    // unregistered/insolvent jar and drains the real jar's reserves.
    function swapExactJarForJar(address fromJar, address toJar, uint256 amount) external {
        jarReserves[fromJar] -= amount;
        jarShares[toJar] += amount;
        want.transfer(toJar, amount);
    }
}
