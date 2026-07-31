// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {CatallaxyConsent} from "../contracts/CatallaxyConsent.sol";
import {Scopes} from "../contracts/lib/Scopes.sol";
import {RevertingReceiver} from "./mocks/MockVerifier.sol";

contract CatallaxyConsentTest is Base {
    uint128 constant PRICE_PER_DAY = 1 ether;
    uint32 constant TERM = 10;

    uint256 tokenId;

    function setUp() public override {
        super.setUp();
        tokenId = _registerAlice();

        vm.startPrank(alice);
        consent.setPolicy(tokenId, Scopes.BATTERY_HEALTH, PRICE_PER_DAY, 1, 365, true);
        consent.setPolicy(tokenId, Scopes.LOCATION_PRECISE, 50 ether, 1, 30, false);
        vm.stopPrank();
    }

    function _rate(uint128 pricePerDay, uint32 termDays) internal pure returns (uint256) {
        return (uint256(pricePerDay) * termDays) / (uint256(termDays) * 1 days);
    }

    // ------------------------------------------------------------------- scoping

    /// Buying the cheap scope must not open the expensive one. In the original
    /// sketch the grant was keyed by subscriber alone, so one day of battery data
    /// bought a precise location trace for free.
    function test_grantsAreScoped() public {
        uint256 cost = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.prank(insurer);
        consent.subscribe{value: cost}(tokenId, Scopes.BATTERY_HEALTH, TERM);

        assertTrue(consent.hasAccess(tokenId, Scopes.BATTERY_HEALTH, insurer));
        assertFalse(consent.hasAccess(tokenId, Scopes.LOCATION_PRECISE, insurer));
        assertFalse(consent.hasAccess(tokenId, Scopes.DIAGNOSTICS, insurer));
    }

    function test_onlyVehicleOwnerSetsPolicy() public {
        vm.prank(insurer);
        vm.expectRevert(CatallaxyConsent.NotVehicleOwner.selector);
        consent.setPolicy(tokenId, Scopes.DIAGNOSTICS, PRICE_PER_DAY, 1, 30, false);
    }

    function test_termBoundsEnforced() public {
        vm.prank(alice);
        consent.setPolicy(tokenId, Scopes.USAGE, PRICE_PER_DAY, 7, 30, false);

        vm.prank(insurer);
        vm.expectRevert(CatallaxyConsent.TermOutOfBounds.selector);
        consent.subscribe{value: 100 ether}(tokenId, Scopes.USAGE, 3);
    }

    // ---------------------------------------------------------------- settlement

    function test_fullTermSettlesToOwnerNetOfFee() public {
        uint256 rate = _rate(PRICE_PER_DAY, TERM);
        uint256 cost = rate * (uint256(TERM) * 1 days);

        vm.prank(insurer);
        consent.subscribe{value: consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM)}(
            tokenId, Scopes.BATTERY_HEALTH, TERM
        );

        vm.warp(block.timestamp + uint256(TERM) * 1 days);
        consent.settle(tokenId, Scopes.BATTERY_HEALTH, insurer);

        uint256 fee = (cost * FEE_BPS) / 10_000;
        assertEq(consent.credits(alice), cost - fee, "owner takes the stream net of the capped DAO fee");
        assertEq(consent.credits(treasury), fee);
        assertFalse(consent.hasAccess(tokenId, Scopes.BATTERY_HEALTH, insurer));
    }

    /// Revocation is only credible if it is costless to exercise and fair to the
    /// buyer: delivered seconds pay, undelivered seconds refund.
    function test_revokeMidTermRefundsUnearnedEscrow() public {
        uint256 rate = _rate(PRICE_PER_DAY, TERM);
        uint256 cost = rate * (uint256(TERM) * 1 days);
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.prank(insurer);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);
        uint256 dust = quoted - cost; // truncation remainder, credited at subscribe

        vm.warp(block.timestamp + 3 days);
        vm.prank(alice);
        consent.revokeAccess(tokenId, Scopes.BATTERY_HEALTH, insurer);

        uint256 earned = rate * 3 days;
        uint256 fee = (earned * FEE_BPS) / 10_000;

        assertFalse(consent.hasAccess(tokenId, Scopes.BATTERY_HEALTH, insurer), "access ends immediately");
        assertEq(consent.credits(alice), earned - fee);
        assertEq(consent.credits(treasury), fee);
        assertEq(consent.credits(insurer), dust + (cost - earned), "buyer gets every unearned wei back");
    }

    /// A mid-term sale must stop the seller's revenue at the moment of sale, and must
    /// not silently hand the buyer of the car a live insurer feed.
    function test_saleStopsSellerEarningsAtTransferTime() public {
        uint256 rate = _rate(PRICE_PER_DAY, TERM);
        uint256 cost = rate * (uint256(TERM) * 1 days);
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.prank(insurer);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);
        uint256 dust = quoted - cost;

        vm.warp(block.timestamp + 2 days);
        vm.prank(alice);
        vinReg.transferFrom(alice, researcher, tokenId);

        assertFalse(consent.hasAccess(tokenId, Scopes.BATTERY_HEALTH, insurer), "grant dies with the epoch");

        // Even if nobody settles for another week, the seller earns only up to the sale.
        vm.warp(block.timestamp + 7 days);
        consent.settle(tokenId, Scopes.BATTERY_HEALTH, insurer);

        uint256 earned = rate * 2 days;
        uint256 fee = (earned * FEE_BPS) / 10_000;
        assertEq(consent.credits(alice), earned - fee, "seller paid only for delivered time");
        assertEq(consent.credits(researcher), 0, "new owner inherits no revenue from a grant they never gave");
        assertEq(consent.credits(insurer), dust + (cost - earned));
    }

    function test_overpaymentIsCreditedNotRetained() public {
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.prank(insurer);
        consent.subscribe{value: quoted + 5 ether}(tokenId, Scopes.BATTERY_HEALTH, TERM);

        uint256 rate = _rate(PRICE_PER_DAY, TERM);
        uint256 cost = rate * (uint256(TERM) * 1 days);
        assertEq(consent.credits(insurer), quoted + 5 ether - cost);
    }

    function test_underpaymentReverts() public {
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.prank(insurer);
        vm.expectRevert(CatallaxyConsent.InsufficientPayment.selector);
        consent.subscribe{value: quoted - 1}(tokenId, Scopes.BATTERY_HEALTH, TERM);
    }

    function test_cannotStackGrantsBeforeSettling() public {
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.startPrank(insurer);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);
        vm.expectRevert(CatallaxyConsent.GrantOutstanding.selector);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);
        vm.stopPrank();
    }

    function test_settleBeforeCutoffReverts() public {
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);
        vm.prank(insurer);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(CatallaxyConsent.NotSettleableYet.selector);
        consent.settle(tokenId, Scopes.BATTERY_HEALTH, insurer);
    }

    // ------------------------------------------------------------ payout safety

    /// An owner address that reverts on receive must not be able to take the whole
    /// subscription path down with it. The original sketch pushed `msg.value` to the
    /// owner inside `subscribeToData`, which turns any such address — a multisig with
    /// a strict fallback, a contract that ran out of gas — into a market-wide DoS.
    function test_revertingOwnerCannotBlockTheMarket() public {
        RevertingReceiver hostileOwner = new RevertingReceiver();
        uint256 id = _register(address(hostileOwner), "5YJ3E1EA7KF000777", bytes32("salt-7"));

        vm.prank(address(hostileOwner));
        consent.setPolicy(id, Scopes.BATTERY_HEALTH, PRICE_PER_DAY, 1, 30, false);

        uint256 quoted = consent.quote(id, Scopes.BATTERY_HEALTH, TERM);
        vm.prank(insurer);
        consent.subscribe{value: quoted}(id, Scopes.BATTERY_HEALTH, TERM);

        vm.warp(block.timestamp + uint256(TERM) * 1 days);
        consent.settle(id, Scopes.BATTERY_HEALTH, insurer);

        assertGt(consent.credits(address(hostileOwner)), 0, "revenue accrues; collecting it is their problem");
    }

    function test_withdrawPaysOut() public {
        uint256 quoted = consent.quote(tokenId, Scopes.BATTERY_HEALTH, TERM);
        vm.prank(insurer);
        consent.subscribe{value: quoted}(tokenId, Scopes.BATTERY_HEALTH, TERM);

        vm.warp(block.timestamp + uint256(TERM) * 1 days);
        consent.settle(tokenId, Scopes.BATTERY_HEALTH, insurer);

        uint256 owed = consent.credits(alice);
        uint256 before = alice.balance;
        vm.prank(alice);
        consent.withdraw();

        assertEq(alice.balance, before + owed);
        assertEq(consent.credits(alice), 0);
    }

    // ---------------------------------------------------------------- governance

    function test_feeCapIsHard() public {
        vm.expectRevert(CatallaxyConsent.FeeTooHigh.selector);
        consent.setFee(consent.MAX_FEE_BPS() + 1, treasury);

        consent.setFee(consent.MAX_FEE_BPS(), treasury);
        assertEq(consent.feeBps(), consent.MAX_FEE_BPS());
    }

    function test_governanceHasNoHandleOnAnIndividualVehicle() public {
        // There is deliberately no owner-gated path to a vehicle's policies. The
        // registry's `onlyOwner` surface is attestors; consent's is the fee. If this
        // assertion ever needs changing, polycentricity has been lost.
        vm.expectRevert(CatallaxyConsent.NotVehicleOwner.selector);
        consent.setPolicy(tokenId, Scopes.BATTERY_HEALTH, 0, 1, 30, false);
    }

    /// Zero is a legitimate price: donating telemetry to a research pool is a choice
    /// the market has to be able to express.
    function test_freeConsentIsExpressible() public {
        vm.prank(alice);
        consent.setPolicy(tokenId, Scopes.DIAGNOSTICS, 0, 1, 30, true);

        vm.prank(researcher);
        consent.subscribe{value: 0}(tokenId, Scopes.DIAGNOSTICS, 30);
        assertTrue(consent.hasAccess(tokenId, Scopes.DIAGNOSTICS, researcher));
    }

    function test_priceTooLowToStreamIsRejected() public {
        vm.prank(alice);
        vm.expectRevert(CatallaxyConsent.PriceTooLowForStreaming.selector);
        consent.setPolicy(tokenId, Scopes.USAGE, 1000, 1, 30, false);
    }
}
