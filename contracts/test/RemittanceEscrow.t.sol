// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {RemittanceEscrow, IERC20} from "../src/RemittanceEscrow.sol";
import {HonkVerifier, IVerifier} from "../src/HonkVerifier.sol";
import {MockUSDC} from "../src/MockUSDC.sol";

/// Replays a real bundle captured from `npm run demo` (TLSNotary attestation +
/// UltraHonk proof) against the contracts. The escrow's narration is derived
/// from (chainid, contract address, id), so the escrow is deployed at the same
/// address and chain id the demo used (`deployCodeTo` + `vm.chainId`).
///
/// Regenerate the fixture after changing the circuit, the notary or the
/// escrow: `npm run demo && npm run fixture`.
contract RemittanceEscrowTest is Test {
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    MockUSDC usdc;
    HonkVerifier honk;
    RemittanceEscrow escrow;
    address agent = address(0xA9E47);
    address notary;
    uint64 thresholdPaise;
    RemittanceEscrow.Attestation att;
    bytes sig;
    bytes proof;

    function setUp() public {
        string memory j = vm.readFile("test/fixtures/bundle.json");
        vm.chainId(vm.parseJsonUint(j, ".chainId"));
        usdc = new MockUSDC();
        honk = new HonkVerifier();
        notary = vm.parseJsonAddress(j, ".notary");
        thresholdPaise = uint64(vm.parseJsonUint(j, ".thresholdPaise"));
        address at = vm.parseJsonAddress(j, ".escrowAddress");
        deployCodeTo(
            "RemittanceEscrow.sol:RemittanceEscrow",
            abi.encode(
                address(usdc),
                address(honk),
                notary,
                vm.parseJsonString(j, ".serverName"),
                vm.parseJsonString(j, ".endpoint")
            ),
            at
        );
        escrow = RemittanceEscrow(at);
        att = RemittanceEscrow.Attestation({
            serverName: vm.parseJsonString(j, ".serverName"),
            endpoint: vm.parseJsonString(j, ".endpoint"),
            currency: vm.parseJsonString(j, ".currency"),
            narration: vm.parseJsonString(j, ".narration"),
            amountCommitment: vm.parseJsonBytes32(j, ".amountCommitment"),
            tsCommitment: vm.parseJsonBytes32(j, ".tsCommitment"),
            sessionTime: uint64(vm.parseJsonUint(j, ".sessionTime"))
        });
        sig = vm.parseJsonBytes(j, ".signature");
        proof = vm.parseJsonBytes(j, ".proof");

        // Recreate escrow #1 with the same minTs the proof was generated for.
        vm.warp(vm.parseJsonUint(j, ".minTs"));
        usdc.mint(address(this), 1_000e6);
        usdc.approve(address(escrow), type(uint256).max);
        escrow.createEscrow(agent, 500e6, thresholdPaise, 1 days);
        assertEq(escrow.narrationFor(1), att.narration, "fixture narration must match escrow #1");
    }

    // ------------------------------------------------------------ happy path

    function test_release_pays_beneficiary() public {
        uint256 g = gasleft();
        escrow.release(1, att, sig, proof);
        emit log_named_uint("release gas (incl. UltraHonk verify)", g - gasleft());
        assertEq(usdc.balanceOf(agent), 500e6);
        assertEq(usdc.balanceOf(address(escrow)), 0);
    }

    function test_anyone_can_submit_but_only_beneficiary_is_paid() public {
        address relayer = address(0xBEEF);
        vm.prank(relayer);
        escrow.release(1, att, sig, proof);
        assertEq(usdc.balanceOf(relayer), 0);
        assertEq(usdc.balanceOf(agent), 500e6);
    }

    // ------------------------------------------------------------ replay / binding

    function test_replay_reverts() public {
        escrow.release(1, att, sig, proof);
        vm.expectRevert(RemittanceEscrow.AlreadySettled.selector);
        escrow.release(1, att, sig, proof);
    }

    function test_wrong_narration_reverts() public {
        escrow.createEscrow(agent, 1e6, thresholdPaise, 1 days);
        vm.expectRevert(RemittanceEscrow.WrongNarration.selector);
        escrow.release(2, att, sig, proof);
    }

    /// One bank credit must not release escrow #1 on a second deployment that
    /// trusts the same notary (the old "POR-ESCROW-<id>" narration allowed it).
    function test_cross_deployment_replay_reverts() public {
        RemittanceEscrow other = new RemittanceEscrow(IERC20(address(usdc)), honk, notary, att.serverName, att.endpoint);
        usdc.approve(address(other), type(uint256).max);
        other.createEscrow(agent, 500e6, thresholdPaise, 1 days);
        vm.expectRevert(RemittanceEscrow.WrongNarration.selector);
        other.release(1, att, sig, proof);
    }

    function test_narration_is_domain_separated() public {
        string memory n1 = escrow.narrationFor(1);
        assertEq(bytes(n1).length, 24);
        assertTrue(keccak256(bytes(n1)) != keccak256(bytes(escrow.narrationFor(2))));
        vm.chainId(block.chainid + 1);
        assertTrue(keccak256(bytes(n1)) != keccak256(bytes(escrow.narrationFor(1))));
    }

    function testFuzz_narration_charset(uint256 id) public view {
        bytes memory n = bytes(escrow.narrationFor(id));
        assertEq(n.length, 24);
        assertEq(string(abi.encodePacked(n[0], n[1], n[2], n[3])), "POR-");
        for (uint256 i = 4; i < n.length; i++) {
            bytes1 c = n[i];
            assertTrue((c >= "0" && c <= "9") || (c >= "A" && c <= "F"));
        }
    }

    // ------------------------------------------------------------ ZK binding

    function test_tampered_proof_reverts() public {
        bytes memory bad = proof;
        bad[300] = bytes1(uint8(bad[300]) ^ 0x01);
        vm.expectRevert(RemittanceEscrow.ZkProofRejected.selector);
        escrow.release(1, att, sig, bad);
    }

    function testFuzz_any_flipped_proof_byte_reverts(uint256 index, uint8 mask) public {
        vm.assume(mask != 0);
        bytes memory bad = proof;
        index = bound(index, 0, bad.length - 1);
        bad[index] = bytes1(uint8(bad[index]) ^ mask);
        vm.expectRevert(RemittanceEscrow.ZkProofRejected.selector);
        escrow.release(1, att, sig, bad);
    }

    function test_empty_proof_reverts() public {
        vm.expectRevert(RemittanceEscrow.ZkProofRejected.selector);
        escrow.release(1, att, sig, "");
    }

    function test_higher_threshold_rejects_same_proof() public {
        // Same proof, but public input threshold raised to Rs 1,00,000.
        bytes32[] memory p = escrow.publicInputs(1, att);
        p[0] = bytes32(uint256(10_000_000));
        assertFalse(_verifies(p));
    }

    function test_later_min_ts_rejects_same_proof() public {
        bytes32[] memory p = escrow.publicInputs(1, att);
        p[1] = bytes32(uint256(p[1]) + 1 days);
        assertFalse(_verifies(p));
    }

    function test_swapped_commitment_order_rejects_same_proof() public {
        // Amount and ts commitments swapped in the public inputs.
        (att.amountCommitment, att.tsCommitment) = (att.tsCommitment, att.amountCommitment);
        assertFalse(_verifies(escrow.publicInputs(1, att)));
    }

    function test_threshold_comes_from_escrow_not_caller() public {
        // Escrow #2 has a higher threshold; its public inputs differ from #1's
        // even with the same attestation, so the caller cannot lower the bar.
        escrow.createEscrow(agent, 1e6, 10_000_000, 1 days);
        assertEq(uint256(escrow.publicInputs(2, att)[0]), 10_000_000);
        assertEq(uint256(escrow.publicInputs(1, att)[0]), thresholdPaise);
    }

    // ------------------------------------------------------------ notary signature

    function test_swapped_commitment_breaks_signature() public {
        att.amountCommitment = keccak256("an invented amount");
        vm.expectRevert(RemittanceEscrow.BadNotarySignature.selector);
        escrow.release(1, att, sig, proof);
    }

    function test_high_s_malleated_signature_reverts() public {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(SECP256K1_N - uint256(s));
        // The malleated form recovers the same signer through raw ecrecover...
        assertEq(ecrecover(_ethSigned(escrow.attestationDigest(att)), v2, r, s2), notary);
        // ...but the escrow refuses it.
        vm.expectRevert(RemittanceEscrow.BadNotarySignature.selector);
        escrow.release(1, att, abi.encodePacked(r, s2, v2), proof);
    }

    function test_bad_v_or_length_reverts() public {
        (bytes32 r, bytes32 s,) = _split(sig);
        vm.expectRevert(RemittanceEscrow.BadNotarySignature.selector);
        escrow.release(1, att, abi.encodePacked(r, s, uint8(0)), proof);
        vm.expectRevert(RemittanceEscrow.BadNotarySignature.selector);
        escrow.release(1, att, abi.encodePacked(r, s), proof);
    }

    function test_signature_from_other_key_reverts() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, _ethSigned(escrow.attestationDigest(att)));
        vm.expectRevert(RemittanceEscrow.BadNotarySignature.selector);
        escrow.release(1, att, abi.encodePacked(r, s, v), proof);
    }

    function test_session_facts_are_checked() public {
        RemittanceEscrow.Attestation memory a = att;
        a.currency = "USD";
        vm.expectRevert(RemittanceEscrow.WrongCurrency.selector);
        escrow.release(1, a, sig, proof);
        a = att;
        a.serverName = "evil.test";
        vm.expectRevert(RemittanceEscrow.WrongServer.selector);
        escrow.release(1, a, sig, proof);
        a = att;
        a.endpoint = "GET /api/v1/accounts/me/debits";
        vm.expectRevert(RemittanceEscrow.WrongEndpoint.selector);
        escrow.release(1, a, sig, proof);
        a = att;
        a.sessionTime = uint64(block.timestamp) - 1;
        vm.expectRevert(RemittanceEscrow.StaleSession.selector);
        escrow.release(1, a, sig, proof);
    }

    // ------------------------------------------------------------ accounting / access

    function test_expired_then_refund() public {
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(RemittanceEscrow.Expired.selector);
        escrow.release(1, att, sig, proof);
        uint256 before = usdc.balanceOf(address(this));
        vm.prank(address(0xCAFE)); // anyone may trigger the refund, it pays the depositor
        escrow.refund(1);
        assertEq(usdc.balanceOf(address(this)) - before, 500e6);
        vm.expectRevert(RemittanceEscrow.AlreadySettled.selector);
        escrow.refund(1);
    }

    function test_refund_before_expiry_reverts() public {
        vm.expectRevert(RemittanceEscrow.NotExpired.selector);
        escrow.refund(1);
    }

    function test_release_at_expiry_boundary() public {
        vm.warp(block.timestamp + 1 days); // == expiry: still releasable
        escrow.release(1, att, sig, proof);
        assertEq(usdc.balanceOf(agent), 500e6);
    }

    function test_refund_after_release_reverts() public {
        escrow.release(1, att, sig, proof);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(RemittanceEscrow.AlreadySettled.selector);
        escrow.refund(1);
    }

    function test_unknown_escrow_reverts() public {
        vm.expectRevert(RemittanceEscrow.UnknownEscrow.selector);
        escrow.release(99, att, sig, proof);
        vm.expectRevert(RemittanceEscrow.UnknownEscrow.selector);
        escrow.refund(99);
    }

    function test_create_escrow_validates_params() public {
        vm.expectRevert(RemittanceEscrow.InvalidEscrowParams.selector);
        escrow.createEscrow(address(0), 1e6, 1, 1 days);
        vm.expectRevert(RemittanceEscrow.InvalidEscrowParams.selector);
        escrow.createEscrow(agent, 0, 1, 1 days);
        vm.expectRevert(RemittanceEscrow.InvalidEscrowParams.selector);
        escrow.createEscrow(agent, 1e6, 0, 1 days);
        vm.expectRevert(RemittanceEscrow.InvalidEscrowParams.selector);
        escrow.createEscrow(agent, 1e6, 1, 0);
    }

    function test_constructor_rejects_zero_addresses() public {
        vm.expectRevert(RemittanceEscrow.ZeroAddress.selector);
        new RemittanceEscrow(IERC20(address(usdc)), honk, address(0), "a", "b");
        vm.expectRevert(RemittanceEscrow.ZeroAddress.selector);
        new RemittanceEscrow(IERC20(address(0)), honk, notary, "a", "b");
        vm.expectRevert(RemittanceEscrow.ZeroAddress.selector);
        new RemittanceEscrow(IERC20(address(usdc)), IVerifier(address(0)), notary, "a", "b");
    }

    function test_escrows_are_isolated() public {
        escrow.createEscrow(agent, 7e6, thresholdPaise, 1 days);
        escrow.release(1, att, sig, proof);
        assertEq(usdc.balanceOf(address(escrow)), 7e6, "escrow #2 funds untouched");
    }

    // ------------------------------------------------------------ helpers

    function _verifies(bytes32[] memory p) internal view returns (bool ok) {
        try honk.verify(proof, p) returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
    }

    function _ethSigned(bytes32 d) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", d));
    }

    function _split(bytes memory sg) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sg, 32))
            s := mload(add(sg, 64))
            v := byte(0, mload(add(sg, 96)))
        }
    }
}
