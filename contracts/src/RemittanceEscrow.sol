// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IVerifier} from "./HonkVerifier.sol";

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title  RemittanceEscrow
/// @notice Releases escrowed USDC when someone proves, from a TLSNotary-notarized
///         HTTPS session with a bank, that an INR credit of at least
///         `thresholdPaise` carrying this escrow's narration (see `narrationFor`)
///         landed after the escrow was created.
///
/// Two independent checks, both on-chain:
///   1. Notary signature (secp256k1, EIP-191) over the session facts it saw:
///      server name, endpoint, currency, narration, and SHA-256 commitments to
///      the hidden amount and timestamp.  -> "this came from the bank's TLS session"
///   2. UltraHonk ZK proof that the committed amount >= threshold and the
///      committed timestamp >= escrow creation time.  -> "the hidden values pass"
///
/// The contract never sees the amount, the timestamp, the account, the UTR
/// reference or the balance.
contract RemittanceEscrow {
    struct Escrow {
        address depositor;
        address beneficiary;
        uint256 usdcAmount;
        uint64 thresholdPaise; // INR amount in paise (1 INR = 100 paise)
        uint64 minTs; // credit must be timestamped at or after this
        uint64 expiry;
        bool settled;
    }

    struct Attestation {
        string serverName;
        string endpoint;
        string currency;
        string narration;
        bytes32 amountCommitment;
        bytes32 tsCommitment;
        uint64 sessionTime;
    }

    bytes32 public constant VERSION_HASH = keccak256("POR_TLSN_V1");

    IERC20 public immutable usdc;
    IVerifier public immutable zkVerifier;
    address public immutable notary;
    bytes32 public immutable serverNameHash;
    bytes32 public immutable endpointHash;

    uint256 public nextId = 1;
    mapping(uint256 => Escrow) public escrows;

    event EscrowCreated(
        uint256 indexed id,
        address depositor,
        address beneficiary,
        uint256 usdcAmount,
        uint64 thresholdPaise,
        uint64 minTs,
        string narration
    );
    event Released(uint256 indexed id, address beneficiary, uint256 usdcAmount, bytes32 amountCommitment);
    event Refunded(uint256 indexed id);

    error UnknownEscrow();
    error AlreadySettled();
    error Expired();
    error NotExpired();
    error WrongServer();
    error WrongEndpoint();
    error WrongCurrency();
    error WrongNarration();
    error BadNotarySignature();
    error StaleSession();
    error ZkProofRejected();
    error ZeroAddress();
    error InvalidEscrowParams();

    constructor(IERC20 _usdc, IVerifier _zk, address _notary, string memory serverName, string memory endpoint) {
        // A zero notary would make `_recover`'s address(0) failure value a
        // valid signer, i.e. any garbage signature would pass.
        if (address(_usdc) == address(0) || address(_zk) == address(0) || _notary == address(0)) {
            revert ZeroAddress();
        }
        usdc = _usdc;
        zkVerifier = _zk;
        notary = _notary;
        serverNameHash = keccak256(bytes(serverName));
        endpointHash = keccak256(bytes(endpoint));
    }

    function createEscrow(address beneficiary, uint256 usdcAmount, uint64 thresholdPaise, uint64 ttl)
        external
        returns (uint256 id)
    {
        if (beneficiary == address(0) || usdcAmount == 0 || thresholdPaise == 0 || ttl == 0) {
            revert InvalidEscrowParams();
        }
        id = nextId++;
        escrows[id] = Escrow({
            depositor: msg.sender,
            beneficiary: beneficiary,
            usdcAmount: usdcAmount,
            thresholdPaise: thresholdPaise,
            minTs: uint64(block.timestamp),
            expiry: uint64(block.timestamp) + ttl,
            settled: false
        });
        require(usdc.transferFrom(msg.sender, address(this), usdcAmount), "transferFrom");
        emit EscrowCreated(
            id, msg.sender, beneficiary, usdcAmount, thresholdPaise, uint64(block.timestamp), narrationFor(id)
        );
    }

    /// @notice The narration the INR payer must put on the transfer:
    ///         "POR-" followed by 20 uppercase hex characters (80 bits) of
    ///         keccak256(chainid, this contract, id).
    /// @dev    The narration is the only thing tying a bank credit to an
    ///         escrow, and the notary signature carries no chain id or
    ///         contract address. A bare "POR-ESCROW-<id>" would let one credit
    ///         release escrow #1 on every deployment and chain that trusts the
    ///         same notary. Hashing the deployment into the narration gives
    ///         each escrow, everywhere, its own reference. 24 characters fits
    ///         IMPS and UPI remark limits, and the notary's [A-Za-z0-9_-]
    ///         charset.
    function narrationFor(uint256 id) public view returns (string memory) {
        bytes32 h = keccak256(abi.encode(block.chainid, address(this), id));
        bytes memory out = new bytes(24);
        out[0] = "P";
        out[1] = "O";
        out[2] = "R";
        out[3] = "-";
        bytes16 hexChars = "0123456789ABCDEF";
        for (uint256 i = 0; i < 10; i++) {
            uint8 b = uint8(h[i]);
            out[4 + 2 * i] = hexChars[b >> 4];
            out[5 + 2 * i] = hexChars[b & 0x0f];
        }
        return string(out);
    }

    /// @notice Same digest the notary signs (see prover-rs/src/common.rs).
    function attestationDigest(Attestation calldata a) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VERSION_HASH,
                keccak256(bytes(a.serverName)),
                keccak256(bytes(a.endpoint)),
                keccak256(bytes(a.currency)),
                keccak256(bytes(a.narration)),
                a.amountCommitment,
                a.tsCommitment,
                uint256(a.sessionTime)
            )
        );
    }

    /// @notice Public inputs of the Noir circuit, in declaration order:
    ///         threshold_paise, min_ts, amount_hash[32], ts_hash[32].
    function publicInputs(uint256 id, Attestation calldata a) public view returns (bytes32[] memory p) {
        Escrow storage e = escrows[id];
        p = new bytes32[](66);
        p[0] = bytes32(uint256(e.thresholdPaise));
        p[1] = bytes32(uint256(e.minTs));
        for (uint256 i = 0; i < 32; i++) {
            p[2 + i] = bytes32(uint256(uint8(a.amountCommitment[i])));
            p[34 + i] = bytes32(uint256(uint8(a.tsCommitment[i])));
        }
    }

    function release(uint256 id, Attestation calldata a, bytes calldata notarySig, bytes calldata zkProof) external {
        Escrow storage e = escrows[id];
        if (e.depositor == address(0)) revert UnknownEscrow();
        if (e.settled) revert AlreadySettled();
        if (block.timestamp > e.expiry) revert Expired();

        // 1. Session facts bound to this escrow.
        if (keccak256(bytes(a.serverName)) != serverNameHash) revert WrongServer();
        if (keccak256(bytes(a.endpoint)) != endpointHash) revert WrongEndpoint();
        if (keccak256(bytes(a.currency)) != keccak256("INR")) revert WrongCurrency();
        if (keccak256(bytes(a.narration)) != keccak256(bytes(narrationFor(id)))) revert WrongNarration();
        if (a.sessionTime < e.minTs) revert StaleSession();

        // 2. Notary signature.
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", attestationDigest(a)));
        address signer = _recover(h, notarySig);
        if (signer == address(0) || signer != notary) revert BadNotarySignature();

        // 3. ZK predicate over the hidden amount and timestamp.
        bool ok;
        try zkVerifier.verify(zkProof, publicInputs(id, a)) returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
        if (!ok) revert ZkProofRejected();

        e.settled = true;
        require(usdc.transfer(e.beneficiary, e.usdcAmount), "transfer");
        emit Released(id, e.beneficiary, e.usdcAmount, a.amountCommitment);
    }

    function refund(uint256 id) external {
        Escrow storage e = escrows[id];
        if (e.depositor == address(0)) revert UnknownEscrow();
        if (e.settled) revert AlreadySettled();
        if (block.timestamp <= e.expiry) revert NotExpired();
        e.settled = true;
        require(usdc.transfer(e.depositor, e.usdcAmount), "transfer");
        emit Refunded(id);
    }

    function _recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        // Reject malleable high-s signatures.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        if (v != 27 && v != 28) return address(0);
        return ecrecover(h, v, r, s);
    }
}
