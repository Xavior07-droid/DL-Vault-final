// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DocumentNotary
 * @notice Records that a document's fingerprint existed at a point in time,
 *         and who registered it. Used by the Digital Legacy Vault (Step 23).
 *
 * WHAT GOES ON-CHAIN (and nothing else):
 *   - hash:      the SHA-256 fingerprint of the file (32 bytes)
 *   - cid:       OPTIONAL. Where the file is pinned on IPFS, if the owner
 *                chose to publish it there. Empty means "fingerprint only",
 *                which is the default for the Vault: the file itself stays
 *                private and nothing but the hash is made public.
 *   - owner:     the wallet address that registered it
 *   - timestamp: the block time of registration
 *
 * NEVER on-chain: file contents, names, or any personal data. Everything
 * written here is PUBLIC and PERMANENT, and cannot be edited or deleted.
 *
 * RULES
 *   - First registration of a hash wins. It cannot be overwritten, so the
 *     original timestamp and owner can always be trusted.
 *   - Reading is free and needs no wallet.
 */
contract DocumentNotary {
    struct Record {
        address owner;     // 20 bytes
        uint64 timestamp;  // 8 bytes (packs into the same storage slot)
        string cid;
    }

    // A SHA-256 digest is exactly 32 bytes, so it fits a bytes32 with no loss.
    mapping(bytes32 => Record) private records;

    // IPFS CIDs are ~46 (v0) to ~60 (v1) characters. This cap just stops
    // anyone stuffing arbitrary data on-chain through the optional cid field.
    uint256 private constant MAX_CID_LENGTH = 128;

    event DocumentRegistered(
        bytes32 indexed hash,
        address indexed owner,
        string cid,
        uint256 timestamp
    );

    /**
     * @notice Register a document fingerprint.
     * @param hash SHA-256 of the file, as 32 bytes.
     * @param cid  The file's IPFS content id, or "" for fingerprint-only.
     */
    function registerDocument(bytes32 hash, string calldata cid) external {
        require(hash != bytes32(0), "Hash cannot be empty");

        // An empty cid is allowed: it means "fingerprint only".
        require(bytes(cid).length <= MAX_CID_LENGTH, "CID is too long");

        // timestamp == 0 means "never registered" (block.timestamp is never 0).
        require(records[hash].timestamp == 0, "Already registered");

        records[hash] = Record({
            owner: msg.sender,
            timestamp: uint64(block.timestamp),
            cid: cid
        });

        emit DocumentRegistered(hash, msg.sender, cid, block.timestamp);
    }

    /**
     * @notice Look up a fingerprint. Never reverts for an unknown hash —
     *         it returns exists = false, so the app can show "NOT NOTARIZED"
     *         instead of an error.
     */
    function getRecord(bytes32 hash)
        external
        view
        returns (
            bool exists,
            address owner,
            string memory cid,
            uint256 timestamp
        )
    {
        Record storage r = records[hash];
        if (r.timestamp == 0) {
            return (false, address(0), "", 0);
        }
        return (true, r.owner, r.cid, r.timestamp);
    }
}
