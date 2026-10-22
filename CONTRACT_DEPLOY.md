# Smart contract — Step 23 (compile, test, deploy)

The contract is `contracts/DocumentNotary.sol`. It stores, for each document
fingerprint: who registered it and when (plus an optional, normally empty, IPFS id).
Nothing else. It has no owner, no admin, no way to edit or delete a record, and
it never holds money.

Do **Part 1 and 2 now, with no wallet and no cost.** Part 3 needs the wallet
from `BLOCKCHAIN_SETUP.md`, so do it later.

---

## Part 1 — Compile it in Remix (free, no wallet)

1. Open **remix.ethereum.org** (type it yourself).
2. In the file explorer, create a new file called `DocumentNotary.sol` and paste
   in the full contents of `contracts/DocumentNotary.sol`.
3. Open the **Solidity compiler** tab (left sidebar). Pick compiler version
   **0.8.20 or newer** and click **Compile DocumentNotary.sol**.
4. A green tick means it compiled. **If you see a red error, copy it exactly and
   send it to me** — I could not run a compiler in my sandbox, so this is the
   first real compile of the file.

## Part 2 — Try it on Remix's practice blockchain (free, no wallet)

1. Open the **Deploy & run transactions** tab.
2. Set **Environment** to **Remix VM (Cancun)** (or any "Remix VM"). This is a
   private sandbox inside your browser, with fake accounts that already hold
   fake money. Nothing is public.
3. Click **Deploy**. The contract appears under "Deployed Contracts".
4. Expand it and test these in order:

| Try this | Expect |
|---|---|
| `getRecord` with `0x` followed by 64 `a`s | `exists: false` (no error) |
| `registerDocument` with the same hash and cid `bafytestcid123` | succeeds |
| `getRecord` with that hash again | `exists: true`, your address, the cid, a timestamp |
| `registerDocument` with the **same hash again** | fails: `Already registered` |
| `registerDocument` with hash `0x` + 64 zeros | fails: `Hash cannot be empty` |
| `registerDocument` with a **new** hash and an empty cid | succeeds (fingerprint-only) |

(A hash is 32 bytes, so it is `0x` followed by exactly 64 hex characters, e.g.
`0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.)

If all six behave as shown, the contract does what it should.

## Part 3 — Deploy to Polygon Amoy (needs your wallet — do later)

Only after `python check_wallet_setup.py --online` says `all checks passed`.

1. In MetaMask, switch to **Polygon Amoy** and confirm the chain ID is `80002`.
2. In Remix → Deploy & run, set **Environment** to **Injected Provider – MetaMask**.
   Remix should now show `Custom (80002) network`. If it says anything else,
   stop and fix the network first.
3. Click **Deploy**. MetaMask asks you to confirm a small fee, paid in free test
   POL. Confirm.
4. After a few seconds, the contract appears under "Deployed Contracts". Click
   the **copy icon** next to it to copy the **contract address** (starts `0x`).
5. Paste it into `.env`:
   ```
   NOTARIZATION_CONTRACT_ADDRESS=0xYourContractAddress
   ```
6. Optional: look the address up on **amoy.polygonscan.com** to see it is live.

The ABI the app needs is already saved at
`static/contract/DocumentNotary.abi.json`, so there is nothing to copy out of
Remix. If you ever edit the contract, run `python check_contract_abi.py` to make
sure the ABI still matches.

## Part 4 — Switch on Notarize and Verify in the app

Two things must be in place, and the Documents page tells you which is missing:

1. **The contract address** in `.env` (Part 3, step 5).
2. **The ethers.js library**, served from your own project rather than a
   third-party site. Run this once (it needs internet):
   ```bash
   python vendor_ethers.py
   ```
   It saves a pinned copy to `static/vendor/ethers.umd.min.js` and prints its
   SHA-384 fingerprint. Compare that with the "SRI" value for ethers **6.13.4**
   on cdnjs.com/libraries/ethers, or pass it in to have the script check it:
   `python vendor_ethers.py --sha384 sha384-XXXX...`. **Commit that file** so a
   deployed copy of the app has it too.

Restart the app. Then:

- **Upload a document** and tick **Notarize this document**. Its fingerprint is
  saved and it shows *Ready to notarize*.
- Click **Notarize**. Your wallet opens and asks you to approve one small
  transaction (a few cents of free test POL). The app checks the transaction on
  the blockchain itself before it marks the document *Notarized*.
- Click **Verify** any time. It re-reads the file, looks up the blockchain
  record, and tells you whether the file is **unchanged** or **tampered**. Verify
  needs no wallet.

### Good to know

- **Deleting a notarized document** removes the file from your vault, but its
  fingerprint stays on the public blockchain forever. The delete prompt says so.
  The fingerprint alone reveals nothing about the file.
- **Two copies of the same file** have the same fingerprint, and a fingerprint
  can only be registered once. Notarizing the second copy will say it is already
  recorded.
- **If you close the tab** after approving in your wallet but before the app
  finishes saving the result, the document can stay at *Ready to notarize* even
  though the fingerprint is on the blockchain. Trying again then reports
  "already recorded". This is a known limit; tell me if you hit it and we will
  add a recovery step.
- **Fees** are paid in free test POL on Amoy. If a transaction says you have too
  little, use a faucet again (see `BLOCKCHAIN_SETUP.md`).

---

## Why there is no IPFS upload

Everything on a public blockchain is public and permanent, and so is anything on
public IPFS: anyone who learns a file's CID can download it. Notarizing a will or
an ID that way would publish it. So the Vault records **only the fingerprint**
and keeps your files private. The fingerprint is enough to prove a file has not
changed since a given date, without revealing what is in it. (The contract still
has an optional `cid` field, left empty, in case encrypted IPFS storage is added
later.)
