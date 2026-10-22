"""
check_wallet_setup.py — Step 22

A read-only checker for the blockchain wallet/network setup. Run it AFTER you
have created your MetaMask wallet, added the Polygon Amoy network, and claimed
test POL from a faucet:

    python check_wallet_setup.py            # offline checks only
    python check_wallet_setup.py --online   # also asks the network (no keys)

It only ever reads PUBLIC information: your wallet address, the RPC URL, and
(with --online) the chain id and your address's public balance. It never asks
for, reads, or stores a seed phrase or private key, and it refuses to continue
if it finds something that looks like one in your .env.

Uses only the Python standard library — nothing extra to install.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

AMOY_CHAIN_ID = 80002
DEFAULT_RPC = "https://rpc-amoy.polygon.technology"
EXPLORER = "https://amoy.polygonscan.com"

# A private key is 64 hex chars (optionally 0x-prefixed). An address is 40.
_PRIVATE_KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

results = []


def report(status, label, detail=""):
    icon = {"PASS": "[ OK ]", "WARN": "[WARN]", "FAIL": "[FAIL]", "SKIP": "[skip]"}[status]
    print(f"{icon} {label}" + (f"\n         {detail}" if detail else ""))
    results.append(status)


def looks_like_seed_phrase(value):
    """12 or 24 lowercase words is the shape of a recovery phrase."""
    words = value.strip().split()
    return len(words) in (12, 15, 18, 21, 24) and all(w.isalpha() and w.islower() for w in words)


def rpc_call(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise RuntimeError(payload["error"].get("message", "RPC error"))
    return payload["result"]


def check_env_for_secrets():
    """Refuse to go on if any .env value looks like a private key or seed phrase."""
    env_path = os.path.join(BASE_DIR, ".env")
    if not os.path.isfile(env_path):
        report("WARN", ".env file found",
               "No .env yet. Copy .env.example to .env and fill in the values.")
        return True
    dangerous = []
    with open(env_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            if _PRIVATE_KEY_RE.match(value) or looks_like_seed_phrase(value):
                dangerous.append(key.strip())
    if dangerous:
        report("FAIL", "No secrets in .env",
               "These entries look like a private key or seed phrase: "
               + ", ".join(dangerous)
               + ".\n         Remove them NOW. This project never needs them. If they were "
               "ever shared or committed,\n         treat that wallet as compromised and "
               "make a fresh one.")
        return False
    report("PASS", "No private key or seed phrase found in .env")
    return True


def check_address():
    addr = os.environ.get("NOTARIZATION_WALLET_ADDRESS", "").strip()
    if not addr:
        report("FAIL", "Wallet address set",
               "NOTARIZATION_WALLET_ADDRESS is empty. Open MetaMask, click your account "
               "name to copy\n         the address (starts with 0x), and paste it into .env.")
        return None
    if _PRIVATE_KEY_RE.match(addr):
        report("FAIL", "Wallet address format",
               "That is 64 characters — it looks like a PRIVATE KEY, not an address. "
               "Remove it from .env.")
        return None
    if not _ADDRESS_RE.match(addr):
        report("FAIL", "Wallet address format",
               f"Expected 0x + 40 hex characters (42 total); got {len(addr)} characters.")
        return None
    report("PASS", "Wallet address looks valid", addr)
    return addr


def check_rpc_setting():
    rpc = os.environ.get("POLYGON_AMOY_RPC_URL", "").strip()
    if not rpc:
        report("PASS", "RPC URL", f"Not set — using the default {DEFAULT_RPC}")
        return DEFAULT_RPC
    if not rpc.startswith("https://"):
        report("FAIL", "RPC URL", "Should start with https://")
        return None
    report("PASS", "RPC URL set", rpc)
    return rpc


def check_online(rpc, addr):
    try:
        chain_hex = rpc_call(rpc, "eth_chainId", [])
    except (urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
        report("FAIL", "Reached the RPC endpoint", f"{type(exc).__name__}: {exc}\n"
               "         Public RPCs are sometimes down or rate-limited — try again, or set "
               "POLYGON_AMOY_RPC_URL\n         to another Amoy endpoint.")
        return
    report("PASS", "Reached the RPC endpoint")

    chain_id = int(chain_hex, 16)
    if chain_id == AMOY_CHAIN_ID:
        report("PASS", "Network is Polygon Amoy", f"chain id {chain_id}")
    elif chain_id == 137:
        report("FAIL", "Network is Polygon Amoy",
               "That RPC is Polygon MAINNET (chain id 137) — real money. Use an Amoy endpoint.")
        return
    else:
        report("FAIL", "Network is Polygon Amoy",
               f"Expected chain id {AMOY_CHAIN_ID}, but this endpoint reports {chain_id}.")
        return

    if not addr:
        report("SKIP", "Wallet has test POL", "Skipped — no valid wallet address.")
        return
    try:
        balance_wei = int(rpc_call(rpc, "eth_getBalance", [addr, "latest"]), 16)
    except (urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
        report("FAIL", "Read wallet balance", f"{type(exc).__name__}: {exc}")
        return
    pol = balance_wei / 10**18
    if balance_wei == 0:
        report("WARN", "Wallet has test POL",
               "Balance is 0. Claim some from a faucet (see BLOCKCHAIN_SETUP.md). "
               "Faucets usually\n         allow one request per wallet every 12-24 hours, and "
               "it can take a minute to arrive.")
    else:
        report("PASS", "Wallet has test POL", f"{pol:.4f} POL  ({EXPLORER}/address/{addr})")


def main():
    online = "--online" in sys.argv[1:]
    print("Digital Legacy Vault — wallet & network check (Step 22)\n")

    safe = check_env_for_secrets()
    if not safe:
        print("\nStopped: fix the secret in .env first.")
        sys.exit(1)

    addr = check_address()
    rpc = check_rpc_setting()

    if online and rpc:
        print()
        check_online(rpc, addr)
    elif not online:
        print("\n(Run with --online to also check the network and your balance.)")

    print()
    if "FAIL" in results:
        print("Result: some checks failed — see above.")
        sys.exit(1)
    if "WARN" in results:
        print("Result: OK so far, with warnings — see above.")
    else:
        print("Result: all checks passed.")


if __name__ == "__main__":
    main()
