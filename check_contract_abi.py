"""
check_contract_abi.py — Step 23

Confirms static/contract/DocumentNotary.abi.json matches the public
functions and events declared in contracts/DocumentNotary.sol, and scans the
source for risky constructs. No compiler or network needed.

This is NOT a substitute for compiling: Remix does that (see CONTRACT_DEPLOY.md).
It catches the quiet mistake of editing the contract and forgetting the ABI.

    python check_contract_abi.py
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
SOL = os.path.join(BASE, "contracts", "DocumentNotary.sol")
ABI = os.path.join(BASE, "static", "contract", "DocumentNotary.abi.json")

problems = []


def check(ok, label, detail=""):
    print(("[ OK ] " if ok else "[FAIL] ") + label + (f"\n         {detail}" if detail and not ok else ""))
    if not ok:
        problems.append(label)


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def split_params(text):
    """'bytes32 hash, string calldata cid' -> [('bytes32','hash'), ('string','cid')]"""
    out = []
    for p in [x.strip() for x in text.split(",") if x.strip()]:
        parts = [w for w in p.split() if w not in ("calldata", "memory", "storage", "indexed")]
        out.append((parts[0], parts[-1] if len(parts) > 1 else ""))
    return out


src_raw = open(SOL, encoding="utf-8").read()
src = strip_comments(src_raw)
abi = json.load(open(ABI, encoding="utf-8"))

# ---- source hygiene --------------------------------------------------------
check("SPDX-License-Identifier" in src_raw, "Has an SPDX license line")
check(re.search(r"pragma solidity \^0\.8\.\d+;", src) is not None, "Pins Solidity 0.8.x (built-in overflow checks)")
check(src.count("{") == src.count("}"), "Braces are balanced", f"{src.count('{')} open vs {src.count('}')} close")
check(src.count("(") == src.count(")"), "Parentheses are balanced")
for bad in ["selfdestruct", "delegatecall", "tx.origin", "payable", "assembly", "onlyOwner", "transfer(", "send("]:
    check(bad not in src, f"Does not use '{bad}'")

# ---- functions: source vs ABI ---------------------------------------------
src_funcs = {}
for m in re.finditer(r"function\s+(\w+)\s*\((.*?)\)\s*([^{]*?)\{", src, flags=re.S):
    name, params, rest = m.group(1), m.group(2), m.group(3)
    if not re.search(r"\b(external|public)\b", rest):
        continue
    returns = re.search(r"returns\s*\((.*?)\)", rest, flags=re.S)
    src_funcs[name] = {
        "inputs": split_params(params),
        "outputs": split_params(returns.group(1)) if returns else [],
        "view": bool(re.search(r"\bview\b", rest)),
    }

abi_funcs = {e["name"]: e for e in abi if e["type"] == "function"}
check(set(src_funcs) == set(abi_funcs), "Same public functions in source and ABI",
      f"source={sorted(src_funcs)} abi={sorted(abi_funcs)}")
for name, f in src_funcs.items():
    a = abi_funcs.get(name)
    if not a:
        continue
    check([(i["type"], i["name"]) for i in a["inputs"]] == f["inputs"], f"{name}: inputs match",
          f"source={f['inputs']} abi={[(i['type'], i['name']) for i in a['inputs']]}")
    check([(o["type"], o["name"]) for o in a["outputs"]] == f["outputs"], f"{name}: outputs match",
          f"source={f['outputs']} abi={[(o['type'], o['name']) for o in a['outputs']]}")
    want = "view" if f["view"] else "nonpayable"
    check(a["stateMutability"] == want, f"{name}: stateMutability is '{want}'", f"abi says {a['stateMutability']}")

# ---- events: source vs ABI -------------------------------------------------
src_events = {}
for m in re.finditer(r"event\s+(\w+)\s*\((.*?)\)\s*;", src, flags=re.S):
    params = []
    for p in [x.strip() for x in m.group(2).split(",") if x.strip()]:
        words = p.split()
        params.append((words[0], words[-1], "indexed" in words))
    src_events[m.group(1)] = params
abi_events = {e["name"]: e for e in abi if e["type"] == "event"}
check(set(src_events) == set(abi_events), "Same events in source and ABI")
for name, params in src_events.items():
    a = abi_events.get(name)
    if a:
        check([(i["type"], i["name"], i["indexed"]) for i in a["inputs"]] == params, f"event {name}: fields match")

# ---- the properties that make the contract trustworthy ---------------------
check('require(records[hash].timestamp == 0, "Already registered")' in src,
      "Re-registering a hash is blocked (first registration wins)")
check("delete " not in src, "Nothing can be deleted")
check("CID cannot be empty" not in src, "Empty cid is allowed (fingerprint-only notarization)")
check("MAX_CID_LENGTH" in src, "cid length is still capped")
check(len([f for f in src_funcs.values() if not f["view"]]) == 1, "Exactly one state-changing function")

print()
if problems:
    print(f"{len(problems)} problem(s) found.")
    sys.exit(1)
print("All checks passed. Next: compile it in Remix (see CONTRACT_DEPLOY.md).")
