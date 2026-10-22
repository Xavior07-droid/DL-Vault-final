"""
vendor_ethers.py — Step 25

Downloads ONE pinned version of ethers.js and saves it inside this project
(static/vendor/ethers.umd.min.js), so the Documents page runs it from your own
server instead of loading code from a third-party CDN every time.

Run it once (needs internet), then commit the file so deployment includes it:

    python vendor_ethers.py
    python vendor_ethers.py --sha384 <hash>   # also check it against a hash you trust

Why this matters: the Documents page handles sensitive files. Pinning an exact
version and serving it yourself means nobody can swap different code in later.

It prints the file's SHA-384 fingerprint. For extra assurance, compare it with
the "SRI" value shown for ethers 6.13.4 on https://cdnjs.com/libraries/ethers
(the hashes are in the format sha384-XXXX...). Use --sha384 to have this script
check that for you and refuse to save the file on a mismatch.

Standard library only; nothing to install.
"""
import argparse
import base64
import hashlib
import os
import sys
import urllib.error
import urllib.request

VERSION = "6.13.4"
DEFAULT_URL = f"https://cdnjs.cloudflare.com/ajax/libs/ethers/{VERSION}/ethers.umd.min.js"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(BASE_DIR, "static", "vendor", "ethers.umd.min.js")

MIN_BYTES = 100_000       # the real file is several hundred KB
MAX_BYTES = 5_000_000


def sri_sha384(data):
    """The 'sha384-<base64>' form used for Subresource Integrity."""
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()


def check_looks_like_ethers(data):
    """Return an error string if this clearly isn't the ethers bundle, else None."""
    if len(data) < MIN_BYTES:
        return f"Only {len(data)} bytes — far too small to be ethers.js (expected 100 KB+)."
    if len(data) > MAX_BYTES:
        return f"{len(data)} bytes — far too large to be ethers.js."
    head = data[:200].lstrip().lower()
    if head.startswith(b"<!doctype") or head.startswith(b"<html"):
        return "That's a web page, not JavaScript (probably an error or login page)."
    if b"ethers" not in data[:5000000].lower():
        return "The file doesn't mention 'ethers' anywhere, so it doesn't look like the library."
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Download a pinned ethers.js into static/vendor/")
    parser.add_argument("--url", default=DEFAULT_URL, help="Where to download from (default: cdnjs, version %s)" % VERSION)
    parser.add_argument("--sha384", default="", help="Expected SRI hash (sha384-...). Refuse to save on mismatch.")
    parser.add_argument("--out", default=TARGET, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    print(f"Downloading ethers {VERSION}\n  from {args.url}")
    try:
        with urllib.request.urlopen(args.url, timeout=30) as resp:
            data = resp.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        print(f"\n[FAIL] Couldn't download it: {exc}")
        print("       Check your internet connection and try again.")
        return 1

    problem = check_looks_like_ethers(data)
    if problem:
        print(f"\n[FAIL] {problem}\n       Nothing was saved.")
        return 1

    digest = sri_sha384(data)
    if args.sha384 and args.sha384.strip() != digest:
        print("\n[FAIL] The downloaded file does NOT match the hash you gave.")
        print(f"       expected: {args.sha384.strip()}")
        print(f"       got:      {digest}")
        print("       Nothing was saved. Don't use this file.")
        return 1

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".part"
    with open(tmp, "wb") as fh:           # write fully, then swap in, so a
        fh.write(data)                    # failed run never leaves half a file
    os.replace(tmp, args.out)

    print(f"\n[ OK ] Saved {len(data):,} bytes to {os.path.relpath(args.out, BASE_DIR)}")
    print(f"       SHA-384: {digest}")
    if args.sha384:
        print("       Matches the hash you provided.")
    else:
        print("       Tip: compare that with the SRI shown for ethers %s on cdnjs.com/libraries/ethers," % VERSION)
        print("       or re-run with --sha384 <that hash> to have this script check it.")
    print("\nNow commit static/vendor/ethers.umd.min.js so deployments include it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
