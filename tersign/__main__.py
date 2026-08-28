"""python3 -m tersign — CLI. v0.1: verify.

    python3 -m tersign verify <receipt.json>            offline (default, no network)
    python3 -m tersign verify 0x<digest> --ledger URL   chain lookup (explicit network)

Defaulting a digest lookup to a hosted ledger would turn an offline verification
into a silent network call for file inputs — so files never touch the network,
and digest lookups print the endpoint they hit.
"""
import json
import sys
import urllib.request

from . import verify_receipt, __version__


def main(argv):
    if len(argv) < 2 or argv[0] != "verify":
        print(__doc__)
        return 2
    target = argv[1]
    if target.startswith("0x") and len(target) == 66:
        ledger = "https://tersign.ai"
        if "--ledger" in argv:
            i = argv.index("--ledger")
            if i + 1 >= len(argv):  # a trailing flag must not IndexError
                print("--ledger requires a URL, e.g. --ledger https://tersign.ai")
                return 2
            ledger = argv[i + 1]
        url = "%s/v1/receipts/%s/verify" % (ledger.rstrip("/"), target)
        print("network lookup: %s" % url)
        with urllib.request.urlopen(url, timeout=30) as r:
            body = json.load(r)
        print(json.dumps(body, indent=2))
        cm = body.get("commitment")
        if cm:  # chains anchored under tersign-chain-commitment-v1 (since 2026-08-28)
            block = cm.get("bitcoinBlockHeight")
            print("commitment: seq <= %s committed (acc %s…) — %s%s" % (
                cm.get("seq"), str(cm.get("acc", ""))[:10], cm.get("status"),
                " block %s" % block if block else ""))
        return 0 if body.get("found") and body.get("chainOk") else 1

    artifact = json.load(open(target))
    if "artifact" in artifact:  # a bundle record file — verify its inner artifact
        artifact = artifact["artifact"]
    result = verify_receipt(artifact)
    print(json.dumps({"tersign": __version__, **result}, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
