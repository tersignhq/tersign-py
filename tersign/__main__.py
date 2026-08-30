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
    if argv and argv[0] in ("--help", "-h", "help"):
        print(__doc__)
        return 0
    if argv and argv[0] in ("--version", "-V"):
        print(__version__)
        return 0
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

    # --help / -h / an unreadable path must not surface a traceback. The first thing a stranger
    # types at any CLI is --help, and on a package whose whole job is verification an unhandled
    # FileNotFoundError is the worst possible first impression. Found 2026-08-30 by installing
    # the PUBLISHED package into a clean venv and typing exactly that.
    if target in ("--help", "-h", "help"):
        print(__doc__)
        return 0
    try:
        with open(target) as fh:
            artifact = json.load(fh)
    except FileNotFoundError:
        print("no such file: %s\n\nA receipt path, or a 0x-prefixed 32-byte digest with --ledger."
              % target, file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print("%s is not JSON: %s" % (target, exc), file=sys.stderr)
        return 2
    if "artifact" in artifact:  # a bundle record file — verify its inner artifact
        artifact = artifact["artifact"]
    result = verify_receipt(artifact)
    print(json.dumps({"tersign": __version__, **result}, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
