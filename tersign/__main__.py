"""python3 -m tersign — CLI. v0.1: verify.

    python3 -m tersign verify <receipt.json> [--signer 0xADDRESS]   offline, no network
    python3 -m tersign verify 0x<digest> [--ledger URL]             chain lookup (network)

--signer binds the receipt to its issuer: pass the issuer's address, obtained out-of-band
(from the issuer through a channel you trust, never from the receipt itself). Without it the
signer is reported UNAUTHENTICATED, because a signature recovers to SOME address for any
payload: an unbound PASS proves neither who signed nor that the receipt is unmodified.
Receipts signed with a published test key are flagged either way.

An evidence-bundle record file (records/NNNNNN.json) is accepted: the receipt nested under its
`artifact` is what gets verified, and the verdict says so and lists the record's own fields
(seq, format, artifactDigest, prevDigest, linkDigest, countersignature) as NOT checked - the
bundle verifier (verify/verify_bundle.py) checks those. A file with any other field beside `artifact`
is refused: a reader would take its top-level fields for the receipt that was checked.

Exit status: 0 PASS (read `verdict` - an unbound or test-key PASS is qualified there; a
digest lookup's verdict is `PASS (ledger-reported)`: the ledger's own answer, nothing verified
locally), 1 FAIL, 2 usage.

Defaulting a digest lookup to a hosted ledger would turn an offline verification
into a silent network call for file inputs — so files never touch the network,
and digest lookups print the endpoint they hit.
"""
import json
import re
import sys
import urllib.error
import urllib.request

from . import verify_receipt, __version__
from .verify import ADDRESS_RE

# \A...\Z plus fullmatch (see verify.ADDRESS_RE): "0x<digest>\n" is not a digest.
DIGEST_RE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z")

# Every option this CLI accepts. Anything else is refused: `--signer` used to be silently
# dropped here, so `verify r.json --signer 0xWRONG` printed the same PASS as an unbound run and
# the operator believed a binding had been checked that never ran — an unearned confidence is
# the worst shape a verifier can have. An unknown flag is now a usage error, never a no-op.
OPTIONS = {"--signer": "--signer 0x<issuer address>", "--ledger": "--ledger https://tersign.ai"}

SIGNED_FIELDS_TEXT = "version, network, resourceUrl, payer, issuedAt, transaction"

# The fields an evidence-bundle record file carries beside the signed receipt under `artifact`
# (records/NNNNNN.json; spec/evidence-bundle-v1.md). The CLI unwraps `artifact` ONLY when every
# other key is one of these. It used to unwrap any object with an `artifact` key, so a fabricated
# top-level receipt wrapped around a genuine issuer-signed one printed the plain BOUND PASS -
# "the signed receipt fields (...) were signed by <issuer>" - for top-level fields it never
# checked. The verdict must describe exactly the object whose signature was checked.
RECORD_FIELDS = ("seq", "format", "artifactDigest", "prevDigest", "linkDigest", "countersignature")


def _quoted(text, limit=40):
    """File-supplied text as it may appear in a verdict: JSON-quoted and length-bounded, so a
    key or value chosen by whoever wrote the file can never read as the tool's own sentence."""
    text = str(text)
    return json.dumps(text if len(text) <= limit else text[:limit] + "...")


class _Usage(Exception):
    pass


class _DuplicateKey(ValueError):
    pass


class _NotOneReceipt(ValueError):
    pass


def _no_dupes(pairs):
    """json object_pairs_hook refusing duplicate keys — the bundle verifier's rule, here too.

    json.load is last-wins while a human reader and most first-wins parsers take the FIRST, so
    two "resourceUrl" keys would let the file a reader sees differ from the value this CLI
    checked, under a PASS.
    """
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise _DuplicateKey("duplicate key %s - one JSON object, two values for one name"
                                % _quoted(k))
        seen[k] = v
    return seen


def _parse(args):
    """verify's arguments -> (target, {option: value}). Raises _Usage on anything ambiguous."""
    target, opts, i = None, {}, 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            if a not in OPTIONS:
                raise _Usage("unknown option %s (accepted: %s)" % (a, ", ".join(sorted(OPTIONS))))
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                raise _Usage("%s requires a value, e.g. %s" % (a, OPTIONS[a]))
            if a in opts:
                raise _Usage("%s given twice" % a)
            opts[a] = args[i + 1]
            i += 2
            continue
        if target is not None:
            raise _Usage("one receipt path or digest per run (got %s and %s)" % (target, a))
        target = a
        i += 1
    if target is None:
        raise _Usage("verify needs a receipt path or a 0x-prefixed 32-byte digest")
    return target, opts


def _signer_status(r):
    if not r.get("signer"):
        return None
    if r["signerBound"]:
        return "BOUND"
    return "MISMATCH" if r.get("reason") else "UNAUTHENTICATED"


def _verdict(r, expected, record_fields=None):
    """One sentence that never says more than the checks behind it.

    Everything interpolated here is derived (a recovered address, a count), validated (the
    --signer hex), from this package's own tables, or passed through _quoted() at the point it
    was read. `reason` is this package's own message text: the library's errors name fixed
    fields, types and integers, and the two that name file content (_DuplicateKey,
    _NotOneReceipt) quote it through _quoted(). unsignedFields is the file's own key names, so
    the verdict states their number and leaves the names to the machine-readable field.
    """
    if not r["valid"]:
        if r.get("signer") and expected:
            return ("FAIL - the signature recovers to %s, not to the --signer %s: this receipt "
                    "was not signed by that key, or was altered after signing."
                    % (r["signer"], expected))
        return "FAIL - %s" % r.get("reason", "invalid receipt")
    s, test_key = r["signer"], r.get("testKey")
    what = "the record's nested `artifact`" if record_fields is not None else "the receipt"
    qualifiers = []
    if r["signerBound"]:
        body = ("the signed receipt fields (%s) of %s were signed by %s, the address you "
                "supplied with --signer. The binding is only as strong as the channel that "
                "address came from." % (SIGNED_FIELDS_TEXT, what, s))
    else:
        qualifiers.append("signer UNAUTHENTICATED")
        body = ("the signature of %s recovers to %s, but no --signer was supplied, so nothing "
                "binds that address to the issuer. This proves neither who signed nor that the "
                "receipt is unmodified: an edited receipt recovers a different address and "
                "reaches this same line. For authorship, re-run with --signer <the issuer's "
                "address, obtained out-of-band>." % (what, s))
    if test_key:
        qualifiers.append("published test key")
    if record_fields is not None:
        qualifiers.append("record artifact only")
    notes = ""
    if test_key:
        notes += (" %s is a PUBLISHED test key (%s): anyone can produce this signature, so it "
                  "is not evidence of who issued the receipt." % (s, test_key))
    n = len(r.get("unsignedFields") or ())
    if n:
        notes += (" %d field%s the signature does not cover %s listed in unsignedFields."
                  % (n, "" if n == 1 else "s", "is" if n == 1 else "are"))
    if record_fields is not None:
        notes += (" The record's own fields (%s) were NOT checked: this verifies the receipt "
                  "inside a bundle record, not its place in the chain or the ledger's "
                  "countersignature - the bundle verifier (verify/verify_bundle.py) checks those."
                  % ", ".join(record_fields))
    head = "PASS (%s)" % ", ".join(qualifiers) if qualifiers else "PASS"
    return "%s - %s%s" % (head, body, notes)


def _report(result, expected, record_fields=None):
    """CLI output: the library result, led by a verdict and an explicit signer status."""
    out = {"tersign": __version__, "verdict": _verdict(result, expected, record_fields),
           "valid": result["valid"]}
    if "signer" in result:
        out["signer"] = result["signer"]
    status = _signer_status(result)
    if status:
        out["signerStatus"] = status
    out["signerBound"] = result["signerBound"]
    if expected:
        out["expectedSigner"] = expected
    for k in ("testKey", "digest", "unsignedFields", "reason"):
        if k in result:
            out[k] = result[k]
    if record_fields is not None:
        out["checked"] = "record.artifact"
        out["recordFieldsNotChecked"] = list(record_fields)
    return out


def _unwrap_record(obj):
    """(object to verify, record fields or None), or raise _NotOneReceipt.

    A bundle record file nests the signed receipt under `artifact` beside RECORD_FIELDS; that
    is the only wrapper accepted. Anything else beside `artifact` - a top-level payload or
    signature, a stray resourceUrl, a note - is refused rather than dropped, because a reader
    would take those fields for the receipt that was checked.
    """
    if not (isinstance(obj, dict) and "artifact" in obj):
        return obj, None
    extra = [k for k in obj if k != "artifact" and k not in RECORD_FIELDS]
    if extra:
        raise _NotOneReceipt(
            "not one receipt: the file nests a signed `artifact` and also carries %d top-level "
            "field%s no evidence-bundle record has (first: %s), so its top-level fields would "
            "read as the receipt while the nested one was checked; nothing was verified. Pass "
            "the receipt itself, or an unmodified records/NNNNNN.json."
            % (len(extra), "" if len(extra) == 1 else "s", _quoted(extra[0])))
    return obj["artifact"], [k for k in RECORD_FIELDS if k in obj]


def _lookup_digest(target, opts):
    ledger = opts.get("--ledger", "https://tersign.ai")
    url = "%s/v1/receipts/%s/verify" % (ledger.rstrip("/"), target)
    print("network lookup: %s" % url)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            body = json.load(r)
    except urllib.error.HTTPError as exc:
        # The ledger answers an unknown digest with 404 and a JSON body ({found: false, ...}):
        # that is an answer, so print it and judge it like any other; only a body that is not a
        # JSON object is a failed lookup.
        try:
            body = json.load(exc)
        except ValueError:
            body = None
        if not isinstance(body, dict):
            print("ledger lookup failed (HTTP %d) - nothing was verified." % exc.code,
                  file=sys.stderr)
            return 1
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # URLError covers HTTP errors and refused connections; ValueError covers an invalid URL
        # and a non-JSON body. Unreached is a FAIL (nothing was verified), never a traceback.
        print("ledger lookup failed (%s): %s - nothing was verified."
              % (type(exc).__name__, exc), file=sys.stderr)
        return 1
    if not isinstance(body, dict):
        print("ledger lookup failed: the response is not a JSON object - nothing was verified.",
              file=sys.stderr)
        return 1
    print(json.dumps(body, indent=2))
    cm = body.get("commitment")
    if cm:  # chains anchored under tersign-chain-commitment-v1 (since 2026-08-28)
        block = cm.get("bitcoinBlockHeight")
        print("commitment: seq <= %s committed (acc %s…) — %s%s" % (
            cm.get("seq"), str(cm.get("acc", ""))[:10], cm.get("status"),
            " block %s" % block if block else ""))
    ok = bool(body.get("found") and body.get("chainOk"))
    # The verdict is the LEDGER's answer about itself: nothing above was re-verified here (no
    # countersignature checked against a pinned key), and a look-alike server can answer the same.
    # The local check is the receipt file with --signer.
    print("verdict: %s (ledger-reported) - %s %s; nothing was verified locally" % (
        "PASS" if ok else "FAIL", json.dumps(ledger),
        "reports the record and its counter-signed chain" if ok
        else "does not report both the record and an intact counter-signed chain"))
    return 0 if ok else 1


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
    args = argv[1:]
    # --help / -h / an unreadable path must not surface a traceback. The first thing a stranger
    # types at any CLI is --help, and on a package whose whole job is verification an unhandled
    # FileNotFoundError is the worst possible first impression. Found 2026-08-30 by installing
    # the PUBLISHED package into a clean venv and typing exactly that.
    if args[0] in ("--help", "-h", "help") or "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    try:
        target, opts = _parse(args)
        if DIGEST_RE.fullmatch(target):
            if "--signer" in opts:
                raise _Usage("--signer binds a receipt FILE's signature; a digest lookup checks "
                             "the ledger's counter-signed chain instead. Verify the receipt file "
                             "with --signer.")
        else:
            if "--ledger" in opts:
                raise _Usage("--ledger applies to a digest lookup; a receipt file is verified "
                             "offline and never sent anywhere. Verify the file, then look its "
                             "digest up: python3 -m tersign verify 0x<digest> --ledger URL")
            signer = opts.get("--signer")
            if signer is not None and not ADDRESS_RE.fullmatch(signer):
                raise _Usage("--signer must be a 20-byte 0x-prefixed hex address, got %s"
                             % _quoted(signer, 60))
    except _Usage as exc:
        print("usage: %s\n\n%s" % (exc, __doc__), file=sys.stderr)
        return 2

    if DIGEST_RE.fullmatch(target):
        return _lookup_digest(target, opts)

    signer = opts.get("--signer")
    try:
        with open(target, "rb") as fh:
            artifact = json.loads(fh.read().decode("utf8"), object_pairs_hook=_no_dupes)
    except _DuplicateKey as exc:
        result = {"valid": False, "signerBound": False, "reason": str(exc)}
        print(json.dumps(_report(result, signer), indent=2))
        return 1
    except UnicodeDecodeError as exc:
        print("%s is not UTF-8 JSON: %s" % (target, exc), file=sys.stderr)
        return 2
    except FileNotFoundError:
        print("no such file: %s\n\nA receipt path, or a 0x-prefixed 32-byte digest with --ledger."
              % target, file=sys.stderr)
        return 2
    except IsADirectoryError:
        print("%s is a directory: pass a receipt JSON file. An evidence bundle directory is "
              "checked by the bundle verifier (verify/verify_bundle.py)." % target, file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print("%s is not JSON: %s" % (target, exc), file=sys.stderr)
        return 2
    except RecursionError:
        print("%s nests deeper than this parser can read; no receipt is shaped like that."
              % target, file=sys.stderr)
        return 2
    except OSError as exc:  # after the subclasses above: PermissionError and the rest
        print("cannot read %s: %s" % (target, exc.strerror or exc), file=sys.stderr)
        return 2
    try:
        artifact, record_fields = _unwrap_record(artifact)
    except _NotOneReceipt as exc:
        result = {"valid": False, "signerBound": False, "reason": str(exc)}
        print(json.dumps(_report(result, signer), indent=2))
        return 1
    result = verify_receipt(artifact, expected_signer=signer)
    print(json.dumps(_report(result, signer, record_fields), indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
