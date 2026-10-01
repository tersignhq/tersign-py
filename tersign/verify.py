"""Offline verification — receipts and chain links. Zero network, zero deps.

verify_receipt: the python twin of `npx tersign verify <receipt.json>`.
verify_link:    checks one counter-signed chain link (the ledger's signature class).
For full frozen-bundle verification use the bundle's own bundled verifier
(tersign-evidence-bundle-v1 ships verify/verify_bundle.py inside the artifact).
"""
import re

from .canonical import digest_of, chain_link_digest, GENESIS, fold_accumulator, commitment_digest  # noqa: F401
from .eip712 import recover_receipt_signer
from .known_keys import published_key_label
from .secp256k1 import recover_countersigner

# \A...\Z, not ^...$: Python's `$` also matches before a final "\n", so an address read from a
# file ("0x...\n") passed validation and then failed the comparison as a signer MISMATCH, telling
# the operator a genuine receipt "was not signed by that key, or was altered". Call sites use
# fullmatch too, so a later .match() call cannot bring the case back on its own.
ADDRESS_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")

# What the EIP-712 signature actually covers. Anything else in the file rides along unsigned:
# it changes the digest (the ledger's content address) but not the recovered signer.
SIGNED_RECEIPT_FIELDS = ("version", "network", "resourceUrl", "payer", "issuedAt", "transaction")
_ENVELOPE_FIELDS = ("format", "payload", "signature")


# The ONE accepted encoding of an EIP-712 signature: "0x" + 130 lower-case hex digits,
# r || s || v, v = 27 or 28 (what viem emits). r/s range and low-s are enforced by
# secp256k1.recover_pubkey. The TypeScript twin applies the same rules (sdk/src/receipt/binding.ts
# signatureError), with the same reason texts. Without this, one issuance had several "also valid"
# byte-distinct copies - the recovery-id twin (v 0/1), upper-case hex, a missing 0x, whitespace or
# a trailing newline inside the hex (bytes.fromhex skips it) - each recovering the real signer
# under its own content digest (release review 2026-09-27).
_CANONICAL_SIG_SHAPE = re.compile(r"0x[0-9a-fA-F]{130}")


def signature_error(sig):
    """Why `sig` is not the canonical encoding, or None. Package text only: nothing from the
    file is echoed."""
    if not isinstance(sig, str):
        kind = ("null" if sig is None else "an array" if isinstance(sig, list)
                else "an object" if isinstance(sig, dict) else "a boolean" if isinstance(sig, bool)
                else "a number" if isinstance(sig, (int, float)) else "a %s" % type(sig).__name__)
        return "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v), not %s" % kind
    if not _CANONICAL_SIG_SHAPE.fullmatch(sig):
        return "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)"
    if sig != sig.lower():
        return "signature hex must be lower-case (non-canonical)"
    v = int(sig[130:132], 16)
    if v in (0, 1):
        return "recovery id %d rejected (non-canonical): v must be 27 or 28" % v
    if v not in (27, 28):
        return "unsupported recovery id %d" % v
    return None


def _unsigned_fields(artifact):
    out = ["payload.%s" % k for k in sorted(artifact.get("payload", {}))
           if k not in SIGNED_RECEIPT_FIELDS]
    out += sorted(k for k in artifact if k not in _ENVELOPE_FIELDS)
    return out


def verify_receipt(artifact: dict, expected_signer: str = None) -> dict:
    """Structural + signature verification of a SignedReceipt, fully offline.

    Returns {valid, signer, signerBound, digest, testKey?, unsignedFields?, reason?}.

    valid        the signature is well-formed and recovers to an address — and, when
                 expected_signer is given, to exactly that address. The TypeScript twin's
                 verifyReceipt (npm 0.5.0) applies the same input rules: the signed uint256
                 fields (version, issuedAt) must be JSON integers, as the ledger requires at
                 ingest; the signed string fields must be strings; the signature must be the
                 one canonical encoding (see signature_error: 0x + 130 lower-case hex digits,
                 v 27/28, low-s); only None and "" mean no expected_signer. One known
                 difference in this function: it accepts a signed integer above 2**53-1 (up to
                 2**256-1), which the TypeScript twin refuses before recovery. The two CLIs
                 differ on more input classes; sdk/src/verify-bin.ts lists the measured ones.
                 expected_signer implements the spec's payTo-key authorization model.
    signerBound  True only when expected_signer was supplied and matched. When False, `signer`
                 is whatever the receipt's own signature recovers to, and ECDSA recovery yields
                 an address for ANY payload: an edited receipt still returns valid:True, with a
                 different signer. So valid:True with signerBound:False proves neither who
                 signed nor that the payload is unmodified. Bind it: pass the issuer's address,
                 obtained out-of-band.
    testKey      present when the recovered signer is a PUBLISHED test key (tersign.known_keys):
                 anyone can produce that signature, so even a bound match says nothing about
                 who issued the receipt.
    unsignedFields  fields present in the artifact that the EIP-712 signature does not cover.
    """
    # Only None and "" mean "not supplied" (the TypeScript twin treats "" as absent). Any other
    # falsy value (0, False, [], {}) is a malformed argument and fails like one: a bare
    # `if not expected_signer` used to read it as "no binding asked for" and return valid:True.
    if expected_signer is None or (isinstance(expected_signer, str) and expected_signer == ""):
        expected_signer = None
    if expected_signer is not None and not (
            isinstance(expected_signer, str) and ADDRESS_RE.fullmatch(expected_signer)):
        return {"valid": False, "signerBound": False,
                "reason": "expected_signer is not a 20-byte 0x-prefixed hex address"}
    if not isinstance(artifact, dict) or not isinstance(artifact.get("payload"), dict):
        return {"valid": False, "signerBound": False,
                "reason": "not a signed receipt: expected {format, payload{...}, signature}"}
    bad_sig = signature_error(artifact.get("signature"))
    if bad_sig is not None:
        return {"valid": False, "signerBound": False, "reason": bad_sig}
    try:
        signer = recover_receipt_signer(artifact)
        # Inside the try: a float-carrying (or over-deep) artifact must return
        # valid:False, never traceback — digest_of raises on domain violations
        #.
        digest = digest_of(artifact)
        unsigned = _unsigned_fields(artifact)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "signerBound": False, "reason": str(e)}
    out = {"valid": True, "signer": signer,
           "signerBound": expected_signer is not None, "digest": digest}
    label = published_key_label(signer)
    if label:
        out["testKey"] = label
    if unsigned:
        out["unsignedFields"] = unsigned
    if expected_signer is not None and signer.lower() != expected_signer.lower():
        out.update(valid=False, signerBound=False,
                   reason="signer does not match expected authorization key")
    return out


def verify_link(artifact_digest: str, prev_digest: str, seq: int,
                countersignature: str, ledger_signer: str) -> dict:
    """Verify one counter-signed chain link (EIP-191 over the raw 32-byte link digest).

    The counter-signature must be its one accepted encoding, decided on the bytes before
    recovery (secp256k1.countersignature_error): "0x" then 130 hex digits of either case (no
    whitespace, no other prefix), v 27 or 28, s <= n/2. A high-s or v 0/1 re-encoding of the
    ledger's genuine signature recovers the same ledger key and is refused, with `reason`
    starting with the crypto profile's code (malformed_signature, non_canonical_s,
    unrecoverable). This rule is for the ledger's counter-signature only; receipt signatures
    follow signature_error above."""
    link = chain_link_digest(artifact_digest, prev_digest, seq)
    try:
        addr = recover_countersigner(bytes.fromhex(link[2:]), countersignature)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "link": link, "reason": str(e)}
    ok = addr.lower() == ledger_signer.lower()
    return {"valid": ok, "link": link, "signer": addr,
            **({} if ok else {"reason": "signer_mismatch: the countersignature does not recover to ledger_signer"})}


def verify_commitment(records, commitment: dict) -> dict:
    """Recompute a chain commitment offline from the public records and compare.

    records:    list of {artifactDigest, prevDigest, seq} in seq order, at least 1..commitment.seq
                (a longer chain is fine — only the committed prefix is folded).
    commitment: {seq, head, acc} — the `commitment` object /verify returns, or chain.commitment
                from a frozen bundle. If it carries `subjectDigest` that is checked too.
    Returns {valid, acc, digest, reason?} where acc/digest are the RECOMPUTED values
    (absent when the prefix does not re-walk). A truncated, substituted, reordered or
    renumbered prefix under the real commitment returns valid:False — the shape the anchored
    accumulator exists to reject.
    """
    try:
        seq = int(commitment["seq"])
    except Exception:  # noqa: BLE001
        return {"valid": False, "reason": "commitment.seq is not an integer"}
    if seq < 1:
        return {"valid": False, "reason": "commitment.seq must be >= 1"}
    if len(records) < seq:
        return {"valid": False, "reason": "expected %d records, have %d" % (seq, len(records))}
    try:
        out = fold_accumulator(records[:seq])
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "reason": str(e)}
    acc, head = out["acc"], out["head"]
    digest = commitment_digest(seq, head, acc)
    result = {"valid": True, "acc": acc, "digest": digest}
    if str(commitment.get("head", "")).lower() != head.lower():
        return {**result, "valid": False, "reason": "head does not match the last artifactDigest"}
    if str(commitment.get("acc", "")).lower() != acc.lower():
        return {**result, "valid": False,
                "reason": "accumulator mismatch: commitment.acc does not commit to the presented prefix"}
    subject = commitment.get("subjectDigest")
    if subject is not None and str(subject).lower() != digest.lower():
        return {**result, "valid": False, "reason": "subjectDigest does not match the commitment digest"}
    return result
