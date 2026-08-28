"""Offline verification — receipts and chain links. Zero network, zero deps.

verify_receipt: the python twin of `npx tersign verify <receipt.json>`.
verify_link:    checks one counter-signed chain link (the ledger's signature class).
For full frozen-bundle verification use the bundle's own bundled verifier
(tersign-evidence-bundle-v1 ships verify/verify_bundle.py inside the artifact).
"""
from .canonical import digest_of, chain_link_digest, GENESIS, fold_accumulator, commitment_digest  # noqa: F401
from .eip712 import recover_receipt_signer
from .secp256k1 import eip191_hash_bytes32, recover_address


def verify_receipt(artifact: dict, expected_signer: str = None) -> dict:
    """Structural + signature verification of a SignedReceipt, fully offline.

    Returns {valid, signer, digest, reason?}. Mirrors sdk verifyReceipt semantics:
    expected_signer implements the spec's payTo-key authorization model.
    """
    try:
        signer = recover_receipt_signer(artifact)
        # Inside the try: a float-carrying (or over-deep) artifact must return
        # valid:False, never traceback — digest_of raises on domain violations
        #.
        digest = digest_of(artifact)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "reason": str(e)}
    if expected_signer and signer.lower() != expected_signer.lower():
        return {"valid": False, "signer": signer, "digest": digest,
                "reason": "signer does not match expected authorization key"}
    return {"valid": True, "signer": signer, "digest": digest}


def verify_link(artifact_digest: str, prev_digest: str, seq: int,
                countersignature: str, ledger_signer: str) -> dict:
    """Verify one counter-signed chain link (EIP-191 over the raw 32-byte link digest)."""
    link = chain_link_digest(artifact_digest, prev_digest, seq)
    try:
        addr = recover_address(
            eip191_hash_bytes32(bytes.fromhex(link[2:])), countersignature)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "link": link, "reason": str(e)}
    ok = addr.lower() == ledger_signer.lower()
    return {"valid": ok, "link": link, "signer": addr,
            **({} if ok else {"reason": "countersignature signer mismatch"})}


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
