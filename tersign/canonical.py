"""RFC 8785 (JCS) canonical form + the Tersign digest and chain-link constructors.

Byte-compatible with Tersign's TypeScript implementation — pinned
cross-implementation vectors in tests/.
Digest domain: ints/strings/bools/null/objects/arrays only; floats are REJECTED
(the digest-domain boundary is the number TOKEN — a float that survives a parse
round-trip is exactly the divergence class the conformance suite kills).
"""
import json

from .keccak import keccak256

GENESIS = "0x" + "00" * 32

# Parity with the TypeScript implementation and the bundle verifier: an implementation
# without this bound accepts artifacts the others reject, which is exactly the divergence
# class this package exists to kill.
MAX_DEPTH = 64


def canonical(v, _depth=0) -> str:
    if _depth > MAX_DEPTH:
        raise ValueError("nesting exceeds MAX_DEPTH (%d) — outside the Tersign digest domain" % MAX_DEPTH)
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("float outside the Tersign digest domain")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x, _depth + 1) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical(val, _depth + 1) for k, val in items) + "}"
    raise ValueError("unsupported type %r" % type(v))


def digest_of(v) -> str:
    """keccak256(utf8(JCS(v))) as 0x-hex — the artifact digest."""
    return "0x" + keccak256(canonical(v).encode("utf-8")).hex()


def _hx(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def chain_link_digest(artifact_digest: str, prev_digest: str, seq: int) -> str:
    """keccak256(artifactDigest ‖ prevDigest ‖ uint64be(seq)) — the counter-signed link."""
    return "0x" + keccak256(
        _hx(artifact_digest) + _hx(prev_digest or GENESIS) + int(seq).to_bytes(8, "big")).hex()


# Chain commitment accumulator. DERIVED, never signed, never
# stored per row: acc_0 = keccak256(utf8("tersign-chain-commitment-v1")); acc_k =
# keccak256(acc_{k-1} || link_k). A pure function of (a_1..a_k, 1..k) — any omission,
# insertion, reordering or rewrite below k changes acc_k, so ONE anchored digest over acc_N
# commits to the whole prefix. Domain separation by construction: link preimages are 72 raw
# bytes, acc preimages 64 raw bytes, every JCS digest is UTF-8 text starting "{", and the seed
# is a tagged digest — never the 32-zero-byte link-genesis sentinel. Pinned identically in
# every Tersign implementation and the bundle verifier: edit all or none.
CHAIN_COMMITMENT_SCHEMA = "tersign-chain-commitment-v1"
ACC_GENESIS = "0x" + keccak256(CHAIN_COMMITMENT_SCHEMA.encode("utf-8")).hex()


def accumulator_step(acc: str, link: str) -> str:
    """keccak256(acc ‖ link) — one fold step of the chain commitment accumulator."""
    return "0x" + keccak256(_hx(acc) + _hx(link)).hex()


def fold_accumulator(records) -> dict:
    """Fold records 1..N (each {artifactDigest, prevDigest, seq}) into {acc, head}.

    Fail-closed: an empty list, a seq gap or renumbering, or a prevDigest that is not
    the previous record's artifactDigest (None at seq 1) raises ValueError — never derive
    an accumulator over a chain that does not re-walk.
    """
    if not records:
        raise ValueError("no records: expected a dense chain 1..N")
    acc = ACC_GENESIS
    prev = None
    for i, r in enumerate(records):
        seq = r.get("seq")
        if seq != i + 1:
            raise ValueError("seq %r at position %d" % (seq, i + 1))
        if r.get("prevDigest") != prev:
            raise ValueError("prev mismatch at seq %d" % seq)
        digest = r["artifactDigest"]
        acc = accumulator_step(acc, chain_link_digest(digest, prev, seq))
        prev = digest
    return {"acc": acc, "head": prev}


def chain_commitment(seq: int, head: str, acc: str) -> dict:
    """The self-describing object the anchor cron stamps: {acc, head, schema, seq}."""
    return {"acc": acc, "head": head, "schema": CHAIN_COMMITMENT_SCHEMA, "seq": seq}


def commitment_digest(seq: int, head: str, acc: str) -> str:
    """keccak256(utf8(JCS(chain_commitment(seq, head, acc)))) — the anchored subject digest."""
    return digest_of(chain_commitment(seq, head, acc))
