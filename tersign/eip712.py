"""EIP-712 hashing + signer recovery for the pinned Tersign artifact domains.

v0.1 covers the upstream `x402 receipt` domain (the merged offer-receipt
extension) — the artifact class the ledger counter-signs. Other domains
(action-record, dispute, compliance-fields) follow the same pattern and land
with their verify use cases.
"""
from .keccak import keccak256
from .secp256k1 import eip191_hash_bytes32, eip191_hash_text, recover_address  # noqa: F401

_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)")
_RECEIPT_TYPEHASH = keccak256(
    b"Receipt(uint256 version,string network,string resourceUrl,string payer,"
    b"uint256 issuedAt,string transaction)")


def _u256(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def _s(text: str) -> bytes:
    return keccak256(text.encode("utf-8"))


def _uint_field(payload: dict, name: str) -> bytes:
    """A signed uint256 field, accepted only as a JSON integer in range.

    int() would coerce true, "1", " 1783761710 " and "1_783_761_710" to the same number: each
    such edit recovered the real signer, under a different digest, with nothing reporting it.
    The ledger counter-signs only JSON integers here (safe-integer check at ingest), so any
    other spelling is a file whose text is not what the signature covers.
    """
    v = payload[name]
    if type(v) is not int:  # bool is an int subclass: exclude it by exact type
        raise ValueError("payload.%s must be a JSON integer, not %s: the signature covers the "
                         "number, so another spelling of it is unsigned text"
                         % (name, type(v).__name__))
    if not 0 <= v < 2 ** 256:
        raise ValueError("payload.%s is outside the uint256 range" % name)
    return _u256(v)


def _str_field(payload: dict, name: str) -> bytes:
    v = payload[name]
    if not isinstance(v, str):
        raise ValueError("payload.%s must be a string, not %s" % (name, type(v).__name__))
    return _s(v)


def receipt_eip712_digest(payload: dict) -> bytes:
    """The exact digest a conforming `x402 receipt` signer signs (domain chainId=1)."""
    domain_sep = keccak256(_DOMAIN_TYPEHASH + _s("x402 receipt") + _s("1") + _u256(1))
    struct = keccak256(
        _RECEIPT_TYPEHASH + _uint_field(payload, "version") + _str_field(payload, "network") +
        _str_field(payload, "resourceUrl") + _str_field(payload, "payer") +
        _uint_field(payload, "issuedAt") + _str_field(payload, "transaction"))
    return keccak256(b"\x19\x01" + domain_sep + struct)


def recover_receipt_signer(artifact: dict) -> str:
    """Recover the signer address of a SignedReceipt {format:'eip712', payload, signature}."""
    if artifact.get("format") != "eip712":
        raise ValueError("only eip712 receipts are supported in v0.1")
    return recover_address(receipt_eip712_digest(artifact["payload"]), artifact["signature"])
