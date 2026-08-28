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


def receipt_eip712_digest(payload: dict) -> bytes:
    """The exact digest a conforming `x402 receipt` signer signs (domain chainId=1)."""
    domain_sep = keccak256(_DOMAIN_TYPEHASH + _s("x402 receipt") + _s("1") + _u256(1))
    struct = keccak256(
        _RECEIPT_TYPEHASH + _u256(payload["version"]) + _s(payload["network"]) +
        _s(payload["resourceUrl"]) + _s(payload["payer"]) + _u256(payload["issuedAt"]) +
        _s(payload["transaction"]))
    return keccak256(b"\x19\x01" + domain_sep + struct)


def recover_receipt_signer(artifact: dict) -> str:
    """Recover the signer address of a SignedReceipt {format:'eip712', payload, signature}."""
    if artifact.get("format") != "eip712":
        raise ValueError("only eip712 receipts are supported in v0.1")
    return recover_address(receipt_eip712_digest(artifact["payload"]), artifact["signature"])
