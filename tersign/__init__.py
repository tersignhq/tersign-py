"""Tersign — the evidence layer for the agent economy.

Python SDK v0.2: OFFLINE VERIFICATION FIRST. Zero dependencies, stdlib only —
the verify path a tribunal, examiner, or CI job can run with nothing installed.

    python3 -m tersign verify receipt.json --signer 0x<issuer address>
    from tersign import verify_receipt, digest_of, chain_link_digest

Without --signer (expected_signer) the signer is UNAUTHENTICATED: a signature recovers to some
address for any payload, so an unbound PASS proves neither authorship nor an unmodified receipt.

Issuing/signing stays in the TypeScript SDK (npm `tersign`) for now; this
package is the independent second implementation of the verification surface —
cross-implementation by construction.
"""
__version__ = "0.2.1"

from .canonical import canonical, digest_of, chain_link_digest, GENESIS  # noqa: F401
from .canonical import (  # noqa: F401
    CHAIN_COMMITMENT_SCHEMA, ACC_GENESIS, accumulator_step, fold_accumulator,
    chain_commitment, commitment_digest,
)
from .eip712 import receipt_eip712_digest, recover_receipt_signer  # noqa: F401
from .verify import verify_receipt, verify_link, verify_commitment  # noqa: F401
from .known_keys import PUBLISHED_TEST_KEYS, published_key_label  # noqa: F401
