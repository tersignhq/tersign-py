# tersign (Python)

Tersign — the evidence layer for the agent economy. This package is the
**verification-first Python SDK**: zero dependencies, standard library only —
the verify path a tribunal, examiner, or CI job can run with nothing installed.

```bash
python3 -m tersign verify receipt.json            # offline — no network, ever
python3 -m tersign verify 0x<digest> --ledger …   # chain lookup (explicit network)
```

```python
from tersign import verify_receipt, digest_of, chain_link_digest, verify_link, verify_commitment

result = verify_receipt(signed_receipt)        # {'valid': True, 'signer': '0x…', 'digest': '0x…'}
```

What it covers (v0.1):

- **RFC 8785 (JCS) canonical form** + the Tersign artifact digest
  (`keccak256(utf8(JCS(v)))`) and chain-link constructor — byte-compatible with
  the TypeScript reference, pinned by shared cross-implementation vectors.
- **EIP-712 recovery** for the upstream `x402 receipt` domain (the merged
  offer-receipt extension) — pure-python secp256k1, canonical low-s only.
- **Counter-signature verification** (`verify_link`): EIP-191 over the raw
  32-byte chain-link digest, recovered against the published ledger signer
  (`https://tersign.ai/v1/ledger`).
- **Chain commitment recompute** (`verify_commitment`): since 2026-08-28 each
  anchor stamps a chain commitment — an accumulator over every counter-signed
  link — so one anchored digest covers the whole prefix; rows anchored earlier
  bind the head record only and say so (`subjectSchema`).

Issuing/signing lives in the TypeScript SDK (npm
[`tersign`](https://www.npmjs.com/package/tersign)); this package is the
independent second implementation of the verification surface —
cross-implementation by construction. Frozen evidence bundles
(`tersign-evidence-bundle-v1`) ship their own copy of this verify core inside
the artifact, so bundle verification never depends on an install.

No console script on purpose: the `tersign` bin name belongs to the npm
package; the Python surface is `python3 -m tersign`.
