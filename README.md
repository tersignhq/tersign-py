# tersign (Python)

```bash
pip install tersign
```


Tersign — the evidence layer for the agent economy. This package is the
**verification-first Python SDK**: zero dependencies, standard library only —
the verify path a tribunal, examiner, or CI job can run with nothing installed.

```bash
python3 -m tersign verify receipt.json --signer 0x<issuer address>   # offline — no network, ever
python3 -m tersign verify 0x<digest> --ledger https://tersign.ai     # chain lookup (explicit network)
```

```python
from tersign import verify_receipt, digest_of, chain_link_digest, verify_link, verify_commitment

result = verify_receipt(signed_receipt, expected_signer="0x<issuer address, out-of-band>")
# {'valid': True, 'signer': '0x…', 'signerBound': True, 'digest': '0x…'}
```

**Bind the signer, or a PASS proves little.** A signature recovers to *some* address for any
payload, so a receipt checked without `--signer` (CLI) or `expected_signer` (library) comes back
with `signerBound` false, and the CLI's verdict says what that means: it proves neither who
signed nor that the receipt is unmodified, because an edited receipt recovers a different address
and still verifies. Take the issuer's address from a channel you trust, never from the receipt.
A receipt signed with a published test key — the Hardhat/Anvil default dev accounts #0–#19, or
private keys 0x1, 0x2 and 0x3 — is flagged `testKey` whether or not it is bound: anyone can
produce that signature.

`verify_receipt` (the library) returns `valid`, `signer`, `signerBound` and `digest`, plus
`testKey`, `unsignedFields` (fields in the file that the signature does not cover) and `reason`
when they apply. The CLI prints that result and adds `tersign`, `verdict`, `signerStatus`
(BOUND, UNAUTHENTICATED or MISMATCH), `expectedSigner`, and, for an evidence-bundle record file,
`checked` and `recordFieldsNotChecked`. A record file's own chain fields are reported as not
checked (the bundle verifier checks them), and a file carrying any other field beside the nested
`artifact` is refused. Exit status: `0` PASS (read `verdict`), `1` FAIL, `2` usage — an unknown
or valueless flag is refused, never ignored. A digest lookup (`verify 0x<digest> --ledger URL`)
prints the ledger's answer and the verdict `PASS (ledger-reported)` or `FAIL (ledger-reported)`:
nothing in it is verified locally.

What it covers (v0.1):

- **RFC 8785 (JCS) canonical form** + the Tersign artifact digest
  (`keccak256(utf8(JCS(v)))`) and chain-link constructor — byte-compatible with
  the TypeScript reference, pinned by shared cross-implementation vectors.
- **EIP-712 recovery** for the upstream `x402 receipt` domain (the merged
  offer-receipt extension) — pure-python secp256k1. A receipt's signature must be
  the one canonical encoding (`0x` + 130 lower-case hex digits, v 27/28, low-s);
  a re-encoding of a genuine signature (v 0/1, upper-case hex, the high-s twin) also
  recovers the issuer, under a different digest, so it is refused.
- **Counter-signature verification** (`verify_link`): EIP-191 over the raw
  32-byte chain-link digest, recovered against the published ledger signer
  (`https://tersign.ai/v1/ledger`).
- **Chain commitment recompute** (`verify_commitment`): since 2026-08-28 each
  anchor stamps a chain commitment — an accumulator over every counter-signed
  link — so one anchored digest covers the whole prefix; rows anchored earlier
  bind the head record only and say so (`subjectSchema`).

**The bundled copy is a convenience, not a trust root.** A frozen bundle ships this verify
core inside itself, which is fine for a worked example and wrong for evidence handed to you by
an interested party — a bundle can ship a checker that blesses it. For adversarial input fetch
the checker out-of-band from `https://tersign.ai/verify/v1/` (digests at `SHA256SUMS` beside
it) and diff it against the bundled copy; a difference is itself the finding.

**Check this package against the public corpus yourself.** Since 0.1.4 the sdist carries the
subset of the [two-sided conformance corpus](https://github.com/tersignhq/evidence-record-conformance)
these primitives decide — 19 vectors across canonical bytes, digest recompute, chain link and
chain commitment, both accept and reject arms. `python3 -m unittest discover -s tests` runs
them. A package whose job is letting you check us without trusting us should ship the means to
check the package.

Issuing/signing lives in the TypeScript SDK (npm
[`tersign`](https://www.npmjs.com/package/tersign)); this package is the
independent second implementation of the verification surface —
cross-implementation by construction. Frozen evidence bundles
(`tersign-evidence-bundle-v1`) ship their own copy of this verify core inside
the artifact, so bundle verification never depends on an install.

No console script on purpose: the `tersign` bin name belongs to the npm
package; the Python surface is `python3 -m tersign`.
