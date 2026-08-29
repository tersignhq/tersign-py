"""The Python SDK decides the PUBLIC conformance vectors the same way the TS engine does.

This file exists because the cross-language check that was here before never once ran. It
compared a fixture against a path supplied by ``TERSIGN_REFERENCE_FIXTURE``, and nothing —
no CI, no workflow, no script — ever set that variable, so every run printed
``OK (skipped=1)`` and the suite looked green while checking nothing. A gate that cannot fire
is worse than an absent one: it converts "nobody looked" into "we verified it".

The replacement has no environment dependency and no network. ``vectors/`` holds the subset of
the public two-sided corpus (github.com/tersignhq/evidence-record-conformance) that this
package's own primitives can decide — canonical bytes, digest recompute, chain link, chain
commitment. The evaluator-semantics kinds (independence, phase, boundary, offer binding) are
deliberately absent: they are not crypto and this package does not implement them, so claiming
them would be the same over-assertion in a new place.

Two properties make it hard to degrade:

  * every vector is decided, and both arms are exercised — the corpus is two-sided by policy,
    so an implementation that accepted everything would fail on the reject vectors and one
    that rejected everything would fail on the valid ones;
  * the DENOMINATOR is asserted. Silently deciding fewer vectors — a rename, a bad glob, an
    empty directory — fails rather than passing quietly with nothing to do.

Freshness against the public repo is checked OUT of this suite, by
scripts/check-conformance-vendored.sh. A network call inside an offline test suite goes red
from weather rather than from defect, and a suite that cries wolf gets switched off.
"""
import json
import os
import unittest

from tersign import canonical, chain_link_digest, digest_of, fold_accumulator

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")

# Bumped deliberately when vectors are added. It is the tripwire against a silent shrink.
EXPECTED_VECTOR_COUNT = 19
EXPECTED_KINDS = {"canonical_bytes": 6, "digest_recompute": 7, "chain_link": 2, "chain_commitment": 4}

DIGEST_RE = "0123456789abcdef"


def _norm_digest(v):
    """A 32-byte hex digest, 0x-prefixed and lowercased, or None if it is not one."""
    if not isinstance(v, str):
        return None
    s = v[2:] if v.startswith(("0x", "0X")) else v
    if len(s) != 64 or any(c not in DIGEST_RE for c in s.lower()):
        return None
    return "0x" + s.lower()


def _load():
    out = []
    for name in sorted(os.listdir(VECTORS)):
        if name.endswith(".json"):
            with open(os.path.join(VECTORS, name), "rb") as fh:
                out.append(json.loads(fh.read().decode("utf8")))
    return out


def decide(vec):
    """Return 'valid' or 'reject' for one vector, using only this package's primitives."""
    kind, inp = vec["kind"], vec["input"]

    if kind == "digest_recompute":
        try:
            got = digest_of(inp["payload"])
        except ValueError:
            # The digest domain is I-JSON with integer numerics: a float, or an integer past
            # 2**53-1, is refused rather than silently serialized into bytes no other
            # implementation reproduces.
            return "reject"
        expected = _norm_digest(inp.get("expected_digest"))
        return "valid" if expected is not None and got == expected else "reject"

    if kind == "canonical_bytes":
        try:
            # payload_text carries raw JSON where the distinction under test cannot survive a
            # parse in every language (JS collapses the token 2.0 to 2). Python keeps
            # float-ness, so canonical()'s own domain guard is the enforcement here.
            payload = json.loads(inp["payload_text"]) if "payload_text" in inp else inp["payload"]
            got = canonical(payload)
        except ValueError:
            return "reject"
        return "valid" if got == inp["claimed_canonical"] else "reject"

    if kind == "chain_link":
        artifact = _norm_digest(inp.get("artifact_digest"))
        prev = None if inp.get("prev_digest") is None else _norm_digest(inp["prev_digest"])
        seq = inp.get("seq")
        expected = _norm_digest(inp.get("expected_link"))
        if artifact is None or expected is None:
            return "reject"
        if inp.get("prev_digest") is not None and prev is None:
            return "reject"
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return "reject"
        return "valid" if chain_link_digest(artifact, prev, seq) == expected else "reject"

    if kind == "chain_commitment":
        # The corpus is a WIRE format and uses snake_case; this package's API is camelCase, so
        # a consumer translates. Getting that wrong is how the first draft of this test failed
        # two valid vectors and briefly looked like a cross-language divergence — it was the
        # test, not the implementation.
        try:
            records = [{"seq": r["seq"],
                        "artifactDigest": r["artifact_digest"],
                        "prevDigest": r.get("prev_digest")}
                       for r in sorted(inp["records"], key=lambda r: r["seq"])]
            got = fold_accumulator(records)
        except (ValueError, KeyError, TypeError):
            # fold_accumulator fail-closes on an empty list, a seq gap or renumbering, and a
            # prevDigest that is not the previous artifactDigest — the continuity half of the
            # reference predicate. The evaluator-side chain_set checks beyond that are out of
            # this package's scope and out of this subset.
            return "reject"
        head = inp.get("head") or {}
        claimed_acc = _norm_digest(head.get("acc"))
        if claimed_acc is None or got["acc"] != claimed_acc:
            # The accumulator is what distinguishes THE prefix from a substituted one ending
            # in the same record; a head digest alone binds only the last row.
            return "reject"
        claimed_head = _norm_digest(head.get("digest"))
        if claimed_head is not None and got["head"] != claimed_head:
            return "reject"
        return "valid"

    raise AssertionError("undecidable kind vendored into this suite: %s" % kind)


class PublicConformanceVectors(unittest.TestCase):
    def setUp(self):
        self.vectors = _load()

    def test_the_corpus_is_the_size_it_claims(self):
        """Denominator first. A shrunk or empty corpus must fail, never pass vacuously."""
        self.assertEqual(len(self.vectors), EXPECTED_VECTOR_COUNT)
        kinds = {}
        for v in self.vectors:
            kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
        self.assertEqual(kinds, EXPECTED_KINDS)

    def test_both_arms_are_present(self):
        """A one-sided corpus proves nothing about the side it never exercises."""
        expects = {v["expect"] for v in self.vectors}
        self.assertEqual(expects, {"valid", "reject"})

    def test_every_vector_decides_as_the_public_corpus_says(self):
        wrong = []
        for v in self.vectors:
            got = decide(v)
            if got != v["expect"]:
                wrong.append("%s (%s): expected %s, this implementation said %s"
                             % (v["id"], v["kind"], v["expect"], got))
        self.assertEqual(wrong, [], "cross-implementation divergence:\n  " + "\n  ".join(wrong))


if __name__ == "__main__":
    unittest.main()
