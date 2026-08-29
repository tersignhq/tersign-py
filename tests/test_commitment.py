"""Chain commitment accumulator — cross-implementation pins.

Every value here is pinned identically across Tersign's TypeScript and Python
implementations and the bundle verifier: edit all or none. The tersign-first-13 fixture is
the live genesis chain walked from the public /verify endpoint on 2026-08-28; the demo
vectors are the public conformance suite's p6 records.

    python3 -m unittest discover -s tests -v
"""
import json
import os
import unittest

from tersign import (
    ACC_GENESIS, CHAIN_COMMITMENT_SCHEMA, accumulator_step, chain_commitment,
    chain_link_digest, commitment_digest, digest_of, fold_accumulator, verify_commitment,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "tersign-first-13.json")
# Byte-identity against the reference implementation's copy of the same fixture. The path is
# supplied by the environment so this file carries no assumption about where that copy lives;
# where it is not set, the check skips (an installed package has nothing to compare against).
LEDGER_FIXTURE = os.environ.get("TERSIGN_REFERENCE_FIXTURE", "")

DEMO_DIGESTS = [
    "0x4672842890404de85d907f76149e3edb90687d233ad7efbaabf887f888053ef4",
    "0x5a811da59710bb115a7744189a9732f27883180f5821caa7a99979bc33257c29",
    "0xdb17ed57683dea4c9ff668a1e769503e933fcc4e133ea0a823f7ddfc7b6106cd",
]
DEMO_ACCS = [
    "0xe720e2ed33d43c61b5dba81994d46200a51c1b28207c555c034fadc8877217f1",
    "0x067d811a57c765d912c1096b279c2bf19fd904830ab8d0c3f56c7ff2653a8e16",
    "0xae28e0e8b22b15cd27de2390efbe4e3c206decbfe5cede4751b85410f6648f4f",
]
P26_COMMITMENT_DIGEST = "0x0ba9d97eb4a80b863ff720fbf61cbda9f705633fab4b6da5b8648406a9be3745"
N36_SUBSTITUTED_DIGEST = "0x9473ed5e265517974b7a073afd50605372f918a60177ca3655da2117520ef53c"
N36_SUBSTITUTED_TRUE_ACC = "0x5479a41d713938384141892656be4e7e8e0ffbdf621b65b6f2194ccd2688e3ba"
N37_LAST_LINK_ONLY_ACC = "0x4062010194c5605f41afc27e0094266c1cee5063703f5614901893c7fb67ec64"


def demo_records(digests):
    return [{"seq": i + 1, "artifactDigest": d, "prevDigest": None if i == 0 else digests[i - 1]}
            for i, d in enumerate(digests)]


def load_fixture():
    with open(FIXTURE, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


class CommitmentPins(unittest.TestCase):
    def test_seed_is_the_tagged_digest_never_the_zero_sentinel(self):
        self.assertEqual(CHAIN_COMMITMENT_SCHEMA, "tersign-chain-commitment-v1")
        self.assertEqual(ACC_GENESIS, "0x79dde68558318c3f4b7d1af20992f140584708a1001befee3e4ec19c217acfe3")
        self.assertNotEqual(ACC_GENESIS, "0x" + "00" * 32)

    def test_demo_records_fold_to_pinned_accs_and_p26_commitment_digest(self):
        objs = [{"demo": i, "note": "synthetic chain-set record"} for i in (1, 2, 3)]
        for o, d in zip(objs, DEMO_DIGESTS):
            self.assertEqual(digest_of(o), d)
        rows = demo_records(DEMO_DIGESTS)
        self.assertEqual(fold_accumulator(rows[:1])["acc"], DEMO_ACCS[0])
        self.assertEqual(fold_accumulator(rows[:2])["acc"], DEMO_ACCS[1])
        full = fold_accumulator(rows)
        self.assertEqual(full["acc"], DEMO_ACCS[2])
        self.assertEqual(full["head"], DEMO_DIGESTS[2])
        self.assertEqual(chain_commitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2]),
                         {"acc": DEMO_ACCS[2], "head": DEMO_DIGESTS[2],
                          "schema": "tersign-chain-commitment-v1", "seq": 3})
        self.assertEqual(commitment_digest(3, DEMO_DIGESTS[2], DEMO_ACCS[2]), P26_COMMITMENT_DIGEST)
        self.assertEqual(digest_of(chain_commitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2])), P26_COMMITMENT_DIGEST)

    def test_live_tersign_first_chain_folds_to_pinned_acc_13_and_commitment(self):
        fx = load_fixture()
        rows, exp = fx["records"], fx["expected"]
        self.assertEqual(len(rows), 13)
        self.assertEqual(chain_link_digest(rows[0]["artifactDigest"], None, 1), exp["link_1"])
        self.assertEqual(fold_accumulator(rows[:1])["acc"], exp["acc_1"])
        out = fold_accumulator(rows)
        self.assertEqual(out["acc"], exp["acc_13"])
        self.assertEqual(out["acc"], "0xfc831c0f98c8ea5df6417cd26afa278ed4ab82a1e682d170e47aa4a4173c5511")
        self.assertEqual(out["head"], exp["head"])
        self.assertEqual(out["head"], "0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961")
        self.assertEqual(commitment_digest(13, out["head"], out["acc"]), exp["commitment_13"])
        self.assertEqual(exp["commitment_13"], "0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b")

    def test_fixture_is_byte_identical_to_the_reference_fixture(self):
        """OPTIONAL cross-check against a private reference copy, when one is on hand.

        This used to be the only cross-implementation check in this package and it never once
        ran: nothing set TERSIGN_REFERENCE_FIXTURE, so every suite printed OK (skipped=1) and
        looked green while checking nothing. The real cross-language gate now lives in
        test_public_conformance.py, decides 19 public two-sided vectors with no environment
        dependency, and cannot skip. This one stays as a bonus for a monorepo checkout — but a
        SET-BUT-WRONG path is now a failure rather than a silent skip, because "I pointed it
        somewhere and it stayed quiet" is exactly the shape that hid the original problem.
        """
        if not LEDGER_FIXTURE:
            self.skipTest("optional: set TERSIGN_REFERENCE_FIXTURE to also byte-diff a private copy")
        self.assertTrue(os.path.exists(LEDGER_FIXTURE),
                        "TERSIGN_REFERENCE_FIXTURE is set to a path that does not exist: %s" % LEDGER_FIXTURE)
        with open(FIXTURE, "rb") as a, open(LEDGER_FIXTURE, "rb") as b:
            self.assertEqual(a.read(), b.read())


class CommitmentNegatives(unittest.TestCase):
    def test_truncated_substituted_and_last_link_only_all_differ_from_the_true_acc(self):
        rows = demo_records(DEMO_DIGESTS)
        truth = fold_accumulator(rows)["acc"]
        self.assertEqual(truth, DEMO_ACCS[2])
        # truncated prefix under the full head: acc_2 != acc_3
        truncated = fold_accumulator(rows[:2])["acc"]
        self.assertEqual(truncated, "0x067d811a57c765d912c1096b279c2bf19fd904830ab8d0c3f56c7ff2653a8e16")
        self.assertNotEqual(truncated, truth)
        # n36: record 1 substituted, prevs recomputed so the STRUCTURAL chain still walks
        sub = {"demo": 1, "note": "synthetic chain-set record (substituted)"}
        self.assertEqual(digest_of(sub), N36_SUBSTITUTED_DIGEST)
        sub_rows = demo_records([N36_SUBSTITUTED_DIGEST, DEMO_DIGESTS[1], DEMO_DIGESTS[2]])
        self.assertEqual(fold_accumulator(sub_rows)["acc"], N36_SUBSTITUTED_TRUE_ACC)
        self.assertNotEqual(N36_SUBSTITUTED_TRUE_ACC, truth)
        # n37: accumulator over the LAST link only — the "anchor commits to the last record" shape closed
        last_link = chain_link_digest(DEMO_DIGESTS[2], DEMO_DIGESTS[1], 3)
        self.assertEqual(accumulator_step(ACC_GENESIS, last_link), N37_LAST_LINK_ONLY_ACC)
        self.assertNotEqual(N37_LAST_LINK_ONLY_ACC, truth)
        # none of the three collides with the live acc_13 either
        acc_13 = load_fixture()["expected"]["acc_13"]
        for bad in (truncated, N36_SUBSTITUTED_TRUE_ACC, N37_LAST_LINK_ONLY_ACC):
            self.assertNotEqual(bad, acc_13)
        # order matters
        self.assertNotEqual(accumulator_step(DEMO_ACCS[0], DEMO_ACCS[1]),
                            accumulator_step(DEMO_ACCS[1], DEMO_ACCS[0]))

    def test_fold_accumulator_is_fail_closed(self):
        rows = demo_records(DEMO_DIGESTS)
        with self.assertRaises(ValueError):
            fold_accumulator([])
        with self.assertRaises(ValueError):
            fold_accumulator([rows[0], rows[2]])  # gap
        renumbered = [dict(r, seq=r["seq"] + 1) for r in rows]
        with self.assertRaises(ValueError):
            fold_accumulator(renumbered)
        bad = [dict(r) for r in rows]
        bad[1]["prevDigest"] = DEMO_DIGESTS[2]
        with self.assertRaises(ValueError):
            fold_accumulator(bad)
        with self.assertRaises(ValueError):
            fold_accumulator([rows[0], rows[2], rows[1]])  # reordered


class VerifyCommitment(unittest.TestCase):
    def test_accepts_the_live_commitment_and_the_p26_demo(self):
        fx = load_fixture()
        exp = fx["expected"]
        cm = {"seq": 13, "head": exp["head"], "acc": exp["acc_13"], "subjectDigest": exp["commitment_13"],
              "status": "confirmed", "subjectSchema": "tersign-chain-commitment-v1"}
        r = verify_commitment(fx["records"], cm)
        self.assertTrue(r["valid"], r)
        self.assertEqual(r["acc"], exp["acc_13"])
        self.assertEqual(r["digest"], exp["commitment_13"])
        demo = verify_commitment(demo_records(DEMO_DIGESTS), chain_commitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2]))
        self.assertEqual(demo, {"valid": True, "acc": DEMO_ACCS[2], "digest": P26_COMMITMENT_DIGEST})
        # a longer chain than the commitment covers: only the committed prefix is folded
        longer = demo_records(DEMO_DIGESTS)
        prefix = verify_commitment(longer, chain_commitment(2, DEMO_DIGESTS[1], DEMO_ACCS[1]))
        self.assertTrue(prefix["valid"], prefix)

    def test_rejects_truncated_substituted_renumbered_and_last_link_only(self):
        rows = demo_records(DEMO_DIGESTS)
        cm = chain_commitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2])
        self.assertFalse(verify_commitment(rows[:2], cm)["valid"])  # truncated
        sub_rows = demo_records([N36_SUBSTITUTED_DIGEST, DEMO_DIGESTS[1], DEMO_DIGESTS[2]])
        r = verify_commitment(sub_rows, cm)
        self.assertFalse(r["valid"])
        self.assertEqual(r["acc"], N36_SUBSTITUTED_TRUE_ACC)
        self.assertIn("accumulator mismatch", r["reason"])
        renumbered = [dict(r, seq=r["seq"] + 1) for r in rows]
        self.assertFalse(verify_commitment(renumbered, cm)["valid"])
        last_only = chain_commitment(3, DEMO_DIGESTS[2], N37_LAST_LINK_ONLY_ACC)
        self.assertFalse(verify_commitment(rows, last_only)["valid"])
        wrong_head = chain_commitment(3, DEMO_DIGESTS[1], DEMO_ACCS[2])
        self.assertIn("head", verify_commitment(rows, wrong_head)["reason"])
        self.assertFalse(verify_commitment(rows, {"seq": "x"})["valid"])
        self.assertFalse(verify_commitment(rows, {"seq": 0})["valid"])
        tampered = dict(cm, subjectDigest="0x" + "11" * 32)  # subjectDigest present but wrong
        self.assertFalse(verify_commitment(rows, tampered)["valid"])


if __name__ == "__main__":
    unittest.main()
