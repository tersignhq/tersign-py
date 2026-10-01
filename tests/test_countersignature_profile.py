"""verify_link accepts the ledger's counter-signature in one encoding per signature (hex digits of either case).

The fixture (fixtures/countersignature-profile.json, built by scripts/gen-countersignature-profile.py)
carries the counter-signature class of the public crypto profile's vectors plus derived re-encodings
of genuine signatures. Every re-encoding recovers the SAME signer as its accepting twin, so a
verifier that only compares recovered addresses passes every one of them; the verdict has to be
decided on the bytes before recovery.

Three layers, each able to fail:
  * every vector is decided (verdict AND reason code), and the denominator is asserted;
  * every rejecting vector names an accepting twin that is in the file and accepted;
  * every rule is removed, one at a time, from the REAL source (secp256k1.py / verify.py, string-
    mutated and executed as a throwaway module), and the named vector must then be decided wrongly.
    A mutant nobody kills means the suite cannot see that rule.
"""
import importlib.util
import json
import os
import sys
import unittest

from tersign import verify_link
from tersign.secp256k1 import countersignature_error

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "tersign")
FIXTURE = os.path.join(HERE, "fixtures", "countersignature-profile.json")

EXPECTED = {"vectors": 21, "carried": 11, "derived": 10}
SIG_REASONS = {"malformed_signature", "non_canonical_s", "unrecoverable"}


def load():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def decide(verify, v):
    """(verdict, reason code) the way the profile states them."""
    i = v["input"]
    r = verify(i["artifact_digest"], i.get("prev_digest"), i["seq"], i["countersignature"], i["ledger_signer"])
    if r["valid"]:
        return "valid", None
    return "reject", r["reason"].split(":", 1)[0]


class FixtureShape(unittest.TestCase):
    def test_denominator(self):
        d = load()
        self.assertEqual(d["schema"], "tersign-countersignature-profile-fixture-v1")
        self.assertEqual(len(d["vectors"]), EXPECTED["vectors"])
        self.assertEqual(sum(1 for v in d["vectors"] if v["id"].startswith(("cp", "cn"))), EXPECTED["carried"])
        self.assertEqual(sum(1 for v in d["vectors"] if v["id"].startswith("tv")), EXPECTED["derived"])
        self.assertEqual(len({v["id"] for v in d["vectors"]}), EXPECTED["vectors"])

    def test_every_reject_has_an_accepting_twin(self):
        d = load()
        by_id = {v["id"]: v for v in d["vectors"]}
        rejects = [v for v in d["vectors"] if v["expect"] == "reject"]
        self.assertGreater(len(rejects), 0)
        for v in rejects:
            twin = by_id.get(v.get("twin"))
            self.assertIsNotNone(twin, v["id"])
            self.assertEqual(twin["expect"], "valid", v["id"])
            self.assertEqual(decide(verify_link, twin), ("valid", None), v["id"])


class Vectors(unittest.TestCase):
    def test_every_vector(self):
        for v in load()["vectors"]:
            with self.subTest(v["id"]):
                self.assertEqual(decide(verify_link, v), (v["expect"], v.get("reject_reason")))

    def test_predicate_decides_before_recovery(self):
        # countersignature_error alone (no recovery) returns the encoding reasons; a vector that is
        # well encoded (valid, or rejected only by recovery / signer) gets None.
        for v in load()["vectors"]:
            with self.subTest(v["id"]):
                want = v.get("reject_reason") if v.get("reject_reason") in SIG_REASONS else None
                self.assertEqual(countersignature_error(v["input"]["countersignature"]), want)

    def test_low_s_boundary_on_the_bytes(self):
        from tersign.secp256k1 import N
        r = "%064x" % 1
        self.assertIsNone(countersignature_error("0x" + r + "%064x" % (N // 2) + "1b"))
        self.assertEqual(countersignature_error("0x" + r + "%064x" % (N // 2 + 1) + "1b"), "non_canonical_s")
        self.assertEqual(countersignature_error("0x" + "%064x" % N + "%064x" % 1 + "1b"), "unrecoverable")
        for bad in (None, 7, b"0x" + b"00" * 65, ["0x"]):
            self.assertEqual(countersignature_error(bad), "malformed_signature")


# Each mutant removes or loosens ONE rule in the shipped source: (edits, killing vector, level).
# `level` is where the kill must show: "verdict" (valid/reject flips), "reason" (same verdict,
# wrong code), or "predicate" (verify_link unchanged, countersignature_error wrong). Two rules are
# held twice: recover_pubkey keeps its own low-s and r/s range refusals for every signature class,
# so removing only the encoding-level copy is visible in the reason code (low-s) or only through
# the predicate (range). "no_low_s_anywhere" removes both low-s copies and must flip the verdict.
_LOW_S_ENCODING = ("secp256k1.py", '    if s > N // 2:\n        return "non_canonical_s"\n', "")
_LOW_S_RECOVERY = ("secp256k1.py", '    if s > N // 2:\n        # Ethereum low-s', '    if False:\n        # Ethereum low-s')
MUTANTS = {
    "prefix_any_case": ([("secp256k1.py", 're.compile(r"0x[0-9a-fA-F]{130}")', 're.compile(r"0[xX][0-9a-fA-F]{130}")')],
                        "tv4-upper-case-0X-prefix", "verdict"),
    # an open-ended length rule: the first 65 bytes of a 66-byte string are still read as r, s, v
    "shape_open_length": ([("secp256k1.py", 're.compile(r"0x[0-9a-fA-F]{130}")', 're.compile(r"0x[0-9a-fA-F]{130,}")')],
                          "tv10-66-byte-signature-trailing-byte", "reason"),
    "dollar_anchored_shape": ([("secp256k1.py", "not _COUNTERSIG_SHAPE.fullmatch(signature_hex)",
                                'not re.match(r"^0x[0-9a-fA-F]{130}$", signature_hex)')],
                              "tv6-trailing-newline", "verdict"),
    # repairs the string (strip, drop spaces, re-add "0x") before validating it
    "lenient_parse": ([("secp256k1.py", "    why = countersignature_error(signature_hex)\n",
                        "    signature_hex = '0x' + signature_hex.strip().replace(' ', '')[-130:]\n"
                        "    why = countersignature_error(signature_hex)\n")],
                      "cn14-signature-missing-0x-prefix", "verdict"),
    "v_normalised": ([("secp256k1.py", "if sig[64] not in (27, 28):", "if sig[64] not in (0, 1, 27, 28):")],
                     "tv1-recovery-id-1-twin-of-live", "verdict"),
    "no_low_s": ([_LOW_S_ENCODING], "cn3-high-s-malleated-live-signature", "reason"),
    "no_low_s_anywhere": ([_LOW_S_ENCODING, _LOW_S_RECOVERY], "cn3-high-s-malleated-live-signature", "verdict"),
    "no_range": ([("secp256k1.py", '    if not (1 <= r < N and s >= 1):\n        return "unrecoverable"\n', "")],
                 "tv8-zero-r-and-s", "predicate"),
    "raw_digest_domain": ([("secp256k1.py", "recover_ledger_signer(eip191_hash_bytes32(link32),", "recover_ledger_signer(link32,")],
                          "cn4-raw-digest-signature-no-eip191-prefix", "verdict"),
    "signer_not_compared": ([("verify.py", "ok = addr.lower() == ledger_signer.lower()", "ok = True")],
                            "cn2-foreign-signer-claims-ledger", "verdict"),
}
# Changes bytes the suite cannot observe (a comment), through the same harness: it must SURVIVE
# every vector, or the kills above measure the harness rather than the rules.
IDENTITY = [("secp256k1.py", "# The one accepted encoding of a signature the LEDGER makes", "# The one accepted encoding (identity) of a signature the LEDGER makes")]


def _exec_module(name, path, src):
    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "tersign"
    mod.__file__ = path
    sys.modules[name] = mod
    exec(compile(src, path, "exec"), mod.__dict__)  # noqa: S102 - our own source, mutated in-test
    return mod


def build_mutant(edits):
    """(verify_link, countersignature_error) from the real sources with `edits` applied."""
    srcs = {}
    for f in ("secp256k1.py", "verify.py"):
        with open(os.path.join(PKG, f), encoding="utf-8") as fh:
            srcs[f] = fh.read()
    for f, old, new in edits:
        n = srcs[f].count(old)
        if n != 1:
            raise AssertionError("anchor %r occurs %d times in %s (must be exactly once)" % (old[:40], n, f))
        srcs[f] = srcs[f].replace(old, new, 1)
    ec = _exec_module("tersign._mutant_secp256k1", os.path.join(PKG, "secp256k1.py"), srcs["secp256k1.py"])
    vsrc = srcs["verify.py"].replace("from .secp256k1 import", "from ._mutant_secp256k1 import", 1)
    vm = _exec_module("tersign._mutant_verify", os.path.join(PKG, "verify.py"), vsrc)
    return vm.verify_link, ec.countersignature_error


def wrong_on(verify, predicate, v):
    """None when the implementation decides v as the fixture does, else the level it is wrong at."""
    try:
        got = decide(verify, v)
    except Exception:  # noqa: BLE001 - a raise is also a wrong decision
        return "raise"
    if got[0] != v["expect"]:
        return "verdict"
    if got[1] != v.get("reject_reason"):
        return "reason"
    want_pred = v.get("reject_reason") if v.get("reject_reason") in SIG_REASONS else None
    return "predicate" if predicate(v["input"]["countersignature"]) != want_pred else None


class Mutants(unittest.TestCase):
    def tearDown(self):
        for name in ("tersign._mutant_secp256k1", "tersign._mutant_verify"):
            sys.modules.pop(name, None)

    def test_identity_mutant_survives_every_vector(self):
        verify, pred = build_mutant(IDENTITY)
        vectors = load()["vectors"]
        self.assertEqual(len(vectors), EXPECTED["vectors"])
        self.assertEqual([(v["id"], wrong_on(verify, pred, v)) for v in vectors
                          if wrong_on(verify, pred, v)], [])

    def test_every_mutant_is_killed_by_its_named_vector_at_its_level(self):
        by_id = {v["id"]: v for v in load()["vectors"]}
        for name, (edits, killer, level) in MUTANTS.items():
            with self.subTest(name):
                verify, pred = build_mutant(edits)
                self.assertEqual(wrong_on(verify, pred, by_id[killer]), level,
                                 "mutant %s on vector %s" % (name, killer))


if __name__ == "__main__":
    unittest.main()
