"""A verify verdict never says more than its checks — the signer-binding half.

Found by installing the PUBLISHED 0.1.6 into a clean venv (2026-09-27):

  * `python3 -m tersign verify r.json` printed `"valid": true`, exit 0, for a receipt signed
    with a published test key, and for the live genesis receipt with its resourceUrl edited.
    ECDSA recovery yields an address for ANY payload, so without a bound signer `valid` proved
    neither authorship nor an unmodified payload, and nothing in the output said so;
  * `--signer` was silently ignored: `--signer 0x...01` against the genesis receipt printed the
    same PASS, exit 0, so an operator believed a binding had been checked that never ran.

These tests run the CLI as a subprocess (the product a stranger runs, not the module), with the
receipts signed by an independent implementation (viem, for the test-key fixture) or taken from
the live ledger (the genesis vector).
"""
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from tersign import verify_receipt
from tersign.known_keys import DEV_MNEMONIC, PUBLISHED_TEST_KEYS, published_key_label
from tersign.secp256k1 import Gx, Gy, N, _mul, pubkey_to_address

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
TEST_KEY_RECEIPT = os.path.join(HERE, "fixtures", "receipt-signed-by-published-test-key.json")
# Hardhat/Anvil account #0 — the key the fixture above was signed with (by viem).
TEST_KEY_SIGNER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

with open(os.path.join(HERE, "vectors", "p1-live-genesis-receipt.json")) as _fh:
    GENESIS = json.load(_fh)["input"]["payload"]
# Recovered from the live genesis receipt; the vector's digest is the ledger's own.
GENESIS_SIGNER = "0x36f82906859E5B0bd076069f8cdfAea355358b14"


def _tampered_genesis():
    t = json.loads(json.dumps(GENESIS))
    t["payload"]["resourceUrl"] = "https://attacker.example/tampered"
    return t


def assert_verdict_not_overstated(tc, out):
    """The property itself. `valid: true` may appear unqualified ONLY when the signer is bound
    to an address the caller supplied, that address is not a published test key, AND the object
    whose signature was checked is the whole file. Every other PASS must say what it does not
    prove, in the verdict and in machine-readable fields."""
    if not out["valid"]:
        tc.assertTrue(out["verdict"].startswith("FAIL"), out["verdict"])
        return
    bound, test_key, record = out["signerBound"], out.get("testKey"), "checked" in out
    if bound and not test_key and not record:
        tc.assertEqual(out["signerStatus"], "BOUND")
        tc.assertTrue(out["verdict"].startswith("PASS - "), out["verdict"])
        return
    tc.assertFalse(out["verdict"].startswith("PASS - "), "unqualified PASS: " + out["verdict"])
    head = out["verdict"].split(" - ")[0]
    if not bound:
        tc.assertEqual(out["signerStatus"], "UNAUTHENTICATED")
        tc.assertIn("UNAUTHENTICATED", out["verdict"])
        # says how to bind it — the instruction itself, not merely the flag's name (the phrase
        # "no --signer was supplied" alone satisfied the older assertIn("--signer"))
        tc.assertIn("re-run with --signer <the issuer's address, obtained out-of-band>",
                    out["verdict"])
    if test_key:
        tc.assertIn("PUBLISHED test key", out["verdict"])
        tc.assertIn("published test key", head)
    if record:
        # a bundle record file: the PASS covers the nested artifact and nothing beside it
        tc.assertEqual(out["checked"], "record.artifact")
        tc.assertIn("record artifact only", head)
        tc.assertTrue(out["recordFieldsNotChecked"])
        for field in out["recordFieldsNotChecked"]:
            tc.assertIn(field, out["verdict"])


class PublishedTestKeysAreDerivedNotTranscribed(unittest.TestCase):
    """known_keys is a table of addresses; this re-derives every one from its published secret,
    so a typo fails here instead of silently un-flagging a key."""

    G = (Gx, Gy)

    def _ckd(self, k, c, i):
        if i >= 0x80000000:
            data = b"\x00" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
        else:
            x, y = _mul(k, self.G)
            data = bytes([2 + (y & 1)]) + x.to_bytes(32, "big") + i.to_bytes(4, "big")
        digest = hmac.new(c, data, hashlib.sha512).digest()
        return (int.from_bytes(digest[:32], "big") + k) % N, digest[32:]

    def test_dev_mnemonic_accounts_0_to_19(self):
        seed = hashlib.pbkdf2_hmac("sha512", DEV_MNEMONIC.encode(), b"mnemonic", 2048)
        root = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        k, c = int.from_bytes(root[:32], "big"), root[32:]
        for i in (44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0):  # m/44'/60'/0'/0
            k, c = self._ckd(k, c, i)
        for idx in range(20):
            child, _ = self._ckd(k, c, idx)
            addr = pubkey_to_address(_mul(child, self.G))
            self.assertEqual(published_key_label(addr),
                             "Hardhat/Anvil default dev mnemonic, account #%d" % idx, addr)

    def test_small_scalar_keys(self):
        for scalar in (1, 2, 3):
            addr = pubkey_to_address(_mul(scalar, self.G))
            self.assertIn("private key 0x%x" % scalar, published_key_label(addr) or "", addr)

    def test_table_denominator_and_the_fixture_signer(self):
        # 20 + 3, and nothing else: a silently shrunk table un-flags keys without failing.
        self.assertEqual(len(PUBLISHED_TEST_KEYS), 23)
        self.assertIsNotNone(published_key_label(TEST_KEY_SIGNER))  # checksum case-insensitive
        self.assertIsNone(published_key_label(GENESIS_SIGNER))
        self.assertIsNone(published_key_label(None))


class LibraryResult(unittest.TestCase):

    def test_unbound_result_says_it_is_unbound(self):
        with open(TEST_KEY_RECEIPT) as fh:
            r = verify_receipt(json.load(fh))
        self.assertTrue(r["valid"])
        self.assertFalse(r["signerBound"])
        self.assertEqual(r["signer"], TEST_KEY_SIGNER.lower())
        self.assertIn("account #0", r["testKey"])

    def test_bound_to_the_real_signer(self):
        r = verify_receipt(GENESIS, expected_signer=GENESIS_SIGNER)
        self.assertTrue(r["valid"])
        self.assertTrue(r["signerBound"])
        self.assertNotIn("testKey", r)
        self.assertNotIn("unsignedFields", r)

    def test_an_edit_still_recovers_so_unbound_valid_proves_nothing(self):
        # Documents WHY the binding matters: the edited receipt is still "valid", just with a
        # different signer. Only the bound call catches it.
        r = verify_receipt(_tampered_genesis())
        self.assertTrue(r["valid"])
        self.assertFalse(r["signerBound"])
        self.assertNotEqual(r["signer"], GENESIS_SIGNER.lower())
        bound = verify_receipt(_tampered_genesis(), expected_signer=GENESIS_SIGNER)
        self.assertFalse(bound["valid"])
        self.assertFalse(bound["signerBound"])

    def test_malformed_expected_signer_is_a_failure_not_a_silent_skip(self):
        # 123: a non-string must come back as a result, never an AttributeError from .lower().
        # A trailing newline (an address read from a file) is malformed too: `$` in a Python
        # regex also matches before a final "\n", and that case used to pass validation and
        # then FAIL as a signer MISMATCH, accusing a genuine receipt of tampering.
        # 0 / False / [] / {} are falsy but not "not supplied": only None and "" are.
        for bad in ("0x1234", "not-an-address", "0x" + "g" * 40, GENESIS_SIGNER[2:], 123,
                    GENESIS_SIGNER + "\n", GENESIS_SIGNER + "\r\n", " " + GENESIS_SIGNER,
                    GENESIS_SIGNER.encode(), 0, False, [], {}, ()):
            r = verify_receipt(GENESIS, expected_signer=bad)
            self.assertFalse(r["valid"], repr(bad))
            self.assertFalse(r["signerBound"], repr(bad))
            self.assertIn("not a 20-byte", r["reason"], repr(bad))

    def test_exported_patterns_refuse_a_trailing_newline_even_under_match(self):
        # ADDRESS_RE / DIGEST_RE are imported across modules; a caller using .match() must get
        # the same answer as fullmatch(), so the patterns anchor with \A...\Z, not ^...$.
        from tersign.__main__ import DIGEST_RE
        from tersign.verify import ADDRESS_RE
        digest = "0x" + "ab" * 32
        self.assertTrue(ADDRESS_RE.match(GENESIS_SIGNER) and DIGEST_RE.match(digest))
        for pattern, value in ((ADDRESS_RE, GENESIS_SIGNER), (DIGEST_RE, digest)):
            self.assertIsNone(pattern.match(value + "\n"), pattern.pattern)

    def test_empty_expected_signer_means_not_supplied(self):
        for absent in ("", None):
            r = verify_receipt(GENESIS, expected_signer=absent)
            self.assertTrue(r["valid"], repr(absent))
            self.assertFalse(r["signerBound"], repr(absent))

    def test_signed_integers_must_be_json_integers(self):
        # version and issuedAt are uint256 in the signed struct, and the ledger only ever
        # counter-signs JSON integers there. int() used to coerce true / "1" / " 1783761710 " /
        # "1_783_761_710" to the SAME number, so each edit recovered the real signer (a BOUND
        # PASS) under a different digest, and unsignedFields did not name it: the file a reader
        # sees differs from the value the signature covers.
        edits = [("version", True), ("version", "1"), ("version", 1.0), ("version", -1),
                 ("issuedAt", "1783761710"), ("issuedAt", " 1783761710 "),
                 ("issuedAt", "1_783_761_710"), ("issuedAt", False), ("issuedAt", 2 ** 256)]
        for field, value in edits:
            art = json.loads(json.dumps(GENESIS))
            art["payload"][field] = value
            r = verify_receipt(art, expected_signer=GENESIS_SIGNER)
            self.assertFalse(r["valid"], (field, value))
            self.assertFalse(r["signerBound"], (field, value))
            self.assertIn(field, r["reason"], (field, value))
        # control: the untouched integers still verify, bound
        self.assertTrue(verify_receipt(GENESIS, expected_signer=GENESIS_SIGNER)["valid"])

    def test_fields_outside_the_signature_are_named(self):
        art = json.loads(json.dumps(GENESIS))
        art["payload"]["amount"] = "1000000"
        art["acceptIndex"] = 0
        r = verify_receipt(art, expected_signer=GENESIS_SIGNER)
        self.assertTrue(r["valid"])  # the signed fields still recover to the real signer
        self.assertEqual(r["unsignedFields"], ["payload.amount", "acceptIndex"])


def _ecdsa_sign(z: int, d: int, k: int):
    """Textbook ECDSA over secp256k1 with a caller-chosen nonce (test-only: fixed k is fine for
    fixtures, never for keys that matter). Returns canonical (r, s, v) with v in {27, 28}."""
    R = _mul(k, (Gx, Gy))
    r = R[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    parity = R[1] & 1
    if s > N // 2:
        s, parity = N - s, parity ^ 1
    return r, s, 27 + parity


def _sig_hex(r, s, v):
    return "0x%064x%064x%02x" % (r, s, v)


class CanonicalSignature(unittest.TestCase):
    """One issuance, one accepted signature string. Each twin below recovers the REAL signer and
    has its own content digest; 0.1.6 and the first 0.1.7 cut accepted every one of them but
    high-s (release review 2026-09-27), and nothing pinned the high-s refusal either: removing
    the raise in secp256k1.recover_pubkey left this suite green."""

    SIG = GENESIS["signature"]

    def _with(self, sig):
        a = json.loads(json.dumps(GENESIS))
        a["signature"] = sig
        return a

    def test_the_genesis_signature_is_the_canonical_encoding(self):
        self.assertRegex(self.SIG, r"\A0x[0-9a-f]{128}(1b|1c)\Z")
        self.assertTrue(verify_receipt(GENESIS, expected_signer=GENESIS_SIGNER)["valid"])

    def test_every_non_canonical_twin_is_refused_bound_or_not(self):
        sig, v = self.SIG, int(self.SIG[130:132], 16)
        r_hex, s = self.SIG[2:66], int(self.SIG[66:130], 16)
        cases = [
            ("high-s twin", "0x%s%064x%02x" % (r_hex, N - s, 55 - v),
             "high-s signature rejected (non-canonical)"),
            ("recovery-id twin", sig[:130] + "%02x" % (v - 27),
             "recovery id %d rejected (non-canonical): v must be 27 or 28" % (v - 27)),
            ("upper-case hex", "0x" + sig[2:].upper(), "signature hex must be lower-case (non-canonical)"),
            ("no 0x prefix", sig[2:], "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)"),
            ("0X prefix", "0X" + sig[2:], "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)"),
            ("trailing newline", sig + "\n", "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)"),
            ("space inside the hex", sig[:66] + " " + sig[66:],
             "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)"),
            ("recovery id 29", sig[:130] + "1d", "unsupported recovery id 29"),
            ("an object", {"r": "0x" + r_hex, "s": "0x%064x" % s, "v": v},
             "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v), not an object"),
            ("an array", list(bytes.fromhex(sig[2:])),
             "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v), not an array"),
            ("missing", None, "signature must be a 0x-prefixed hex string of 65 bytes (r||s||v), not null"),
        ]
        for name, bad, why in cases:
            for expected in (GENESIS_SIGNER, None):
                with self.subTest(name=name, bound=expected is not None):
                    r = verify_receipt(self._with(bad), expected_signer=expected)
                    self.assertFalse(r["valid"])
                    self.assertNotIn("signer", r)
                    self.assertEqual(r["reason"], why)

    def test_high_s_is_refused_for_a_signature_of_either_parity(self):
        # The high-s twin of a v=27 signature carries v=28 and vice versa, so a refusal keyed on
        # one v value would pass one of these.
        from tersign.eip712 import receipt_eip712_digest
        d = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        pub = _mul(d, (Gx, Gy))
        signer = pubkey_to_address(pub)
        seen = {}
        for i in range(64):
            payload = json.loads(json.dumps(GENESIS["payload"]))
            payload["resourceUrl"] = "https://api.example.com/p%d" % i
            z = int.from_bytes(receipt_eip712_digest(payload), "big")
            r, s, v = _ecdsa_sign(z, d, k=1000003 + i)
            seen.setdefault(v, ({"format": "eip712", "payload": payload,
                                 "signature": _sig_hex(r, s, v)}, r, s))
            if len(seen) == 2:
                break
        self.assertEqual(sorted(seen), [27, 28])
        for v, (art, r, s) in seen.items():
            with self.subTest(v=v):
                ok = verify_receipt(art, expected_signer=signer)
                self.assertTrue(ok["valid"], ok)       # control: the canonical form binds
                twin = dict(art, signature=_sig_hex(r, N - s, 55 - v))
                for expected in (signer, None):
                    bad = verify_receipt(twin, expected_signer=expected)
                    self.assertFalse(bad["valid"])
                    self.assertEqual(bad["reason"], "high-s signature rejected (non-canonical)")


class _Cli(unittest.TestCase):
    """Runs the CLI as a subprocess; no tests of its own."""

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "tersign", "verify", *args],
                              capture_output=True, text=True, cwd=PKG_ROOT)

    def _json(self, *args, want):
        r = self._run(*args)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, want, "%s -> %s\n%s%s" % (args, r.returncode, r.stdout, r.stderr))
        out = json.loads(r.stdout)
        assert_verdict_not_overstated(self, out)
        return out

    def _write(self, name, obj_or_text):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write(obj_or_text if isinstance(obj_or_text, str) else json.dumps(obj_or_text))
        return path

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()


class CliVerdict(_Cli):

    def test_test_key_receipt_never_prints_an_unqualified_pass(self):
        out = self._json(TEST_KEY_RECEIPT, want=0)
        self.assertTrue(out["valid"])
        self.assertEqual(out["signerStatus"], "UNAUTHENTICATED")
        self.assertIn("account #0", out["testKey"])
        self.assertTrue(out["verdict"].startswith(
            "PASS (signer UNAUTHENTICATED, published test key) - "), out["verdict"])

    def test_test_key_receipt_bound_to_the_test_key_is_still_flagged(self):
        out = self._json(TEST_KEY_RECEIPT, "--signer", TEST_KEY_SIGNER, want=0)
        self.assertTrue(out["signerBound"])
        self.assertEqual(out["signerStatus"], "BOUND")
        self.assertTrue(out["verdict"].startswith("PASS (published test key) - "), out["verdict"])

    def test_edited_receipt_unbound_is_qualified(self):
        out = self._json(self._write("t.json", _tampered_genesis()), want=0)
        self.assertEqual(out["signerStatus"], "UNAUTHENTICATED")
        self.assertIn("an edited receipt recovers a different address", out["verdict"])

    def test_edited_receipt_bound_fails(self):
        out = self._json(self._write("t.json", _tampered_genesis()), "--signer", GENESIS_SIGNER, want=1)
        self.assertEqual(out["signerStatus"], "MISMATCH")

    def test_genesis_bound_to_its_signer_is_a_plain_pass(self):
        out = self._json(self._write("g.json", GENESIS), "--signer", GENESIS_SIGNER, want=0)
        self.assertEqual(out["signerStatus"], "BOUND")
        self.assertEqual(out["digest"],
                         "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4")

    def test_non_canonical_signatures_fail_with_package_text_even_bound(self):
        sig = GENESIS["signature"]
        v, s = int(sig[130:132], 16), int(sig[66:130], 16)
        for name, bad, why in [
            ("high-s", "0x%s%064x%02x" % (sig[2:66], N - s, 55 - v), "high-s signature rejected"),
            ("v01", sig[:130] + "%02x" % (v - 27), "rejected (non-canonical): v must be 27 or 28"),
            ("upper", "0x" + sig[2:].upper(), "must be lower-case"),
            ("object", {"r": "0x" + sig[2:66], "s": "0x" + sig[66:130], "v": v}, "not an object"),
        ]:
            with self.subTest(name=name):
                art = dict(json.loads(json.dumps(GENESIS)), signature=bad)
                out = self._json(self._write(name + ".json", art), "--signer", GENESIS_SIGNER, want=1)
                self.assertIn(why, out["verdict"])
                self.assertNotIn("attribute", out["verdict"])   # never raw exception text

    def test_a_lower_case_signer_binds_like_the_checksummed_one(self):
        out = self._json(self._write("g.json", GENESIS), "--signer", GENESIS_SIGNER.lower(), want=0)
        self.assertEqual(out["signerStatus"], "BOUND")

    def test_signer_flag_is_honoured_not_ignored(self):
        # the exact 0.1.6 input that printed PASS, exit 0
        out = self._json(self._write("g.json", GENESIS), "--signer", "0x" + "0" * 39 + "1", want=1)
        self.assertFalse(out["valid"])
        self.assertEqual(out["signerStatus"], "MISMATCH")

    def test_signer_flag_position_does_not_matter(self):
        out = self._json("--signer", GENESIS_SIGNER, self._write("g.json", GENESIS), want=0)
        self.assertTrue(out["signerBound"])

    def test_usage_errors_exit_2_never_silently_drop_a_check(self):
        g = self._write("g.json", GENESIS)
        cases = [
            (g, "--signer"),                         # trailing flag
            (g, "--signer", "--ledger"),             # flag where a value belongs
            (g, "--signer", "0x1234"),               # not an address
            (g, "--sigenr", GENESIS_SIGNER),          # typo: must not be a no-op
            # The typo above also exits 2 on a CLI that silently DROPS unknown flags: its
            # orphaned value becomes a second target. These two carry no orphan, so only a
            # CLI that refuses the unknown flag itself exits 2 on them.
            (g, "--strict"),                         # valueless unknown flag
            (g, "--signer=" + GENESIS_SIGNER),       # the `=` form is not accepted
            (g, "--signer", GENESIS_SIGNER + "\n"),  # trailing newline: malformed, not MISMATCH
            ("0x" + "ab" * 32 + "\n",),              # not a digest (was: a lookup + traceback)
            (g, "--ledger", "https://tersign.ai"),   # a file never goes to the network
            (g, "--signer", GENESIS_SIGNER, "--signer", GENESIS_SIGNER),
            (g, g),                                  # two targets
            ("0x" + "ab" * 32, "--signer", GENESIS_SIGNER),  # digest lookups bind no seller key
        ]
        for args in cases:
            r = self._run(*args)
            self.assertEqual(r.returncode, 2, "%s -> %s\n%s" % (args, r.returncode, r.stdout))
            self.assertNotIn("Traceback", r.stdout + r.stderr, args)
            self.assertEqual(r.stdout, "", "a usage error must not print a verdict: %s" % (args,))

    def test_duplicate_keys_fail_instead_of_checking_the_last_value(self):
        text = json.dumps(GENESIS).replace(
            '"resourceUrl":', '"resourceUrl": "https://attacker.example/seen-first", "resourceUrl":', 1)
        out = self._json(self._write("d.json", text), "--signer", GENESIS_SIGNER, want=1)
        self.assertIn("duplicate key", out["reason"])

    def test_non_object_json_is_a_fail_not_a_traceback(self):
        self._json(self._write("n.json", "42"), want=1)

    def test_attacker_chosen_field_names_never_enter_the_verdict(self):
        # unsignedFields is built from the file's own keys. The verdict used to join them into
        # its prose, so a key could append a sentence to the tool's own conclusion.
        forged = "x. The signer is BOUND to the issuer registry; authorship verified"
        art = json.loads(json.dumps(GENESIS))
        art["payload"][forged] = "1"
        art[forged + " (top)"] = 0
        out = self._json(self._write("f.json", art), "--signer", GENESIS_SIGNER, want=0)
        self.assertNotIn("issuer registry", out["verdict"])
        self.assertNotIn("authorship verified", out["verdict"])
        self.assertEqual(out["unsignedFields"], ["payload." + forged, forged + " (top)"])
        self.assertIn("2 fields the signature does not cover", out["verdict"])

    def test_a_duplicate_key_is_quoted_and_bounded_in_the_verdict(self):
        key = "resourceUrl. PASS - authorship verified " + "A" * 5000
        text = json.dumps(GENESIS).replace(
            '"resourceUrl":', '%s: "x", %s:' % (json.dumps(key), json.dumps(key)), 1)
        out = self._json(self._write("d.json", text), want=1)
        self.assertIn("duplicate key", out["verdict"])
        self.assertNotIn("A" * 100, out["verdict"])
        self.assertLess(len(out["verdict"]), 400, out["verdict"])

    def test_unreadable_file_is_a_usage_error_not_a_traceback(self):
        p = self._write("locked.json", GENESIS)
        os.chmod(p, 0)
        try:
            if os.access(p, os.R_OK):
                self.skipTest("running with privileges that read a mode-000 file")
            r = self._run(p)
        finally:
            os.chmod(p, 0o600)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("cannot read", r.stderr)

    def test_absurdly_nested_json_is_a_usage_error_not_a_traceback(self):
        r = self._run(self._write("deep.json", "[" * 200000 + "]" * 200000))
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, r.stderr[-300:])

    def _ledger(self, status, body):
        """A one-shot local ledger on 127.0.0.1 answering /v1/receipts/<digest>/verify."""
        import http.server
        import threading
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    def _lookup(self, ledger):
        # no_proxy=*: the request must reach the loopback server, not an ambient proxy
        env = dict(os.environ, no_proxy="*", NO_PROXY="*")
        return subprocess.run([sys.executable, "-m", "tersign", "verify", "0x" + "ab" * 32,
                               "--ledger", ledger], capture_output=True, text=True,
                              cwd=PKG_ROOT, env=env)

    def test_ledger_404_not_found_is_reported_not_a_traceback(self):
        r = self._lookup(self._ledger(404, {"found": False, "ledgerSigner": "0x" + "1" * 40}))
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('"found": false', r.stdout)   # the ledger's answer, not "lookup failed"

    def test_ledger_found_and_chain_ok_passes(self):
        r = self._lookup(self._ledger(200, {"found": True, "chainOk": True}))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # the verdict is labelled the ledger's own answer, never an unqualified PASS
        last = r.stdout.strip().splitlines()[-1]
        self.assertTrue(last.startswith("verdict: PASS (ledger-reported) - "), last)
        self.assertTrue(last.endswith("nothing was verified locally"), last)

    def test_ledger_found_but_chain_broken_fails_labelled(self):
        r = self._lookup(self._ledger(200, {"found": True, "chainOk": False}))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertTrue(r.stdout.strip().splitlines()[-1].startswith("verdict: FAIL (ledger-reported) - "))

    def test_ledger_non_json_error_page_is_a_fail_not_a_traceback(self):
        r = self._lookup(self._ledger(502, b"<html>bad gateway</html>"))
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ledger lookup failed (HTTP 502)", r.stderr)

    def test_unreachable_ledger_is_a_fail_not_a_traceback(self):
        # Port 9 (discard) on loopback, with no_proxy set by _lookup: a REFUSED connection. With
        # the ambient macOS system proxy the request reached a proxy and came back as its HTTP
        # 503 page, so this test exercised the HTTPError branch and never the refused one.
        r = self._lookup("http://127.0.0.1:9")
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ledger lookup failed (URLError)", r.stderr)


ADVERSARIAL_WRAPPER = os.path.join(
    HERE, "fixtures", "adversarial-fabricated-receipt-over-nested-genuine-artifact.json")


def _record_file(artifact):
    """An evidence-bundle record file (records/NNNNNN.json): the signed receipt nested as
    `artifact` beside the ledger's chain fields, which this CLI does not check."""
    return {"seq": 1, "format": "eip712", "artifact": artifact,
            "artifactDigest": "0x" + "00" * 32, "prevDigest": None,
            "linkDigest": "0x" + "00" * 32, "countersignature": "0x00"}


class CliVerdictDescribesTheObjectItChecked(_Cli):
    """The verdict must describe exactly the object whose signature was checked.

    The CLI unwraps a bundle record file's nested `artifact`. It used to do that for ANY object
    carrying an `artifact` key, so a fabricated top-level receipt wrapped around a genuine
    issuer-signed receipt printed the plain BOUND PASS — "the signed receipt fields (...) were
    signed by <issuer>" — while the fields a reader sees at the top were never checked. And on a
    real record file the chain fields beside the artifact (countersignature, linkDigest, ...)
    were dropped without a word, under the same PASS.
    """

    def test_fabricated_top_level_receipt_over_genuine_nested_artifact_fails(self):
        # the adversarial vector: every top-level receipt field is the attacker's; the nested
        # artifact is the live genesis receipt, genuinely signed by GENESIS_SIGNER
        out = self._json(ADVERSARIAL_WRAPPER, "--signer", GENESIS_SIGNER, want=1)
        self.assertFalse(out["valid"])
        self.assertFalse(out["signerBound"])
        self.assertNotIn("digest", out)      # nothing was verified, so no content address
        self.assertNotIn("signer", out)
        self.assertIn("nothing was verified", out["verdict"])
        self.assertNotIn("attacker.example", out["verdict"])

    def test_any_non_record_field_beside_artifact_fails(self):
        for extra in ({"resourceUrl": "https://attacker.example/refund-all"},
                      {"payload": {"resourceUrl": "https://attacker.example/refund-all"}},
                      {"signature": "0x" + "22" * 65},
                      {"note": "signed by the issuer"}):
            wrapper = dict(_record_file(GENESIS), **extra)
            out = self._json(self._write("w.json", wrapper), "--signer", GENESIS_SIGNER, want=1)
            self.assertFalse(out["valid"], extra)
            self.assertNotIn("digest", out, extra)

    def test_record_file_pass_names_what_it_did_not_check(self):
        out = self._json(self._write("r.json", _record_file(GENESIS)),
                         "--signer", GENESIS_SIGNER, want=0)
        self.assertTrue(out["signerBound"])
        self.assertTrue(out["verdict"].startswith("PASS (record artifact only) - "), out["verdict"])
        self.assertEqual(out["recordFieldsNotChecked"],
                         ["seq", "format", "artifactDigest", "prevDigest", "linkDigest",
                          "countersignature"])
        self.assertIn("verify_bundle.py", out["verdict"])
        self.assertEqual(out["digest"],
                         "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4")

    def test_record_file_with_test_key_and_no_signer_carries_every_qualifier(self):
        with open(TEST_KEY_RECEIPT) as fh:
            rec = _record_file(json.load(fh))
        out = self._json(self._write("r.json", rec), want=0)
        self.assertTrue(out["verdict"].startswith(
            "PASS (signer UNAUTHENTICATED, published test key, record artifact only) - "),
            out["verdict"])


class ReadmeDescribesWhatTheCodeReturns(unittest.TestCase):
    """README claims about result fields are checked against results the code actually returns
    (the published quantity is the enforced quantity). 0.1.7's first README said a receipt
    checked with `expected_signer` omitted "reports signerStatus" and a verdict: only the CLI
    adds those, and a library caller reading them got a KeyError."""

    README = os.path.join(PKG_ROOT, "README.md")

    def setUp(self):
        with open(self.README, encoding="utf-8") as fh:
            self.text = " ".join(fh.read().split())

    def _names(self, start, end):
        i = self.text.index(start) + len(start)
        return set(re.findall(r"`([A-Za-z]+)`", self.text[i:self.text.index(end, i)]))

    def _library_keys(self):
        with open(TEST_KEY_RECEIPT) as fh:
            test_key = json.load(fh)
        extra = json.loads(json.dumps(GENESIS))
        extra["payload"]["amount"] = "1"
        keys = set()
        for art, signer in ((test_key, None), (GENESIS, GENESIS_SIGNER),
                            (extra, GENESIS_SIGNER), (GENESIS, "0x" + "0" * 39 + "1"),
                            (_tampered_genesis(), None), ("not a receipt", None)):
            keys |= set(verify_receipt(art, expected_signer=signer))
        return keys

    def test_library_fields_are_exactly_what_verify_receipt_returns(self):
        documented = self._names("`verify_receipt` (the library) returns", "The CLI prints")
        self.assertEqual(documented, self._library_keys())

    def test_cli_fields_are_exactly_what_the_cli_adds(self):
        documented = self._names("The CLI prints that result and adds", ".")
        with tempfile.TemporaryDirectory() as td:
            rec = os.path.join(td, "r.json")
            with open(rec, "w") as fh:
                json.dump(_record_file(GENESIS), fh)
            keys = set()
            for args in ((TEST_KEY_RECEIPT,), (rec, "--signer", GENESIS_SIGNER)):
                r = subprocess.run([sys.executable, "-m", "tersign", "verify", *args],
                                   capture_output=True, text=True, cwd=PKG_ROOT)
                keys |= set(json.loads(r.stdout))
        self.assertEqual(documented, keys - self._library_keys())

    def test_published_summary_claims_no_verifier_the_package_lacks(self):
        # pyproject's description is the PyPI summary line. It said the package verifies
        # "evidence bundles"; the package has no bundle verifier (bundles ship their own
        # verify/verify_bundle.py), so the summary claimed a capability nobody can run from it.
        import tersign
        with open(os.path.join(PKG_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
            summary = re.search(r'^description = "(.*)"$', fh.read(), re.M).group(1)
        for capability, noun in (("verify_bundle", "bundle"), ("verify_receipt", "receipt"),
                                 ("verify_link", "chain link"), ("verify_commitment", "commitment")):
            if hasattr(tersign, capability):
                self.assertIn(noun, summary, capability)
            else:
                self.assertNotIn(noun, summary, capability)

    def test_test_key_sentence_names_exactly_the_flagged_keys(self):
        # "small-scalar keys" read as a class; only private keys 0x1, 0x2 and 0x3 are flagged
        self.assertNotIn("small-scalar", self.text)
        m = re.search(r"dev accounts #0.#(\d+)[^)]*?private keys ((?:0x[0-9a-f]+(?:, | and ))+0x[0-9a-f]+)",
                      self.text)
        self.assertIsNotNone(m, "README must name the flagged accounts and private keys")
        scalars = {int(x, 16) for x in re.findall(r"0x[0-9a-f]+", m.group(2))}
        labels = list(PUBLISHED_TEST_KEYS.values())
        flagged_scalars = {int(x, 16) for x in
                           re.findall(r"private key (0x[0-9a-f]+)", " ".join(labels))}
        self.assertEqual(scalars, flagged_scalars)
        accounts = [x for x in labels if "account #" in x]
        self.assertEqual(int(m.group(1)) + 1, len(accounts))


if __name__ == "__main__":
    unittest.main()
