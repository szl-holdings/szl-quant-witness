"""Tests for the log-evidence replay in verify_observation.py (stdlib unittest).

Run from the repo root:
    python -m unittest discover -s test -p "test_*.py" -v

Merkle tests use an independent RFC 6962 reference (MTH / SUBPROOF, section
2.1) and need no network. Fixtures obs_0417..obs_0422 are byte copies of the
published observations on the observations branch at commit
12ca3050922cabc8e78f89e20de84c72f676c326 (git blob ids pinned below).
"""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import verify_observation as vo  # noqa: E402

FIXTURES = REPO / "test" / "fixtures"
FIXTURE_BLOBS = {
    "obs_0417_1793046357765.observation.json": "38b090ae7f41f6304f562f76cff75115f4b47a7c",
    "obs_0418_1793068487525.observation.json": "e44bc1bcfabceb7cabaf272dddba8b514b594689",
    "obs_0419_1793090052591.observation.json": "fba517acce3ed158a55be7be865a781b8881d1b2",
    "obs_0420_1793111404778.observation.json": "2bb75f26f5d2c891d4db162b60755cee38d19523",
    "obs_0421_1793132365770.observation.json": "7f69422bbdffc67b3b0d30bddc9347488af900e5",
    "obs_0422_1793154252851.observation.json": "b51f329b7267f2cb7fc1e46657c7589e8b9ca292",
}
OBSERVER_PIN = REPO / "keys" / "observer_pubkey.json"
REKOR_PIN = REPO / "keys" / "rekor_pubkey.pem"


def _real_crypto():
    try:
        import cryptography
    except ImportError:
        return False
    return getattr(cryptography, "__version__", None) is not None


def _mth(leaves):
    n = len(leaves)
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _subproof(m, leaves, complete):
    n = len(leaves)
    if m == n:
        return [] if complete else [_mth(leaves)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


LEAVES = [b"leaf-%d" % i for i in range(70)]
ROOTS = {n: _mth(LEAVES[:n]).hex() for n in range(1, 71)}


def proof(m, n):
    return [h.hex() for h in _subproof(m, LEAVES[:n], True)]


def rejects(*args):
    try:
        vo.verify_consistency(*args)
    except vo.ObservationError:
        return True
    return False


def load_summary(name):
    env = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return env, json.loads(base64.b64decode(env["payload"]))["predicate"]["summary"]


def synthetic(engine_size, live_size, engine_root, live_root, proof_hashes, bound=True, origin_live=None):
    return {
        "verdict": None,
        "ledger": {"chainBindingVerified": bound},
        "engineCheckpoint": {"origin": "rekor.sigstore.dev - 1", "treeSize": engine_size, "rootHex": engine_root},
        "liveCheckpoint": {"origin": origin_live or "rekor.sigstore.dev - 1", "treeSize": live_size, "rootHex": live_root},
        "consistency": {"proofHashes": proof_hashes},
    }


class ConsistencyTests(unittest.TestCase):
    def test_every_valid_proof_up_to_70_is_accepted(self):
        for n in range(1, 71):
            for m in range(1, n + 1):
                self.assertTrue(vo.verify_consistency(m, n, ROOTS[m], ROOTS[n], proof(m, n)), (m, n))

    def test_every_mutated_proof_is_rejected(self):
        for n in range(2, 71):
            for m in range(1, n):
                p = proof(m, n)
                for i in range(len(p)):
                    flipped = list(p)
                    flipped[i] = ("0" if p[i][0] != "0" else "1") + p[i][1:]
                    self.assertTrue(rejects(m, n, ROOTS[m], ROOTS[n], flipped), ("flip", m, n, i))
                    self.assertTrue(rejects(m, n, ROOTS[m], ROOTS[n], p[:i] + p[i + 1:]), ("drop", m, n, i))
                self.assertTrue(rejects(m, n, ROOTS[m], ROOTS[n], p + [p[-1]]), ("extra", m, n))
                self.assertTrue(rejects(m, n, ROOTS[n], ROOTS[m], p), ("swapped", m, n))

    def test_bad_sizes_roots_and_hex_are_rejected(self):
        p = proof(5, 17)
        for args in [
            (5, 17, ROOTS[6], ROOTS[17], p), (5, 17, ROOTS[5], ROOTS[16], p), (6, 17, ROOTS[5], ROOTS[17], p),
            (17, 5, ROOTS[17], ROOTS[5], p), (0, 5, ROOTS[1], ROOTS[5], proof(1, 5)),
            (True, 5, ROOTS[1], ROOTS[5], proof(1, 5)), (2**53, 2**53 + 1, ROOTS[1], ROOTS[2], []),
            (5, 17, ROOTS[5][:-2], ROOTS[17], p), (5, 17, ROOTS[5], ROOTS[17], [p[0][:-1] + "z"] + p[1:]),
            (5, 17, ROOTS[5], ROOTS[17], []), (5, 17, ROOTS[5], ROOTS[17], "not-a-list"),
            (9, 9, ROOTS[9], ROOTS[10], []), (9, 9, ROOTS[9], ROOTS[9], [ROOTS[1]]),
        ]:
            self.assertTrue(rejects(*args), args[:2])
        self.assertTrue(vo.verify_consistency(9, 9, ROOTS[9], ROOTS[9], []))

    def test_proof_alone_does_not_bind_second_size(self):
        """Measured RFC 6962 property, identical in witness.mjs.

        A proof for (m, n) also verifies against a claimed size n' with the
        same proof shape; only the signed checkpoint binds the size, which is
        why check_log_evidence verifies the live note.
        """
        p = proof(5, 17)
        self.assertFalse(rejects(5, 18, ROOTS[5], ROOTS[17], p))
        self.assertTrue(rejects(5, 33, ROOTS[5], ROOTS[17], p))


class VerdictReplayTests(unittest.TestCase):
    def test_each_verdict_branch(self):
        cases = [
            (synthetic(5, 17, ROOTS[5], ROOTS[17], proof(5, 17)), "PREFIX_OK"),
            (synthetic(9, 9, ROOTS[9], ROOTS[9], []), "ROOTS_EQUAL"),
            (synthetic(9, 9, ROOTS[9], ROOTS[10], []), "SPLIT_VIEW"),
            (synthetic(5, 17, ROOTS[5], ROOTS[16], proof(5, 17)), "SPLIT_VIEW"),
            (synthetic(17, 5, ROOTS[17], ROOTS[5], []), "LOG_REGRESSED"),
            (synthetic(5, 17, ROOTS[5], ROOTS[17], proof(5, 17), origin_live="rekor.sigstore.dev - 2"), "SHARD_ROTATED"),
            (synthetic(5, 17, ROOTS[5], ROOTS[17], proof(5, 17), bound=False), "LEDGER_BINDING_MISMATCH"),
            (synthetic(9, 9, ROOTS[9], ROOTS[9], [], bound="yes"), "LEDGER_BINDING_MISMATCH"),
        ]
        for summary, want in cases:
            self.assertEqual(vo.recompute_verdict(summary), want)

    def test_malformed_summaries_are_refused(self):
        for bad in [{}, {"engineCheckpoint": {}, "liveCheckpoint": {}, "ledger": {}},
                    synthetic(True, 17, ROOTS[5], ROOTS[17], []), synthetic(5, "17", ROOTS[5], ROOTS[17], [])]:
            with self.assertRaises(vo.ObservationError):
                vo.recompute_verdict(bad)

    def test_published_fixtures_replay_and_tampering_flips_verdict(self):
        names = sorted(FIXTURE_BLOBS)
        for name in names:
            _, summary = load_summary(name)
            self.assertEqual(vo.recompute_verdict(summary), summary["verdict"], name)
            tampered = copy.deepcopy(summary)
            h = tampered["consistency"]["proofHashes"][0]
            tampered["consistency"]["proofHashes"][0] = ("0" if h[0] != "0" else "1") + h[1:]
            self.assertEqual(vo.recompute_verdict(tampered), "SPLIT_VIEW", name)

    def test_fixtures_are_pinned_byte_copies(self):
        for name, blob in FIXTURE_BLOBS.items():
            data = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), blob, name)


NOTE = ("rekor.sigstore.dev - 1193050959916656506\n3409884007\n"
        "1pk9lpC0As5YNZ8hGcSYPIxEbKj0Uoilafe7w62tXtA=\n\n"
        "\u2014 rekor.sigstore.dev wNI9ajBFAiBzkC4TiANJBKAyQIBtiRdM1mO9K1N3cI9VLrC1dCBoiQIhAI4F3CD9Kkyoe994gEZB+7VeM4mnyEjHNV9Dza9jMsQr\n")


class CheckpointParseTests(unittest.TestCase):
    def test_published_note_parses(self):
        cp = vo.parse_checkpoint(NOTE)
        self.assertEqual((cp["tree_size"], cp["sigs"][0]["key_hint_hex"]), (3409884007, "c0d23d6a"))
        self.assertEqual(cp["root_hex"], "d6993d9690b402ce58359f2119c4983c8c446ca8f45288a569f7bbc3adad5ed0")
        self.assertTrue(cp["note_body"].endswith("tXtA=\n"))

    def test_malformed_notes_are_refused(self):
        for i, text in enumerate([
            None, NOTE.replace("\n\n", "\n"), NOTE.replace(" - 1193", "-1193"),
            NOTE.replace("3409884007", "34098840O7"), NOTE.replace("3409884007", "0"),
            NOTE.replace("3409884007", str(2**53)), NOTE.replace("tXtA=", "tXtB="), NOTE.replace("tXtA=", "tXt"),
            NOTE.replace("\u2014", "-"), NOTE.replace("wNI9aj", "wNI9a!"), NOTE.split("\n\n")[0] + "\n\n",
            NOTE.replace("\u2014 rekor.sigstore.dev ", "\u2014 rekor.sigstore.dev  "),
            NOTE.replace("rekor.sigstore.dev wNI", "rekor.sigstore.dev AAAA"),
        ]):
            with self.assertRaises(vo.ObservationError, msg=i):
                vo.parse_checkpoint(text)


class SignatureSkipGuard(unittest.TestCase):
    def test_signature_tests_cannot_skip_in_ci(self):
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertTrue(_real_crypto(), "cryptography must be installed in CI")


@unittest.skipUnless(_real_crypto(), "cryptography not installed")
class LogEvidenceSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads(OBSERVER_PIN.read_text(encoding="utf-8"))
        cls.rekor_pem = REKOR_PIN.read_bytes()
        cls.log_key = vo.load_rekor_pin(cls.rekor_pem)

    def test_pinned_rekor_key_hint_matches_published_notes(self):
        hint = hashlib.sha256(vo.spki_der(self.log_key)).digest()[:4].hex()
        self.assertEqual(hint, "c0d23d6a")

    def test_published_note_verifies_and_forgery_is_refused(self):
        self.assertEqual(vo.verify_checkpoint(NOTE, self.log_key)["tree_size"], 3409884007)
        for forged in (NOTE.replace("3409884007", "3409884008"),
                       NOTE.replace("1pk9lpC0As5YNZ8hGcSYPIxEbKj0Uoilafe7w62tXtA=", base64.b64encode(b"\x00" * 32).decode())):
            with self.assertRaises(vo.ObservationError):
                vo.verify_checkpoint(forged, self.log_key)
        with self.assertRaises(vo.ObservationError):
            vo.load_rekor_pin(b"not a pem")

    def test_every_fixture_verifies_end_to_end_with_replay(self):
        for name in sorted(FIXTURE_BLOBS):
            env, _ = load_summary(name)
            r = vo.verify_observation(env, self.pin, self.rekor_pem)
            self.assertEqual(r["verdict"], "PREFIX_OK", name)

    def test_live_fields_must_agree_with_signed_note(self):
        _, summary = load_summary(sorted(FIXTURE_BLOBS)[0])
        for field, value in (("treeSize", summary["liveCheckpoint"]["treeSize"] + 1),
                             ("rootHex", "0" * 64), ("origin", "rekor.sigstore.dev - 2")):
            bad = copy.deepcopy(summary)
            bad["liveCheckpoint"][field] = value
            with self.assertRaises(vo.ObservationError, msg=field):
                vo.check_log_evidence(bad, self.log_key)

    def test_recorded_verdict_must_equal_replay(self):
        _, summary = load_summary(sorted(FIXTURE_BLOBS)[0])
        self.assertEqual(vo.check_log_evidence(summary, self.log_key), "PREFIX_OK")
        lie = copy.deepcopy(summary)
        lie["consistency"]["proofHashes"] = lie["consistency"]["proofHashes"][:-1]
        with self.assertRaises(vo.ObservationError):
            vo.check_log_evidence(lie, self.log_key)

    def test_cli_replays_by_default_and_no_replay_flag(self):
        name = "obs_0422_1793154252851.observation.json"
        for argv in ([str(FIXTURES / name)], ["--no-replay", str(FIXTURES / name)]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = vo.main(argv)
            self.assertEqual((code, out.getvalue().strip()), (0, f"OK PREFIX_OK {name}"), argv)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = vo.main(["--rekor-pin", str(OBSERVER_PIN), str(FIXTURES / name)])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
