"""Cross-language and fail-closed tests for the log-evidence replay (stdlib unittest).

Run from the repo root:
    python -m unittest discover -s test -p "test_*.py" -v

Complements test_log_replay.py. The parity tests feed the same inputs to the
vendored JS (witness.mjs parseCheckpoint, verifyCheckpoint,
rfc6962VerifyConsistency) and require the same accept/refuse outcome, except
where the Python verifier is deliberately stricter; those cases are listed
separately. The end-to-end tests sign with the vendored JS an observation
whose recorded verdict its own log evidence contradicts. Consistency proofs
come from the RFC 6962 section 2.1.2 definition over synthetic trees.
"""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import verify_observation as vo  # noqa: E402

NODE = shutil.which("node")
FIXTURE = REPO / "test" / "fixtures" / "obs_0422_1793154252851.observation.json"
REKOR_PEM = (REPO / "keys" / "rekor_pubkey.pem").read_bytes()
REKOR_HINT = "c0d23d6a"
ORIGIN = "rekor.sigstore.dev - 1193050959916656506"
LIVE_SIZE = 3409884007

NODE_WITNESS = r"""
import { readFileSync } from 'node:fs';
import { parseCheckpoint, verifyCheckpoint, rfc6962VerifyConsistency } from './vendor/szl-quant/witness.mjs';
import { signEnvelope } from './vendor/szl-quant/dsse.mjs';
import { generateEngineKeypair, keyIdFromPublicKey, publicKeySpkiBase64 } from './vendor/szl-quant/keys.mjs';
const req = JSON.parse(readFileSync(0, 'utf8'));
const outcome = (fn) => { try { return { ok: true, value: fn() }; } catch (e) { return { ok: false, reason: e.message }; } };
let out;
if (req.op === 'parse') {
  out = req.texts.map((t) => outcome(() => {
    const cp = parseCheckpoint(t);
    return { origin: cp.origin, treeSize: cp.treeSize, rootHex: cp.rootHashHex, hints: cp.sigs.map((s) => s.keyHintHex) };
  }));
} else if (req.op === 'verifyCheckpoint') {
  out = req.texts.map((t) => verifyCheckpoint(t, req.pem).ok);
} else if (req.op === 'consistency') {
  out = req.cases.map((c) => outcome(() => rfc6962VerifyConsistency(c)).ok);
} else if (req.op === 'sign') {
  const { privateKey, publicKey } = generateEngineKeypair();
  const keyId = keyIdFromPublicKey(publicKey);
  req.statement.predicate.summary.observer.keyId = keyId;
  out = { envelope: signEnvelope(req.statement, privateKey, publicKey), keyId, spki: publicKeySpkiBase64(publicKey) };
} else {
  throw new Error('unknown op ' + req.op);
}
process.stdout.write(JSON.stringify(out));
"""


def node(req):
    proc = subprocess.run(
        [NODE, "--input-type=module", "-e", NODE_WITNESS],
        input=json.dumps(req),
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=REPO,
        check=True,
        timeout=120,
    )
    return json.loads(proc.stdout)


def fixture_statement():
    envelope = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(envelope["payload"]))


# RFC 6962 section 2.1 reference: tree hash and consistency proof generation.
def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_point(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def subproof(m, leaves, complete):
    n = len(leaves)
    if m == n:
        return [] if complete else [mth(leaves)]
    k = split_point(n)
    if m <= k:
        return subproof(m, leaves[:k], complete) + [mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


LEAVES = [leaf_hash(b"leaf-%d" % i) for i in range(21)]


def consistency_case(m, n):
    return {
        "firstSize": m,
        "secondSize": n,
        "firstRootHex": mth(LEAVES[:m]).hex(),
        "secondRootHex": mth(LEAVES[:n]).hex(),
        "proofHex": [h.hex() for h in subproof(m, LEAVES[:n], True)],
    }


def padded_cases():
    # One extra hash X, with both claimed roots rehashed to H(X, root) to absorb it.
    pad = bytes.fromhex("ab" * 32)
    cases = []
    for m, n in [(3, 5), (5, 13), (6, 7)]:
        case = consistency_case(m, n)
        case["proofHex"].append(pad.hex())
        case["firstRootHex"] = node_hash(pad, mth(LEAVES[:m])).hex()
        case["secondRootHex"] = node_hash(pad, mth(LEAVES[:n])).hex()
        cases.append(case)
    return cases


def flip(hex_hash):
    return "%02x" % (int(hex_hash[:2], 16) ^ 0x01) + hex_hash[2:]


def py_consistency(case):
    try:
        return vo.verify_consistency(
            case["firstSize"], case["secondSize"], case["firstRootHex"], case["secondRootHex"], case["proofHex"]
        )
    except vo.ObservationError:
        return False


def disagreements(cases, js_outcomes):
    """(firstSize, secondSize) of every case where Python and JS disagree."""
    return [
        (c["firstSize"], c["secondSize"])
        for c, js in zip(cases, js_outcomes, strict=True)
        if py_consistency(c) != js
    ]


def py_parse(text):
    try:
        cp = vo.parse_checkpoint(text)
    except vo.ObservationError:
        return {"ok": False}
    return {
        "ok": True,
        "value": {
            "origin": cp["origin"],
            "treeSize": cp["tree_size"],
            "rootHex": cp["root_hex"],
            "hints": [s["key_hint_hex"] for s in cp["sigs"]],
        },
    }


def sig_line(raw):
    return "— rekor.sigstore.dev " + base64.b64encode(raw).decode()


def note(size_line, root_line, *sig_lines):
    return f"{ORIGIN}\n{size_line}\n{root_line}\n\n" + "".join(line + "\n" for line in sig_lines)


PUBLISHED_NOTE = fixture_statement()["predicate"]["summary"]["liveCheckpoint"]["rawNote"]
PUBLISHED_ROOT_B64 = PUBLISHED_NOTE.split("\n")[2]
PUBLISHED_SIG_LINE = PUBLISHED_NOTE.split("\n")[4]
SHORT_SIG = sig_line(bytes.fromhex(REKOR_HINT) + b"\x00\x01\x02")  # 7 bytes, so base64 is padded


class NodeSkipGuard(unittest.TestCase):
    def test_parity_tests_cannot_skip_in_ci(self):
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertIsNotNone(NODE, "node must be installed in CI")


class FailClosedEdgeTests(unittest.TestCase):
    def setUp(self):
        self.key = vo.load_rekor_pin(REKOR_PEM)

    def test_refuses_a_proof_padded_past_the_root(self):
        for case in padded_cases():
            with self.subTest(m=case["firstSize"], n=case["secondSize"]):
                with self.assertRaisesRegex(vo.ObservationError, "too many proof hashes"):
                    vo.verify_consistency(
                        case["firstSize"], case["secondSize"], case["firstRootHex"], case["secondRootHex"], case["proofHex"]
                    )

    def test_refuses_hashes_that_are_not_exactly_64_hex_digits(self):
        case = consistency_case(5, 9)
        good = case["proofHex"][0]
        malformed = {
            "spaced": " ".join(good[i : i + 2] for i in range(0, 64, 2)),
            "trailing newline": good + "\n",
            "odd length": good + "a",
            "short": good[:62],
        }
        self.assertIs(py_consistency(case), True)
        for name, value in malformed.items():
            with self.subTest(name=name):
                bad = copy.deepcopy(case)
                bad["proofHex"][0] = value
                self.assertFalse(py_consistency(bad))

    def test_refuses_a_huge_tree_size_as_an_observation_error(self):
        with self.assertRaisesRegex(vo.ObservationError, "tree size out of range"):
            vo.parse_checkpoint(note("9" * 5000, PUBLISHED_ROOT_B64, SHORT_SIG))

    def test_refuses_a_pin_whose_hint_matches_no_signature(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaisesRegex(vo.ObservationError, "no checkpoint signature carries the pinned key's hint"):
            vo.verify_checkpoint(PUBLISHED_NOTE, other)

    def test_refuses_the_pinned_hint_over_another_keys_signature(self):
        body = PUBLISHED_NOTE[: PUBLISHED_NOTE.index("\n\n") + 1]
        forged = ec.generate_private_key(ec.SECP256R1()).sign(body.encode(), ec.ECDSA(hashes.SHA256()))
        text = body + "\n" + sig_line(bytes.fromhex(REKOR_HINT) + forged) + "\n"
        with self.assertRaisesRegex(vo.ObservationError, "checkpoint signature invalid"):
            vo.verify_checkpoint(text, self.key)

    def test_cli_refuses_non_ecdsa_rekor_pins_and_no_replay_never_reads_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            ed_pem = Path(tmp) / "ed25519.pem"
            ed_pem.write_bytes(
                Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            )
            for args, want_code, want_out, want_err in [
                (["--rekor-pin", str(ed_pem)], 2, "", "PIN-ERROR pinned log key is not ECDSA"),
                (["--rekor-pin", str(Path(tmp) / "absent.pem")], 2, "", "PIN-ERROR"),
                (["--no-replay", "--rekor-pin", str(Path(tmp) / "absent.pem")], 0, f"OK PREFIX_OK {FIXTURE.name}", ""),
            ]:
                with self.subTest(args=args):
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = vo.main([str(FIXTURE), *args])
                    self.assertEqual((code, out.getvalue().strip()), (want_code, want_out))
                    self.assertTrue(err.getvalue().startswith(want_err), err.getvalue())


@unittest.skipUnless(NODE, "node is required for the cross-language tests")
class CrossLanguageReplayTests(unittest.TestCase):
    def test_checkpoint_parsing_matches_js(self):
        root31 = base64.b64encode(b"\x01" * 31).decode()
        texts = {
            "published": PUBLISHED_NOTE,
            "leading zeros": note("007", PUBLISHED_ROOT_B64, SHORT_SIG),
            "largest safe size": note("9007199254740991", PUBLISHED_ROOT_B64, SHORT_SIG),
            "two signatures": note("7", PUBLISHED_ROOT_B64, SHORT_SIG, PUBLISHED_SIG_LINE),
            "no separator": PUBLISHED_NOTE.replace("\n\n", "\n"),
            "crlf": PUBLISHED_NOTE.replace("\n", "\r\n"),
            "origin without tree id": PUBLISHED_NOTE.replace(ORIGIN, "rekor.sigstore.dev", 1),
            "origin with a space": PUBLISHED_NOTE.replace(ORIGIN, "rekor sigstore - 1", 1),
            "size zero": note("0", PUBLISHED_ROOT_B64, SHORT_SIG),
            "negative size": note("-1", PUBLISHED_ROOT_B64, SHORT_SIG),
            "size with letters": note("12a", PUBLISHED_ROOT_B64, SHORT_SIG),
            "size above 2^53": note("9007199254740992", PUBLISHED_ROOT_B64, SHORT_SIG),
            "5000-digit size": note("9" * 5000, PUBLISHED_ROOT_B64, SHORT_SIG),
            "31-byte root": note("7", root31, SHORT_SIG),
            "unpadded root": note("7", PUBLISHED_ROOT_B64.rstrip("="), SHORT_SIG),
            "root with non-zero pad bits": note("7", PUBLISHED_ROOT_B64[:-2] + "B=", SHORT_SIG),
            "hyphen instead of em dash": note("7", PUBLISHED_ROOT_B64, SHORT_SIG.replace("—", "-")),
            "extra signature field": note("7", PUBLISHED_ROOT_B64, SHORT_SIG + " x"),
            "no signature lines": note("7", PUBLISHED_ROOT_B64),
            "4-byte signature": note("7", PUBLISHED_ROOT_B64, sig_line(bytes.fromhex(REKOR_HINT))),
            "not a string": None,
        }
        js = node({"op": "parse", "texts": list(texts.values())})
        for (name, text), js_result in zip(texts.items(), js):
            with self.subTest(name=name):
                self.assertEqual(py_parse(text), {k: v for k, v in js_result.items() if k != "reason"})
        accepted = [name for (name, _), r in zip(texts.items(), js) if r["ok"]]
        self.assertEqual(accepted, ["published", "leading zeros", "largest safe size", "two signatures"])

    def test_python_is_stricter_on_non_canonical_signature_base64(self):
        texts = [
            note("7", PUBLISHED_ROOT_B64, SHORT_SIG.rstrip("=")),
            note("7", PUBLISHED_ROOT_B64, SHORT_SIG.replace("+", "-").replace("/", "_") + "-_"),
        ]
        self.assertEqual([r["ok"] for r in node({"op": "parse", "texts": texts})], [True, True])
        self.assertEqual([py_parse(t)["ok"] for t in texts], [False, False])

    def test_checkpoint_signature_outcomes_match_js(self):
        other_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        edited = PUBLISHED_NOTE.replace(str(LIVE_SIZE), str(LIVE_SIZE + 1), 1)
        for pem, texts, want in [
            (REKOR_PEM, [PUBLISHED_NOTE, edited], [True, False]),
            (other_pem, [PUBLISHED_NOTE], [False]),
        ]:
            key = vo.load_rekor_pin(pem)
            python = []
            for text in texts:
                try:
                    vo.verify_checkpoint(text, key)
                    python.append(True)
                except vo.ObservationError:
                    python.append(False)
            self.assertEqual(node({"op": "verifyCheckpoint", "texts": texts, "pem": pem.decode()}), want)
            self.assertEqual(python, want)

    def test_consistency_outcomes_match_js(self):
        cases = []
        for n in range(1, 21):
            for m in range(1, n + 1):
                case = consistency_case(m, n)
                cases.append(case)
                if case["proofHex"]:
                    flipped = copy.deepcopy(case)
                    i = (m * n) % len(case["proofHex"])
                    flipped["proofHex"][i] = flip(flipped["proofHex"][i])
                    cases.append(flipped)
                    cases.append(dict(case, proofHex=case["proofHex"][:-1]))
                cases.append(dict(case, secondRootHex=flip(case["secondRootHex"])))
        upper = consistency_case(6, 13)
        upper = dict(upper, proofHex=[h.upper() for h in upper["proofHex"]])
        spaced = consistency_case(6, 13)
        spaced["proofHex"][0] = " ".join(spaced["proofHex"][0][i : i + 2] for i in range(0, 64, 2))
        cases += [upper, spaced]
        js = node({"op": "consistency", "cases": cases})
        self.assertEqual(disagreements(cases, js), [])
        self.assertEqual((js.count(True), js[-2:]), (211, [True, False]))

    def test_proofs_presented_under_another_new_size_match_js(self):
        # The proof alone does not bind the new size, so some of these verify in
        # both languages; the signed live checkpoint is what binds it.
        cases = []
        for proved in range(2, 21):
            for m in range(1, proved):
                case = consistency_case(m, proved)
                cases += [dict(case, secondSize=n) for n in range(m + 1, 21) if n != proved]
        cases += padded_cases()
        js = node({"op": "consistency", "cases": cases})
        self.assertEqual(disagreements(cases, js), [])
        self.assertEqual(js[-3:], [False, False, False])

    def test_python_is_stricter_on_an_odd_trailing_hex_digit(self):
        case = consistency_case(6, 13)
        case["proofHex"][0] += "a"
        self.assertEqual(node({"op": "consistency", "cases": [case]}), [True])
        self.assertFalse(py_consistency(case))


@unittest.skipUnless(NODE, "node is required for the cross-language tests")
class SignedButWrongVerdictTests(unittest.TestCase):
    """An observer-signed observation whose verdict its log evidence contradicts."""

    def setUp(self):
        statement = fixture_statement()
        statement["predicate"]["summary"]["verdict"] = "ROOTS_EQUAL"
        signed = node({"op": "sign", "statement": statement})
        self.envelope = signed["envelope"]
        self.pin = {
            "kind": vo.OBSERVER_PIN_KIND,
            "v": 1,
            "alg": "ed25519",
            "keyId": signed["keyId"],
            "publicKeySpkiBase64": signed["spki"],
        }

    def test_signature_only_check_accepts_it(self):
        self.assertEqual(vo.verify_observation(self.envelope, self.pin)["verdict"], "ROOTS_EQUAL")

    def test_replay_refuses_it(self):
        with self.assertRaisesRegex(vo.ObservationError, "recorded verdict ROOTS_EQUAL but replay gives PREFIX_OK"):
            vo.verify_observation(self.envelope, self.pin, REKOR_PEM)

    def test_cli_replays_by_default_and_no_replay_skips_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs = Path(tmp) / "obs_tampered.observation.json"
            pin = Path(tmp) / "observer_pubkey.json"
            obs.write_text(json.dumps(self.envelope), encoding="utf-8")
            pin.write_text(json.dumps(self.pin), encoding="utf-8")
            for extra, want_code, want_out in [
                ([], 1, f"FAIL recorded verdict ROOTS_EQUAL but replay gives PREFIX_OK {obs.name}"),
                (["--no-replay"], 0, f"OK ROOTS_EQUAL {obs.name}"),
            ]:
                with self.subTest(args=extra):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = vo.main([str(obs), "--pin", str(pin), *extra])
                    self.assertEqual((code, out.getvalue().strip()), (want_code, want_out))


if __name__ == "__main__":
    unittest.main()
