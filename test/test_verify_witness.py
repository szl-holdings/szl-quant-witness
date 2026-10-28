"""Tests for verify_witness.py, the Python engine-witness verifier (stdlib unittest).

Run from the repo root:
    python -m unittest discover -s test -p "test_*.py" -v

Merkle tests use an independent RFC 6962 reference (MTH and PATH, section
2.1.1) and need no network. Fixtures witness_*.receipt.json are byte copies
of published engine witness receipts on the szl-quant `ledger` branch at
commit 7e5ed33598487da81c1aad454e0b1f9d7d383b5d (git blob ids pinned below).
The cross-language tests run the vendored JS (engine-witness.mjs,
vendor/szl-quant/witness.mjs) on the same inputs and need node.
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

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import verify_observation as vo  # noqa: E402
import verify_witness as vw  # noqa: E402

NODE = shutil.which("node")
FIXTURES = REPO / "test" / "fixtures"
FIXTURE_BLOBS = {
    "witness_0001_1784228300881.receipt.json": "6acc056fdac656eb7c72890dbafa5a780e87f6cb",
    "witness_0009_1784226998334.receipt.json": "dddc2084885f5a2f979cae74837270ba2124d762",
    "witness_0009_1784228302184.receipt.json": "9a563d8a479ae0b8b261f560013d54aa691634dc",
    "witness_0425_1793212259840.receipt.json": "82ca764065eed7e23086a9186e82438485468934",
}
SET_ONLY_FIXTURE = "witness_0009_1784226998334.receipt.json"
NEWEST_FIXTURE = "witness_0425_1793212259840.receipt.json"
ENGINE_PIN = REPO / "keys" / "engine_pubkey.json"
OBSERVER_PIN = REPO / "keys" / "observer_pubkey.json"
REKOR_PIN = REPO / "keys" / "rekor_pubkey.pem"


def _real_crypto():
    try:
        import cryptography
    except ImportError:
        return False
    return getattr(cryptography, "__version__", None) is not None


def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _mth(leaves):
    n = len(leaves)
    if n == 1:
        return _leaf(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _path(m, leaves):
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


LEAVES = [b"leaf-%d" % i for i in range(40)]
SIZES = range(1, 41)


def path(m, n):
    return [h.hex() for h in _path(m, LEAVES[:n])]


def flip(hex_str, i=0):
    raw = bytearray(bytes.fromhex(hex_str))
    raw[i] ^= 0x01
    return raw.hex()


def walk(*args):
    try:
        return vw.rfc6962_root(*args).hex()
    except vo.ObservationError as exc:
        return exc


def load_fixture(name):
    envelope = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"]))
    return envelope, statement["predicate"]["summary"]


class InclusionWalkTests(unittest.TestCase):
    def test_every_valid_path_up_to_40_lands_on_the_root(self):
        checked = 0
        for n in SIZES:
            root = _mth(LEAVES[:n]).hex()
            for m in range(n):
                self.assertEqual(walk(m, n, _leaf(LEAVES[m]), path(m, n)), root, (m, n))
                checked += 1
        self.assertEqual(checked, 820)

    def test_every_mutated_path_is_rejected_or_misses_the_root(self):
        for n in SIZES:
            root = _mth(LEAVES[:n]).hex()
            for m in range(n):
                good = path(m, n)
                leaf = _leaf(LEAVES[m])
                with self.subTest(m=m, n=n):
                    if good:
                        self.assertRegex(str(walk(m, n, leaf, good[:-1])), "audit path too short")
                    self.assertRegex(str(walk(m, n, leaf, good + ["00" * 32])), "1 unconsumed sibling")
                    for i in range(len(good)):
                        bad = good[:i] + [flip(good[i])] + good[i + 1 :]
                        self.assertNotEqual(walk(m, n, leaf, bad), root)
                    self.assertNotEqual(walk(m, n, _leaf(b"other"), good), root)
                    if m ^ 1 < n:
                        self.assertNotEqual(walk(m ^ 1, n, leaf, good), root)
                    self.assertRegex(str(walk(n, n, leaf, good)), "outside tree of size")

    def test_bad_indexes_sizes_and_siblings_are_rejected(self):
        leaf = _leaf(b"x")
        two = path(0, 2)
        for index, size in [(-1, 1), (0, 0), (1, 1), (True, 2), (0, True), (0.5, 2), (0, 2.5), ("0", 1), (None, 1), (2**53, 2**53 + 1)]:
            with self.subTest(index=index, size=size):
                self.assertRegex(str(walk(index, size, leaf, two)), "outside tree of size")
        self.assertRegex(str(walk(0, 2, leaf, "ab" * 32)), "audit path is not a list")
        for sibling in ["ab" * 31, "ab" * 33, "zz" * 32, "ab" * 32 + " ", "ab" * 32 + "zz", None, 123]:
            with self.subTest(sibling=sibling):
                self.assertRegex(str(walk(0, 2, leaf, [sibling])), "sibling hash is not 32 bytes")

    def test_integral_floats_and_uppercase_hex_are_accepted_like_js(self):
        root = _mth(LEAVES[:2]).hex()
        self.assertEqual(walk(1.0, 2.0, _leaf(LEAVES[1]), [p.upper() for p in path(1, 2)]), root)
        self.assertEqual(walk(0, 1, _leaf(LEAVES[0]), None), _leaf(LEAVES[0]).hex())


class FilenameBindingTests(unittest.TestCase):
    def test_binding_accepts_the_matching_sequence(self):
        self.assertEqual(vw.assert_witness_filename_binding("witness_0013_1784233307672.receipt.json", {"chain": {"seq": 13}}), 13)
        self.assertEqual(vw.assert_witness_filename_binding("witness_0000_1.receipt.json", {"chain": {"seq": 0.0}}), 0)

    def test_binding_refusals(self):
        cases = {
            "drift": ("witness_9999_1784233307672.receipt.json", 13, "does not match signed chain sequence"),
            "five digits": ("witness_10000_1.receipt.json", 10000, "invalid witness filename"),
            "three digits": ("witness_013_1.receipt.json", 13, "invalid witness filename"),
            "arabic-indic digits": ("witness_٠٠١٣_1.receipt.json", 13, "invalid witness filename"),
            "trailing newline": ("witness_0013_1.receipt.json\n", 13, "invalid witness filename"),
            "path prefix": ("witness/witness_0013_1.receipt.json", 13, "invalid witness filename"),
            "bool seq": ("witness_0001_1.receipt.json", True, "does not match signed chain sequence"),
            "string seq": ("witness_0013_1.receipt.json", "13", "does not match signed chain sequence"),
            "missing seq": ("witness_0013_1.receipt.json", None, "does not match signed chain sequence"),
            "not a string": (None, 13, "invalid witness filename"),
        }
        for label, (name, seq, message) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(vo.ObservationError, message):
                    vw.assert_witness_filename_binding(name, {"chain": {"seq": seq}})


def witness_statement(seq=13, **overrides):
    statement = {
        "_type": vo.IN_TOTO_STATEMENT,
        "subject": [{"name": "fixture", "digest": {"sha256": "0" * 64}}],
        "predicateType": vw.WITNESS_PREDICATE,
        "predicate": {"summary": {"kind": vw.WITNESS_KIND, "chain": {"seq": seq}}},
    }
    statement.update(overrides)
    return statement


def python_signed(statement, signer=None, keyid=None):
    """Sign like dsse.mjs signEnvelope, embedding the signer's own key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signer = signer or Ed25519PrivateKey.generate()
    public = signer.public_key()
    payload = json.dumps(statement).encode("utf-8")
    pin = {
        "kind": vw.ENGINE_PIN_KIND,
        "v": 1,
        "alg": "ed25519",
        "keyId": vo.key_id(public),
        "publicKeySpkiBase64": base64.b64encode(vo.spki_der(public)).decode(),
    }
    envelope = {
        "payloadType": vo.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid or pin["keyId"], "sig": base64.b64encode(signer.sign(vo.pae(vo.PAYLOAD_TYPE, payload))).decode()}],
        "publicKeySpkiBase64": pin["publicKeySpkiBase64"],
    }
    return envelope, pin


class SkipGuards(unittest.TestCase):
    def test_signature_tests_cannot_skip_in_ci(self):
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertTrue(_real_crypto(), "cryptography must be installed in CI")

    def test_parity_tests_cannot_skip_in_ci(self):
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertIsNotNone(NODE, "node must be installed in CI")


@unittest.skipUnless(_real_crypto(), "cryptography not installed")
class EngineWitnessSignatureTests(unittest.TestCase):
    """Twins of test/engine-witness.test.mjs, plus pin and statement refusals."""

    def test_accepts_a_witness_signed_by_the_pinned_engine_key(self):
        envelope, pin = python_signed(witness_statement(13))
        verified = vw.verify_engine_witness(envelope, pin)
        self.assertEqual((verified["seq"], verified["engine_key_id"], verified["anchor"]), (13, pin["keyId"], None))
        self.assertEqual(vw.assert_witness_filename_binding("witness_0013_1784233307672.receipt.json", verified["summary"]), 13)

    def test_rejects_payload_tampering_after_signing(self):
        envelope, pin = python_signed(witness_statement(13))
        envelope["payload"] = base64.b64encode(json.dumps(witness_statement(14)).encode()).decode()
        with self.assertRaisesRegex(vo.ObservationError, "signature verification failed: signature invalid"):
            vw.verify_engine_witness(envelope, pin)

    def test_rejects_a_witness_signed_by_another_key(self):
        _, trusted_pin = python_signed(witness_statement(13))
        attacker_envelope, _ = python_signed(witness_statement(13))
        with self.assertRaisesRegex(vo.ObservationError, "signature verification failed: no signature for keyid"):
            vw.verify_engine_witness(attacker_envelope, trusted_pin)

    def test_embedded_key_is_never_trusted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        _, trusted_pin = python_signed(witness_statement(13))
        forged, _ = python_signed(witness_statement(13), Ed25519PrivateKey.generate(), keyid=trusted_pin["keyId"])
        self.assertNotEqual(forged["publicKeySpkiBase64"], trusted_pin["publicKeySpkiBase64"])
        with self.assertRaisesRegex(vo.ObservationError, "signature verification failed: signature invalid"):
            vw.verify_engine_witness(forged, trusted_pin)

    def test_repository_engine_pin_is_valid_and_refuses_an_unsigned_envelope(self):
        pin = json.loads(ENGINE_PIN.read_text(encoding="utf-8"))
        self.assertEqual(vo.key_id(vw.load_engine_pin(pin)), "5c6cf59741ade920")
        fake = {"payloadType": vo.PAYLOAD_TYPE, "payload": "", "signatures": []}
        with self.assertRaisesRegex(vo.ObservationError, "engine witness signature verification failed: no signatures"):
            vw.verify_engine_witness(fake, pin)

    def test_bad_pins_are_refused(self):
        _, pin = python_signed(witness_statement())
        _, other = python_signed(witness_statement())
        ec_spki = base64.b64encode(vo.spki_der(vo.load_rekor_pin(REKOR_PIN.read_bytes()))).decode()
        cases = {
            "observer kind": ({"kind": vo.OBSERVER_PIN_KIND}, "pin metadata"),
            "v true": ({"v": True}, "pin metadata"),
            "v 2": ({"v": 2}, "pin metadata"),
            "alg": ({"alg": "ecdsa"}, "pin metadata"),
            "uppercase keyId": ({"keyId": pin["keyId"].upper()}, "pin keyId"),
            "short keyId": ({"keyId": pin["keyId"][:15]}, "pin keyId"),
            "no key bytes": ({"publicKeySpkiBase64": ""}, "missing engine public-key pin bytes"),
            "other key": ({"publicKeySpkiBase64": other["publicKeySpkiBase64"]}, "pin keyId mismatch"),
            "ecdsa key": ({"publicKeySpkiBase64": ec_spki}, "pin unreadable"),
        }
        for label, (change, message) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(vo.ObservationError, message):
                    vw.load_engine_pin({**pin, **change})
        with self.assertRaisesRegex(vo.ObservationError, "pin metadata"):
            vw.load_engine_pin(None)

    def test_statement_refusals(self):
        bad = {
            "not in-toto": (witness_statement(_type="https://in-toto.io/Statement/v0.1"), "not an in-toto Statement/v1"),
            "predicateType": (witness_statement(predicateType="https://szl.holdings/quant/gossip-observation/v1"), "unexpected predicateType"),
            "kind": (witness_statement(predicate={"summary": {"kind": "szl-quant-gossip-observation", "chain": {"seq": 1}}}), "unexpected witness receipt kind"),
            "no summary": (witness_statement(predicate=[]), "unexpected witness receipt kind: None"),
            "no chain": (witness_statement(predicate={"summary": {"kind": vw.WITNESS_KIND}}), "chain sequence is invalid"),
        }
        for seq in [-1, True, 1.5, "13", None, 2**53]:
            bad[f"seq {seq!r}"] = (witness_statement(seq), "chain sequence is invalid")
        for label, (statement, message) in bad.items():
            with self.subTest(label):
                envelope, pin = python_signed(statement)
                with self.assertRaisesRegex(vo.ObservationError, message):
                    vw.verify_engine_witness(envelope, pin)
        for seq in [0, 9999, 2**53 - 1]:
            envelope, pin = python_signed(witness_statement(seq))
            self.assertEqual(vw.verify_engine_witness(envelope, pin)["seq"], seq)


@unittest.skipUnless(_real_crypto(), "cryptography not installed")
class PublishedReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads(ENGINE_PIN.read_text(encoding="utf-8"))
        cls.engine_key = vw.load_engine_pin(cls.pin)
        cls.rekor_pem = REKOR_PIN.read_bytes()
        cls.log_key = vo.load_rekor_pin(cls.rekor_pem)

    def test_fixtures_are_pinned_byte_copies(self):
        for name, blob in FIXTURE_BLOBS.items():
            data = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), blob, name)

    def test_every_fixture_verifies_end_to_end_with_replay(self):
        for name in sorted(FIXTURE_BLOBS):
            with self.subTest(name):
                envelope, _ = load_fixture(name)
                verified = vw.verify_engine_witness(envelope, self.pin, self.rekor_pem)
                self.assertEqual(vw.assert_witness_filename_binding(name, verified["summary"]), verified["seq"])
                self.assertEqual(verified["anchor"], "SET_ONLY" if name == SET_ONLY_FIXTURE else "INCLUSION")
                self.assertIsNone(vw.verify_engine_witness(envelope, self.pin)["anchor"])

    def test_cli_replays_by_default_and_no_replay_checks_signatures_only(self):
        files = [str(FIXTURES / name) for name in sorted(FIXTURE_BLOBS)]
        for argv, word in ([files, None], [["--no-replay", *files], "SIGNATURE"]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(vw.main(argv), 0)
            expected = [
                f"OK {word or ('SET_ONLY' if name == SET_ONLY_FIXTURE else 'INCLUSION')} {name}"
                for name in sorted(FIXTURE_BLOBS)
            ]
            self.assertEqual(out.getvalue().splitlines(), expected)

    def test_cli_refuses_bad_pins_and_renamed_receipts(self):
        newest = str(FIXTURES / NEWEST_FIXTURE)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(vw.main(["--pin", str(OBSERVER_PIN), newest]), 2)
            self.assertEqual(vw.main(["--rekor-pin", str(ENGINE_PIN), newest]), 2)
        self.assertEqual(err.getvalue().count("PIN-ERROR"), 2)
        with tempfile.TemporaryDirectory() as tmp:
            renamed = Path(tmp) / "witness_0424_1793212259840.receipt.json"
            shutil.copyfile(newest, renamed)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(vw.main([newest, str(renamed)]), 1)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], f"OK INCLUSION {NEWEST_FIXTURE}")
        self.assertRegex(lines[1], r"^FAIL witness filename sequence 424 does not match signed chain sequence 425 ")

    def anchor(self, mutate, name=NEWEST_FIXTURE, log_key=None):
        _, summary = load_fixture(name)
        summary = copy.deepcopy(summary)
        mutate(summary["rekor"], summary)
        return vw.check_anchor(summary, self.engine_key, log_key or self.log_key)

    def test_untouched_anchor_replays(self):
        self.assertEqual(self.anchor(lambda r, s: None), "INCLUSION")
        self.assertEqual(self.anchor(lambda r, s: None, SET_ONLY_FIXTURE), "SET_ONLY")

    def test_every_anchor_mutant_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        def entry(rekor, edit):
            body = json.loads(base64.b64decode(rekor["entryBodyBase64"]))
            edit(body)
            rekor["entryBodyBase64"] = base64.b64encode(json.dumps(body).encode()).decode()

        other_pem = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        def set_key(body):
            body["spec"]["signature"]["publicKey"]["content"] = base64.b64encode(other_pem).decode()

        def set_attr(field, value):
            return lambda r, s: r.__setitem__(field, value(r))

        def proof_attr(field, value):
            return lambda r, s: r["inclusionProof"].__setitem__(field, value(r["inclusionProof"]))

        mutants = {
            "chain head changed": (lambda r, s: s["chain"].__setitem__("sha256", flip(s["chain"]["sha256"])), "does not anchor this chain head"),
            "chain head uppercase": (lambda r, s: s["chain"].__setitem__("sha256", s["chain"]["sha256"].upper()), "not 64 lowercase hex"),
            "entry signed by another key": (lambda r, s: entry(r, set_key), "not signed by the pinned engine key"),
            "entry is hashedrekord": (lambda r, s: entry(r, lambda b: b.__setitem__("kind", "hashedrekord")), "not a sha256 rekord entry"),
            "entry not base64": (set_attr("entryBodyBase64", lambda r: r["entryBodyBase64"] + "!"), "not base64 JSON"),
            "logID changed": (set_attr("logID", lambda r: flip(r["logID"])), "is not the pinned log key's id"),
            "integratedTime + 1": (set_attr("integratedTime", lambda r: r["integratedTime"] + 1), "SET signature invalid"),
            "logIndex + 1": (set_attr("logIndex", lambda r: r["logIndex"] + 1), "SET signature invalid"),
            "SET byte flipped": (set_attr("signedEntryTimestampBase64", lambda r: base64.b64encode(bytes([base64.b64decode(r["signedEntryTimestampBase64"])[0] ^ 1]) + base64.b64decode(r["signedEntryTimestampBase64"])[1:]).decode()), "SET signature invalid"),
            "SET missing": (lambda r, s: r.pop("signedEntryTimestampBase64"), "SET signature invalid"),
            "integratedTime bool": (set_attr("integratedTime", lambda r: True), "SET fields are malformed"),
            "proof leaf index + 1": (proof_attr("logIndex", lambda p: p["logIndex"] + 1), "does not land on the signed root"),
            "proof path short": (proof_attr("hashes", lambda p: p["hashes"][:-1]), "audit path too short"),
            "proof path long": (proof_attr("hashes", lambda p: p["hashes"] + [p["hashes"][0]]), "1 unconsumed sibling"),
            "proof sibling flipped": (proof_attr("hashes", lambda p: [flip(p["hashes"][0])] + p["hashes"][1:]), "does not land on the signed root"),
            "proof root changed": (proof_attr("rootHash", lambda p: flip(p["rootHash"])), "root hash mismatch"),
            "proof root uppercase": (proof_attr("rootHash", lambda p: p["rootHash"].upper()), "root hash mismatch"),
            "proof size + 1": (proof_attr("treeSize", lambda p: p["treeSize"] + 1), "tree size mismatch"),
            "checkpoint edited": (proof_attr("checkpoint", lambda p: p["checkpoint"].replace(str(p["treeSize"]), str(p["treeSize"] + 1), 1)), "checkpoint signature invalid"),
            "proof null": (set_attr("inclusionProof", lambda r: None), "inclusion proof missing required fields"),
            "proof index bool": (proof_attr("logIndex", lambda p: True), "inclusion proof missing required fields"),
        }
        for label, (mutate, message) in mutants.items():
            with self.subTest(label):
                with self.assertRaisesRegex(vo.ObservationError, message):
                    self.anchor(mutate)
        other_log = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaisesRegex(vo.ObservationError, "is not the pinned log key's id"):
            self.anchor(lambda r, s: None, log_key=other_log)


NODE_HELPER = r"""
import { readFileSync } from 'node:fs';
import { signEnvelope } from './vendor/szl-quant/dsse.mjs';
import { generateEngineKeypair, keyIdFromPublicKey, publicKeySpkiBase64 } from './vendor/szl-quant/keys.mjs';
import { assertWitnessFilenameBinding, verifyEngineWitnessEnvelope } from './engine-witness.mjs';
import { rfc6962Root, verifyInclusionProof } from './vendor/szl-quant/witness.mjs';
const req = JSON.parse(readFileSync(0, 'utf8'));
const attempt = (f) => { try { return { ok: true, value: f() }; } catch (e) { return { ok: false, reason: e.message }; } };
let out;
if (req.op === 'sign') {
  const { privateKey, publicKey } = generateEngineKeypair();
  out = {
    envelopes: req.statements.map((s) => signEnvelope(s, privateKey, publicKey)),
    pin: { kind: 'szl-quant-engine-pubkey', v: 1, alg: 'ed25519', keyId: keyIdFromPublicKey(publicKey), publicKeySpkiBase64: publicKeySpkiBase64(publicKey) },
  };
} else if (req.op === 'verify') {
  out = req.envelopes.map((e) => attempt(() => verifyEngineWitnessEnvelope(e, req.pin).summary.chain.seq));
} else if (req.op === 'bind') {
  out = req.cases.map(([name, summary]) => attempt(() => assertWitnessFilenameBinding(name, summary)));
} else if (req.op === 'root') {
  out = req.cases.map((c) => attempt(() => rfc6962Root({ leafIndex: c.leafIndex, treeSize: c.treeSize, leafHash: Buffer.from(c.leafHex, 'hex'), pathHex: c.pathHex }).toString('hex')));
} else if (req.op === 'inclusion') {
  const pem = readFileSync('keys/rekor_pubkey.pem', 'utf8');
  out = req.cases.map((c) => verifyInclusionProof({ entryBodyBase64: c.entryBodyBase64, proof: c.proof, logPublicKeyPem: pem }));
} else {
  throw new Error('unknown op ' + req.op);
}
process.stdout.write(JSON.stringify(out));
"""


def node(req):
    proc = subprocess.run(
        [NODE, "--input-type=module", "-e", NODE_HELPER],
        input=json.dumps(req),
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=REPO,
        check=True,
    )
    return json.loads(proc.stdout)


def py_attempt(fn):
    try:
        return {"ok": True, "value": fn()}
    except vo.ObservationError as exc:
        return {"ok": False, "reason": str(exc)}


@unittest.skipUnless(NODE, "node is required for the cross-language tests")
@unittest.skipUnless(_real_crypto(), "cryptography not installed")
class CrossLanguageWitnessTests(unittest.TestCase):
    def test_js_signed_receipts_and_statement_outcomes_match_python(self):
        statements = {
            "seq 0": witness_statement(0),
            "seq 13": witness_statement(13),
            "largest safe seq": witness_statement(2**53 - 1),
            "seq above 2^53": witness_statement(2**53),
            "negative seq": witness_statement(-1),
            "bool seq": witness_statement(True),
            "fractional seq": witness_statement(1.5),
            "string seq": witness_statement("13"),
            "no chain": witness_statement(predicate={"summary": {"kind": vw.WITNESS_KIND}}),
            "wrong kind": witness_statement(predicate={"summary": {"kind": "x", "chain": {"seq": 1}}}),
            "not in-toto": witness_statement(_type="x"),
        }
        signed = node({"op": "sign", "statements": list(statements.values())})
        js = node({"op": "verify", "envelopes": signed["envelopes"], "pin": signed["pin"]})
        for (label, _), envelope, js_result in zip(statements.items(), signed["envelopes"], js):
            with self.subTest(label):
                py = py_attempt(lambda: vw.verify_engine_witness(envelope, signed["pin"])["seq"])
                self.assertEqual(py["ok"], js_result["ok"])
                if js_result["ok"]:
                    self.assertEqual(py["value"], js_result["value"])
        accepted = [label for (label, _), r in zip(statements.items(), js) if r["ok"]]
        self.assertEqual(accepted, ["seq 0", "seq 13", "largest safe seq"])

    def test_python_also_requires_the_witness_predicate_type(self):
        statement = witness_statement(13, predicateType="https://example.invalid/other")
        signed = node({"op": "sign", "statements": [statement]})
        js = node({"op": "verify", "envelopes": signed["envelopes"], "pin": signed["pin"]})
        self.assertEqual(js, [{"ok": True, "value": 13}])
        with self.assertRaisesRegex(vo.ObservationError, "unexpected predicateType"):
            vw.verify_engine_witness(signed["envelopes"][0], signed["pin"])

    def test_filename_binding_matches_js(self):
        cases = [
            ("witness_0013_1784233307672.receipt.json", {"chain": {"seq": 13}}),
            ("witness_9999_1784233307672.receipt.json", {"chain": {"seq": 13}}),
            ("witness_0000_1.receipt.json", {"chain": {"seq": 0}}),
            ("witness_10000_1.receipt.json", {"chain": {"seq": 10000}}),
            ("witness_٠٠١٣_1.receipt.json", {"chain": {"seq": 13}}),
            ("witness_0013_1.receipt.json\n", {"chain": {"seq": 13}}),
            ("witness_0001_1.receipt.json", {"chain": {"seq": True}}),
            ("witness_0013_1.receipt.json", {"chain": {"seq": "13"}}),
            ("witness_0013_1.receipt.json", {}),
        ]
        js = node({"op": "bind", "cases": cases})
        for (name, summary), js_result in zip(cases, js):
            with self.subTest(name=name, summary=summary):
                py = py_attempt(lambda: vw.assert_witness_filename_binding(name, summary))
                self.assertEqual(py["ok"], js_result["ok"])
                if js_result["ok"]:
                    self.assertEqual(py["value"], js_result["value"])
        self.assertEqual([r["ok"] for r in js], [True, False, True, False, False, False, False, False, False])

    def test_audit_path_walk_matches_js(self):
        cases = []
        for n in (1, 2, 3, 5, 7, 8, 13, 16, 31, 40):
            for m in sorted({0, n // 2, n - 1}):
                good = path(m, n)
                leaf_hex = _leaf(LEAVES[m]).hex()
                cases.append({"leafIndex": m, "treeSize": n, "leafHex": leaf_hex, "pathHex": good})
                cases.append({"leafIndex": m, "treeSize": n, "leafHex": leaf_hex, "pathHex": good + ["00" * 32]})
                cases.append({"leafIndex": n, "treeSize": n, "leafHex": leaf_hex, "pathHex": good})
                if good:
                    cases.append({"leafIndex": m, "treeSize": n, "leafHex": leaf_hex, "pathHex": good[:-1]})
                    cases.append({"leafIndex": m, "treeSize": n, "leafHex": leaf_hex, "pathHex": [flip(good[0])] + good[1:]})
                    cases.append({"leafIndex": m, "treeSize": n, "leafHex": leaf_hex, "pathHex": [good[0][:62]] + good[1:]})
        for index, size in [(-1, 4), (0, 0), (1.5, 4)]:
            cases.append({"leafIndex": index, "treeSize": size, "leafHex": "00" * 32, "pathHex": path(0, 4)})
        js = node({"op": "root", "cases": cases})
        for case, js_result in zip(cases, js):
            with self.subTest(case=case):
                py = walk(case["leafIndex"], case["treeSize"], bytes.fromhex(case["leafHex"]), case["pathHex"])
                if js_result["ok"]:
                    self.assertEqual(py, js_result["value"])
                else:
                    self.assertIsInstance(py, vo.ObservationError)
                    self.assertEqual(str(py), js_result["reason"])

    def test_python_is_stricter_on_sibling_hex(self):
        leaf_hex = _leaf(LEAVES[0]).hex()
        sloppy = [path(0, 2)[0] + "zz"]
        js = node({"op": "root", "cases": [{"leafIndex": 0, "treeSize": 2, "leafHex": leaf_hex, "pathHex": sloppy}]})
        self.assertEqual(js, [{"ok": True, "value": _mth(LEAVES[:2]).hex()}])
        self.assertRegex(str(walk(0, 2, bytes.fromhex(leaf_hex), sloppy)), "sibling hash is not 32 bytes")

    def test_inclusion_outcomes_match_js_on_published_receipts(self):
        log_key = vo.load_rekor_pin(REKOR_PIN.read_bytes())
        mutations = {
            "published": lambda p: None,
            "size + 1": lambda p: p.__setitem__("treeSize", p["treeSize"] + 1),
            "root changed": lambda p: p.__setitem__("rootHash", flip(p["rootHash"])),
            "path short": lambda p: p.__setitem__("hashes", p["hashes"][:-1]),
            "path long": lambda p: p.__setitem__("hashes", p["hashes"] + [p["hashes"][0]]),
            "leaf index + 1": lambda p: p.__setitem__("logIndex", p["logIndex"] + 1),
            "sibling flipped": lambda p: p.__setitem__("hashes", [flip(p["hashes"][0])] + p["hashes"][1:]),
            "checkpoint edited": lambda p: p.__setitem__("checkpoint", p["checkpoint"].replace(str(p["treeSize"]), str(p["treeSize"] + 1), 1)),
            "index as string": lambda p: p.__setitem__("logIndex", str(p["logIndex"])),
        }
        cases, labels = [], []
        for name in sorted(FIXTURE_BLOBS):
            if name == SET_ONLY_FIXTURE:
                continue
            _, summary = load_fixture(name)
            for label, mutate in mutations.items():
                proof = copy.deepcopy(summary["rekor"]["inclusionProof"])
                mutate(proof)
                cases.append({"entryBodyBase64": summary["rekor"]["entryBodyBase64"], "proof": proof})
                labels.append((name, label))
        js = node({"op": "inclusion", "cases": cases})
        for (name, label), case, js_result in zip(labels, cases, js):
            with self.subTest(name=name, mutation=label):
                py = py_attempt(lambda: vw.verify_inclusion_proof(case["entryBodyBase64"], case["proof"], log_key))
                self.assertEqual(py["ok"], js_result["ok"], js_result.get("reason"))
                self.assertEqual(py["ok"], label == "published")


if __name__ == "__main__":
    unittest.main()
