"""Tests for verify_observation.py (stdlib unittest).

Run from the repo root:
    python -m unittest discover -s test -p "test_*.py" -v

The cross-language tests sign envelopes with the vendored JS primitives
(node + vendor/szl-quant), so a pass means the Python verifier accepts
exactly what the JS signs and refuses what the JS refuses.

test/fixtures/obs_0422_1793154252851.observation.json is a byte copy of the
published observation on the observations branch at commit
12ca3050922cabc8e78f89e20de84c72f676c326 (sha256 pinned below).
"""
import base64
import contextlib
import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import verify_observation as vo  # noqa: E402

NODE = shutil.which("node")
FIXTURE = REPO / "test" / "fixtures" / "obs_0422_1793154252851.observation.json"
FIXTURE_SHA256 = "0cfaad6e730f39e27304fdfbb274251419499ea918914d5a1fb125b8996a7a48"
REPO_PIN = REPO / "keys" / "observer_pubkey.json"

NODE_HELPER = r"""
import { readFileSync } from 'node:fs';
import { signEnvelope, verifyEnvelope, pae, PAYLOAD_TYPE } from './vendor/szl-quant/dsse.mjs';
import { generateEngineKeypair, keyIdFromPublicKey, publicKeySpkiBase64, loadPublicKeyFromSpkiBase64 } from './vendor/szl-quant/keys.mjs';
const req = JSON.parse(readFileSync(0, 'utf8'));
let out;
if (req.op === 'sign') {
  const { privateKey, publicKey } = generateEngineKeypair();
  const keyId = keyIdFromPublicKey(publicKey);
  if (req.bindObserverKeyId) req.statement.predicate.summary.observer.keyId = keyId;
  out = { envelope: signEnvelope(req.statement, privateKey, publicKey), keyId, spki: publicKeySpkiBase64(publicKey) };
} else if (req.op === 'pae') {
  out = { pae: pae(PAYLOAD_TYPE, Buffer.from(req.payload, 'base64')).toString('base64') };
} else if (req.op === 'verify') {
  const r = verifyEnvelope(req.envelope, loadPublicKeyFromSpkiBase64(req.spki));
  out = { ok: r.ok, reason: r.reason ?? null };
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
        timeout=60,
    )
    return json.loads(proc.stdout)


def statement(verdict="PREFIX_OK", observer_key_id="0" * 16):
    return {
        "_type": vo.IN_TOTO_STATEMENT,
        "subject": [
            {"name": "szl-quant-witness/observation-seq-422", "digest": {"sha256": "0" * 64}}
        ],
        "predicateType": vo.OBSERVATION_PREDICATE,
        "predicate": {
            "summary": {
                "kind": vo.OBSERVATION_KIND,
                "verdict": verdict,
                "observer": {"keyId": observer_key_id},
                "note": "test fixture — not a real observation",
            }
        },
    }


def js_signed(verdict="PREFIX_OK", bind_observer=True):
    signed = node(
        {"op": "sign", "statement": statement(verdict), "bindObserverKeyId": bind_observer}
    )
    pin = {
        "kind": vo.OBSERVER_PIN_KIND,
        "v": 1,
        "alg": "ed25519",
        "keyId": signed["keyId"],
        "publicKeySpkiBase64": signed["spki"],
    }
    return signed["envelope"], pin


@unittest.skipUnless(NODE, "node is required for the cross-language tests")
class CrossLanguageTests(unittest.TestCase):
    def test_pae_bytes_match_js(self):
        payload = '{"note":"café — ✓","n":422}'.encode("utf-8")
        js = base64.b64decode(node({"op": "pae", "payload": base64.b64encode(payload).decode()})["pae"])
        self.assertEqual(vo.pae(vo.PAYLOAD_TYPE, payload), js)

    def test_accepts_js_signed_observation_with_pinned_key(self):
        envelope, pin = js_signed()
        verified = vo.verify_observation(envelope, pin)
        self.assertEqual(verified["verdict"], "PREFIX_OK")
        self.assertEqual(verified["observer_key_id"], pin["keyId"])

    def test_alarming_verdict_still_verifies_and_is_reported(self):
        envelope, pin = js_signed(verdict="SPLIT_VIEW")
        self.assertEqual(vo.verify_observation(envelope, pin)["verdict"], "SPLIT_VIEW")

    def test_rejects_payload_tampering_the_same_way_as_js(self):
        envelope, pin = js_signed()
        tampered = copy.deepcopy(envelope)
        tampered["payload"] = base64.b64encode(
            json.dumps(statement(verdict="ROOTS_EQUAL", observer_key_id=pin["keyId"])).encode()
        ).decode()
        js = node({"op": "verify", "envelope": tampered, "spki": pin["publicKeySpkiBase64"]})
        self.assertEqual((js["ok"], js["reason"]), (False, "signature invalid"))
        with self.assertRaisesRegex(vo.ObservationError, "signature verification failed: signature invalid"):
            vo.verify_observation(tampered, pin)

    def test_rejects_observation_signed_by_another_key(self):
        _, trusted_pin = js_signed()
        attacker_envelope, _ = js_signed()
        with self.assertRaisesRegex(vo.ObservationError, "no signature for keyid"):
            vo.verify_observation(attacker_envelope, trusted_pin)

    def test_rejects_signed_observer_keyid_that_differs_from_pin(self):
        envelope, pin = js_signed(bind_observer=False)
        with self.assertRaisesRegex(vo.ObservationError, "signed observer keyId does not match"):
            vo.verify_observation(envelope, pin)


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.pin = vo.loads_strict(REPO_PIN.read_text(encoding="utf-8"))
        self.key = vo.load_observer_pin(self.pin)

    def test_verify_envelope_refuses_malformed_input_without_raising(self):
        cases = [
            None,
            {},
            {"payloadType": "text/plain", "signatures": [{}]},
            {"payloadType": vo.PAYLOAD_TYPE, "signatures": []},
            {"payloadType": vo.PAYLOAD_TYPE, "signatures": [{"keyid": self.pin["keyId"], "sig": "%%"}], "payload": "e30="},
            {"payloadType": vo.PAYLOAD_TYPE, "signatures": [{"keyid": self.pin["keyId"], "sig": "AA=="}], "payload": "not base64!"},
        ]
        for envelope in cases:
            with self.subTest(envelope=envelope):
                result = vo.verify_envelope(envelope, self.key)
                self.assertFalse(result["ok"])
                self.assertTrue(result["reason"])

    def test_rejects_pin_with_wrong_kind_or_mismatched_keyid(self):
        wrong_kind = dict(self.pin, kind="szl-quant-engine-pubkey")
        with self.assertRaisesRegex(vo.ObservationError, "invalid observer public-key pin metadata"):
            vo.load_observer_pin(wrong_kind)
        wrong_id = dict(self.pin, keyId="0" * 16)
        with self.assertRaisesRegex(vo.ObservationError, "pin keyId mismatch"):
            vo.load_observer_pin(wrong_id)

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            vo.loads_strict('{"verdict":"SPLIT_VIEW","verdict":"PREFIX_OK"}')

    def test_repository_observer_pin_is_self_consistent(self):
        self.assertEqual(vo.key_id(self.key), self.pin["keyId"])


class PublishedObservationTests(unittest.TestCase):
    def test_fixture_is_the_pinned_byte_copy(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)

    def test_published_observation_verifies_with_repository_pin(self):
        pin = vo.loads_strict(REPO_PIN.read_text(encoding="utf-8"))
        envelope = vo.loads_strict(FIXTURE.read_text(encoding="utf-8"))
        verified = vo.verify_observation(envelope, pin)
        self.assertEqual(verified["verdict"], "PREFIX_OK")
        self.assertEqual(verified["observer_key_id"], pin["keyId"])
        self.assertEqual(verified["summary"]["ledger"]["headSeq"], 422)

    def test_cli_reports_ok_and_exit_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vo.main([str(FIXTURE)])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), f"OK PREFIX_OK {FIXTURE.name}")


if __name__ == "__main__":
    unittest.main()
