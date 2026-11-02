"""Non-finite values must not cross either verifier's JSON boundary."""
import base64
import contextlib
import io
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import verify_observation as vo  # noqa: E402
import verify_witness as vw  # noqa: E402

NONFINITE = ("NaN", "Infinity", "-Infinity", "1e400", "-1e400")
CLI_CASES = (
    (vo.main, "obs_0422_1793154252851.observation.json", "observer_pubkey.json"),
    (vw.main, "witness_0425_1793212259840.receipt.json", "engine_pubkey.json"),
)


class StrictJsonTests(unittest.TestCase):
    def test_rejects_nonfinite_values_at_every_json_depth(self):
        for literal in NONFINITE:
            for text in (literal, '{"value":' + literal + '}', '[{"nested":[' + literal + ']}]'):
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, "non-finite JSON number"):
                    vo.loads_strict(text)

    def test_preserves_finite_numbers_and_literal_strings(self):
        value = vo.loads_strict('[0, -0.0, 1.25, 5e-324, 1.7976931348623157e308, "NaN", "1e400"]')
        self.assertEqual(value[0], 0)
        self.assertEqual(math.copysign(1, value[1]), -1)
        self.assertEqual(value[2:], [1.25, 5e-324, sys.float_info.max, "NaN", "1e400"])

    def test_valid_signatures_do_not_admit_nonfinite_signed_payloads(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        keyid = vo.key_id(public)
        for verify, kind, predicate, pin_kind in (
            (vo.verify_observation, vo.OBSERVATION_KIND, vo.OBSERVATION_PREDICATE, vo.OBSERVER_PIN_KIND),
            (vw.verify_engine_witness, vw.WITNESS_KIND, vw.WITNESS_PREDICATE, vw.ENGINE_PIN_KIND),
        ):
            pin = {"kind": pin_kind, "v": 1, "alg": "ed25519", "keyId": keyid,
                   "publicKeySpkiBase64": base64.b64encode(vo.spki_der(public)).decode()}
            statement = {"_type": vo.IN_TOTO_STATEMENT, "predicateType": predicate,
                         "predicate": {"summary": {"kind": kind, "observer": {"keyId": keyid},
                                                  "verdict": "PREFIX_OK", "chain": {"seq": 1},
                                                  "metric": "REPLACE_NUMBER"}}}
            for literal in ("1.25",) + NONFINITE:
                with self.subTest(verifier=verify.__name__, literal=literal):
                    payload = json.dumps(statement).replace('"REPLACE_NUMBER"', literal).encode()
                    signature = private.sign(vo.pae(vo.PAYLOAD_TYPE, payload))
                    # Confirm refusal below concerns decoded data, not an invalid signature.
                    public.verify(signature, vo.pae(vo.PAYLOAD_TYPE, payload))
                    envelope = {"payloadType": vo.PAYLOAD_TYPE,
                                "payload": base64.b64encode(payload).decode(),
                                "signatures": [{"keyid": keyid, "sig": base64.b64encode(signature).decode()}]}
                    if literal == "1.25":
                        self.assertEqual(verify(envelope, pin)["summary"]["metric"], 1.25)
                    else:
                        with self.assertRaisesRegex(vo.ObservationError, "non-finite JSON number"):
                            verify(envelope, pin)

    def test_cli_refuses_nonfinite_outer_envelope_even_with_valid_fixture(self):
        for main, fixture, _ in CLI_CASES:
            original = (REPO / "test" / "fixtures" / fixture).read_text().rstrip()
            for literal in NONFINITE:
                with self.subTest(fixture=fixture, literal=literal), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / fixture
                    path.write_text(original[:-1] + ',"extra":' + literal + '}')
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main([str(path)])
                    self.assertEqual(code, 1)
                    self.assertIn("FAIL non-finite JSON number", output.getvalue())
                    self.assertNotIn("OK ", output.getvalue())

    def test_cli_reports_nonfinite_pin_as_pin_error(self):
        for main, fixture, pin_file in CLI_CASES:
            original = (REPO / "keys" / pin_file).read_text().rstrip()
            for literal in NONFINITE:
                with self.subTest(pin=pin_file, literal=literal), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / pin_file
                    path.write_text(original[:-1] + ',"extra":' + literal + '}')
                    output = io.StringIO()
                    with contextlib.redirect_stderr(output):
                        code = main(["--pin", str(path), str(REPO / "test" / "fixtures" / fixture)])
                    self.assertEqual(code, 2)
                    self.assertIn("PIN-ERROR non-finite JSON number", output.getvalue())


if __name__ == "__main__":
    unittest.main()
