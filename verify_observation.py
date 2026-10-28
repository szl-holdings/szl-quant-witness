#!/usr/bin/env python3
"""verify_observation.py: verify szl-quant-witness gossip observations in Python.

Checks a published observation (a DSSE envelope over an in-toto Statement,
ed25519) against the pinned observer key in keys/observer_pubkey.json. It
follows the same rules as the vendored JS primitives
(vendor/szl-quant/dsse.mjs, vendor/szl-quant/keys.mjs):

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    keyId           = first 16 hex chars of sha256(SPKI DER of the public key)

This module only verifies. It never signs and does not replace observe.mjs.
It is stricter than the JS on malformed input: base64 must be well-formed,
duplicate JSON keys are refused, and there is no trust-on-first-use fallback
to an embedded key. Any failure is a refusal with a reason, never a pass.

Usage:
    python verify_observation.py observations/obs_0422_*.observation.json
    python verify_observation.py --pin keys/observer_pubkey.json FILE [FILE ...]

Exit status: 0 when every file verifies, 1 when any file fails, 2 on a bad pin.
A valid signature over an alarming verdict (e.g. SPLIT_VIEW) still verifies:
the verdict is printed, and the alarm is the observation's content, not a
verification failure.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
OBSERVATION_PREDICATE = "https://szl.holdings/quant/gossip-observation/v1"
OBSERVATION_KIND = "szl-quant-gossip-observation"
OBSERVER_PIN_KIND = "szl-quant-observer-pubkey"
KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
DEFAULT_PIN = Path(__file__).resolve().parent / "keys" / "observer_pubkey.json"


class ObservationError(Exception):
    """Raised when an observation or its pin fails verification."""


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def loads_strict(data):
    """json.loads that refuses duplicate object keys (fail closed)."""
    return json.loads(data, object_pairs_hook=_reject_duplicate_keys)


def b64decode_strict(text):
    if not isinstance(text, str):
        raise ValueError("base64 field is not a string")
    return base64.b64decode(text, validate=True)


def pae(payload_type, payload):
    """DSSE pre-authentication encoding; byte-for-byte the same as dsse.mjs pae()."""
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(type_bytes), type_bytes, len(payload)) + payload


def spki_der(public_key):
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def key_id(public_key):
    """House keyId: first 16 hex chars of sha256(SPKI DER), as in keys.mjs."""
    return hashlib.sha256(spki_der(public_key)).hexdigest()[:16]


def load_public_key_spki_b64(b64):
    key = load_der_public_key(b64decode_strict(b64))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not ed25519")
    return key


def verify_envelope(envelope, public_key):
    """Verify a DSSE envelope with an explicit key.

    Returns {"ok": True, "keyid": ..., "payload": ...} or
    {"ok": False, "reason": ...}; never raises on bad input.
    """
    try:
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            return {"ok": False, "reason": "bad payloadType"}
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            return {"ok": False, "reason": "no signatures"}
        if public_key is None:
            return {"ok": False, "reason": "no public key available"}
        payload = b64decode_strict(envelope.get("payload"))
        expected = key_id(public_key)
        entry = next(
            (s for s in signatures if isinstance(s, dict) and s.get("keyid") == expected),
            None,
        )
        if entry is None:
            return {"ok": False, "reason": f"no signature for keyid {expected}"}
        try:
            public_key.verify(b64decode_strict(entry.get("sig")), pae(PAYLOAD_TYPE, payload))
        except InvalidSignature:
            return {"ok": False, "reason": "signature invalid"}
        return {"ok": True, "keyid": expected, "payload": loads_strict(payload.decode("utf-8"))}
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
        return {"ok": False, "reason": f"verify error: {exc}"}


def load_observer_pin(pin):
    """Validate an observer pin and return its ed25519 key; raises ObservationError."""
    if (
        not isinstance(pin, dict)
        or pin.get("kind") != OBSERVER_PIN_KIND
        or pin.get("v") != 1
        or pin.get("alg") != "ed25519"
    ):
        raise ObservationError("invalid observer public-key pin metadata")
    pinned_id = pin.get("keyId")
    if not isinstance(pinned_id, str) or not KEY_ID_RE.match(pinned_id):
        raise ObservationError("invalid observer public-key pin keyId")
    if not isinstance(pin.get("publicKeySpkiBase64"), str) or not pin["publicKeySpkiBase64"]:
        raise ObservationError("missing observer public-key pin bytes")
    try:
        public_key = load_public_key_spki_b64(pin["publicKeySpkiBase64"])
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ObservationError(f"observer public-key pin unreadable: {exc}") from None
    derived = key_id(public_key)
    if derived != pinned_id:
        raise ObservationError(
            f"observer public-key pin keyId mismatch: expected {pinned_id}, derived {derived}"
        )
    return public_key


def verify_observation(envelope, pin):
    """Verify one observation against the pinned observer key.

    Returns {"statement", "summary", "verdict", "observer_key_id"};
    raises ObservationError on any failure.
    """
    public_key = load_observer_pin(pin)
    result = verify_envelope(envelope, public_key)
    if not result["ok"]:
        raise ObservationError(f"observation signature verification failed: {result['reason']}")
    if result["keyid"] != pin["keyId"]:
        raise ObservationError(
            f"observation signature keyId mismatch: expected {pin['keyId']}, verified {result['keyid']}"
        )
    statement = result["payload"]
    if not isinstance(statement, dict) or statement.get("_type") != IN_TOTO_STATEMENT:
        raise ObservationError("observation payload is not an in-toto Statement/v1")
    if statement.get("predicateType") != OBSERVATION_PREDICATE:
        raise ObservationError(f"unexpected predicateType: {statement.get('predicateType')}")
    predicate = statement.get("predicate")
    summary = predicate.get("summary") if isinstance(predicate, dict) else None
    if not isinstance(summary, dict) or summary.get("kind") != OBSERVATION_KIND:
        raise ObservationError(
            f"unexpected observation kind: {summary.get('kind') if isinstance(summary, dict) else None}"
        )
    observer = summary.get("observer")
    if not isinstance(observer, dict) or observer.get("keyId") != pin["keyId"]:
        raise ObservationError("signed observer keyId does not match the pinned observer key")
    verdict = summary.get("verdict")
    if not isinstance(verdict, str) or not verdict:
        raise ObservationError("observation verdict is missing")
    return {
        "statement": statement,
        "summary": summary,
        "verdict": verdict,
        "observer_key_id": result["keyid"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path, help="observation .json files")
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN, help="observer pin JSON")
    args = parser.parse_args(argv)
    try:
        pin = loads_strict(args.pin.read_text(encoding="utf-8"))
        load_observer_pin(pin)
    except (OSError, ValueError, ObservationError) as exc:
        print(f"PIN-ERROR {exc}", file=sys.stderr)
        return 2
    failed = 0
    for path in args.files:
        try:
            envelope = loads_strict(path.read_text(encoding="utf-8"))
            verified = verify_observation(envelope, pin)
            print(f"OK {verified['verdict']} {path.name}")
        except (OSError, ValueError, ObservationError) as exc:
            failed += 1
            print(f"FAIL {exc} {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
