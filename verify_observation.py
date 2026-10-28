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
hashes must be exactly 64 hex digits, duplicate JSON keys are refused, and
there is no trust-on-first-use fallback to an embedded key. Any failure is a
refusal with a reason, never a pass.

Usage:
    python verify_observation.py observations/obs_0422_*.observation.json
    python verify_observation.py --pin keys/observer_pubkey.json FILE [FILE ...]

By default the CLI also replays the log evidence (Rekor checkpoint note,
RFC 6962 consistency, recorded verdict) against keys/rekor_pubkey.pem;
--no-replay restricts it to signature checks.

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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
    load_pem_public_key,
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


def verify_observation(envelope, pin, rekor_pem=None):
    """Verify one observation against the pinned observer key.

    With rekor_pem (the pinned Rekor log key, PEM bytes) the log evidence is
    also replayed: live checkpoint note signature, RFC 6962 consistency and
    the recorded verdict (see check_log_evidence).

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
    if rekor_pem is not None:
        check_log_evidence(summary, load_rekor_pin(rekor_pem))
    return {
        "statement": statement,
        "summary": summary,
        "verdict": verdict,
        "observer_key_id": result["keyid"],
    }


# --------------------------------------------------------------------------
# Log-evidence replay: Rekor checkpoint notes, RFC 6962 consistency, verdict.
# Twins of vendor/szl-quant/witness.mjs parseCheckpoint / verifyCheckpoint /
# rfc6962VerifyConsistency and observe.mjs step 6. Opt-in for the library
# function (rekor_pem=None keeps the signature-only behaviour); on by default
# in the CLI.

DEFAULT_REKOR_PIN = Path(__file__).resolve().parent / "keys" / "rekor_pubkey.pem"
MAX_SAFE_INTEGER = 2**53 - 1
# ECMAScript \s (WhiteSpace + LineTerminator), as witness.mjs matches it;
# Python's \s differs on U+FEFF, \x1c-\x1f and \x85.
_JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_ORIGIN_RE = re.compile(f"[^{_JS_SPACE}]+ - [0-9]+")
_TREE_SIZE_RE = re.compile(r"[0-9]+")
_SIG_LINE_RE = re.compile(f"\u2014 ([^{_JS_SPACE}]+) ([^{_JS_SPACE}]+)")
_HEX32_RE = re.compile(r"[0-9a-fA-F]{64}")


def is_safe_integer(value):
    """JS Number.isSafeInteger on a JSON-decoded value; bool is not a number."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    if isinstance(value, float):
        return value == value and abs(value) <= MAX_SAFE_INTEGER and value.is_integer()
    return False


def _hex32(value, message):
    # Exactly 64 hex digits: bytes.fromhex alone would skip whitespace.
    if not isinstance(value, str) or not _HEX32_RE.fullmatch(value):
        raise ObservationError(message)
    return bytes.fromhex(value)


def rfc6962_node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_consistency(first_size, second_size, first_root_hex, second_root_hex, proof_hex):
    """RFC 6962 consistency check; the same algorithm as rfc6962VerifyConsistency.

    Returns True or raises ObservationError. Note: the proof alone does not
    bind second_size (sizes with the same proof shape alias); the signed
    checkpoint does, which is why check_log_evidence verifies the live note.
    """
    if (
        not (is_safe_integer(first_size) and is_safe_integer(second_size))
        or first_size < 1
        or second_size < first_size
    ):
        raise ObservationError(f"consistency proof rejected: invalid tree sizes {first_size} -> {second_size}")
    first_size, second_size = int(first_size), int(second_size)
    first = _hex32(first_root_hex, "consistency proof rejected: root hash is not 32 bytes")
    second = _hex32(second_root_hex, "consistency proof rejected: root hash is not 32 bytes")
    if proof_hex is not None and not isinstance(proof_hex, list):
        raise ObservationError("consistency proof rejected: proof is not a list")
    proof = [_hex32(h, "consistency proof rejected: proof hash is not 32 bytes") for h in (proof_hex or [])]
    if first_size == second_size:
        if proof:
            raise ObservationError("consistency proof rejected: same-size proof must be empty")
        if first != second:
            raise ObservationError("consistency proof rejected: same tree size but different roots (split view)")
        return True
    items = [first] + proof if first_size & (first_size - 1) == 0 else proof
    if not items:
        raise ObservationError("consistency proof rejected: empty proof for a grown tree")
    fn, sn = first_size - 1, second_size - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    fr = sr = items[0]
    for item in items[1:]:
        if sn == 0:
            raise ObservationError("consistency proof rejected: too many proof hashes")
        if fn % 2 == 1 or fn == sn:
            fr = rfc6962_node_hash(item, fr)
            sr = rfc6962_node_hash(item, sr)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            sr = rfc6962_node_hash(sr, item)
        fn //= 2
        sn //= 2
    if fr != first:
        raise ObservationError("consistency proof rejected: recomputed old root differs")
    if sr != second:
        raise ObservationError("consistency proof rejected: recomputed new root differs")
    if sn != 0:
        raise ObservationError("consistency proof rejected: proof hashes exhausted before reaching the root")
    return True


def parse_checkpoint(text):
    """Strict Rekor signed-note parser; the same rules as witness.mjs parseCheckpoint."""
    if not isinstance(text, str):
        raise ObservationError("checkpoint rejected: not a string")
    sep = text.find("\n\n")
    if sep < 0:
        raise ObservationError("checkpoint rejected: no blank-line separator")
    note_body = text[: sep + 1]
    lines = note_body.split("\n")
    if len(lines) < 4:
        raise ObservationError("checkpoint rejected: note body too short")
    if not _ORIGIN_RE.fullmatch(lines[0]):
        raise ObservationError("checkpoint rejected: malformed origin line")
    if not _TREE_SIZE_RE.fullmatch(lines[1]):
        raise ObservationError("checkpoint rejected: malformed tree-size line")
    # Too many significant digits to be safe: out of range without int(),
    # which raises ValueError past Python's 4300-digit conversion limit.
    tree_size = int(lines[1]) if len(lines[1].lstrip("0")) <= len(str(MAX_SAFE_INTEGER)) else 0
    if not 1 <= tree_size <= MAX_SAFE_INTEGER:
        raise ObservationError("checkpoint rejected: tree size out of range")
    try:
        root = b64decode_strict(lines[2])
    except (ValueError, binascii.Error):
        root = b""
    if len(root) != 32 or base64.b64encode(root).decode("ascii") != lines[2]:
        raise ObservationError("checkpoint rejected: root hash is not canonical 32-byte base64")
    sigs = []
    for line in text[sep + 2 :].split("\n"):
        if not line:
            continue
        match = _SIG_LINE_RE.fullmatch(line)
        if not match:
            raise ObservationError("checkpoint rejected: malformed signature line")
        try:
            raw = b64decode_strict(match.group(2))
        except (ValueError, binascii.Error):
            raise ObservationError("checkpoint rejected: malformed signature line") from None
        if len(raw) < 5:
            raise ObservationError("checkpoint rejected: signature too short")
        sigs.append({"name": match.group(1), "key_hint_hex": raw[:4].hex(), "signature": raw[4:]})
    if not sigs:
        raise ObservationError("checkpoint rejected: no signature lines")
    return {"origin": lines[0], "tree_size": tree_size, "root_hex": root.hex(), "note_body": note_body, "sigs": sigs}


def load_rekor_pin(pem_bytes):
    """Load the pinned Rekor log key (ECDSA); raises ObservationError."""
    try:
        key = load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise ObservationError(f"pinned log key unusable: {exc}") from None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ObservationError("pinned log key is not ECDSA")
    return key


def verify_checkpoint(text, log_key):
    """Parse a checkpoint and verify its note under the pinned log key.

    The 4-byte key hint must equal sha256(SPKI DER)[:4] of the pinned key and
    the ECDSA-SHA256 signature must verify over the exact note body.
    """
    cp = parse_checkpoint(text)
    hint = hashlib.sha256(spki_der(log_key)).digest()[:4].hex()
    candidates = [s for s in cp["sigs"] if s["key_hint_hex"] == hint]
    if not candidates:
        raise ObservationError(f"no checkpoint signature carries the pinned key's hint {hint}")
    for sig in candidates:
        try:
            log_key.verify(sig["signature"], cp["note_body"].encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            return cp
        except (InvalidSignature, ValueError):
            continue
    raise ObservationError("checkpoint signature invalid over the signed note body")


def recompute_verdict(summary):
    """The verdict observe.mjs should have reached from the signed fields."""
    engine, live = summary.get("engineCheckpoint"), summary.get("liveCheckpoint")
    ledger, consistency = summary.get("ledger"), summary.get("consistency") or {}
    if not all(isinstance(x, dict) for x in (engine, live, ledger, consistency)):
        raise ObservationError("observation lacks checkpoint, ledger or consistency fields")
    for cp in (engine, live):
        if not is_safe_integer(cp.get("treeSize")) or not isinstance(cp.get("origin"), str):
            raise ObservationError("observation checkpoint fields are malformed")
    if engine["origin"] != live["origin"]:
        verdict = "SHARD_ROTATED"
    elif live["treeSize"] < engine["treeSize"]:
        verdict = "LOG_REGRESSED"
    elif live["treeSize"] == engine["treeSize"]:
        verdict = "ROOTS_EQUAL" if live.get("rootHex") == engine.get("rootHex") else "SPLIT_VIEW"
    else:
        try:
            verify_consistency(
                engine["treeSize"], live["treeSize"], engine.get("rootHex"), live.get("rootHex"),
                consistency.get("proofHashes"),
            )
            verdict = "PREFIX_OK"
        except ObservationError:
            verdict = "SPLIT_VIEW"
    if ledger.get("chainBindingVerified") is not True and verdict in ("PREFIX_OK", "ROOTS_EQUAL"):
        verdict = "LEDGER_BINDING_MISMATCH"
    return verdict


def check_log_evidence(summary, log_key):
    """Re-check the log evidence inside a signature-verified observation.

    The live checkpoint's raw note must verify under the pinned Rekor key and
    agree with the signed origin/treeSize/rootHex; the recorded verdict must
    equal the replayed one. Raises ObservationError; returns the verdict.
    """
    live = summary.get("liveCheckpoint")
    if not isinstance(live, dict):
        raise ObservationError("observation has no live checkpoint")
    cp = verify_checkpoint(live.get("rawNote"), log_key)
    if (cp["origin"], cp["tree_size"], cp["root_hex"]) != (live.get("origin"), live.get("treeSize"), live.get("rootHex")):
        raise ObservationError("live checkpoint fields disagree with its signed note")
    replayed = recompute_verdict(summary)
    if replayed != summary.get("verdict"):
        raise ObservationError(f"recorded verdict {summary.get('verdict')} but replay gives {replayed}")
    return replayed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path, help="observation .json files")
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN, help="observer pin JSON")
    parser.add_argument("--rekor-pin", type=Path, default=DEFAULT_REKOR_PIN, help="Rekor log public key PEM")
    parser.add_argument("--no-replay", action="store_true", help="signature checks only; skip log-evidence replay")
    args = parser.parse_args(argv)
    try:
        pin = loads_strict(args.pin.read_text(encoding="utf-8"))
        load_observer_pin(pin)
        rekor_pem = None if args.no_replay else args.rekor_pin.read_bytes()
        if rekor_pem is not None:
            load_rekor_pin(rekor_pem)
    except (OSError, ValueError, ObservationError) as exc:
        print(f"PIN-ERROR {exc}", file=sys.stderr)
        return 2
    failed = 0
    for path in args.files:
        try:
            envelope = loads_strict(path.read_text(encoding="utf-8"))
            verified = verify_observation(envelope, pin, rekor_pem)
            print(f"OK {verified['verdict']} {path.name}")
        except (OSError, ValueError, ObservationError) as exc:
            failed += 1
            print(f"FAIL {exc} {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
