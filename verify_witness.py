#!/usr/bin/env python3
"""verify_witness.py: verify szl-quant engine witness receipts in Python.

A witness receipt (szl-quant `ledger` branch, witness/witness_<seq4>_<ms>.receipt.json)
is a DSSE envelope, signed by the szl-quant engine, over an in-toto Statement
whose summary anchors one sealed chain head in the Rekor transparency log.
This is the Python twin of engine-witness.mjs (verifyEngineWitnessEnvelope,
assertWitnessFilenameBinding) and of the inclusion path of
vendor/szl-quant/witness.mjs (rfc6962Root, verifyInclusionProof). It reuses
verify_observation.py's DSSE, pin and checkpoint primitives.

Signature checks, against keys/engine_pubkey.json:

    engine pin      kind, v, alg, and keyId == sha256(SPKI DER)[:16]
    DSSE            signed under the pinned key only; the envelope's own
                    publicKeySpkiBase64 is never trusted
    statement       in-toto Statement/v1, witness predicateType, kind
                    szl-quant-witness, safe-integer chain.seq >= 0
    file name       witness_<seq4>_<ms>.receipt.json bound to chain.seq

Anchor replay, against keys/rekor_pubkey.pem (on by default in the CLI):

    entry binding   a rekord entry whose data hash equals chain.sha256 and
                    whose signing key is the pinned engine key
    SET             logID is the pinned log key's id, and Rekor's ECDSA
                    signature over {body, integratedTime, logID, logIndex}
                    verifies
    inclusion       the checkpoint note verifies, its size and root equal the
                    proof's, and the RFC 6962 audit path from
                    sha256(0x00 || entry body) lands on that root

The entry binding and SET checks go beyond the JS, which does not replay
them. Like verify_observation.py, this is stricter than the JS on malformed
input: strict base64 and hex, duplicate JSON keys refused, proof indexes must
be safe integers. Generation-1 receipts carry no inclusion proof; they verify
as SET_ONLY, as in witness.mjs, where they stay valid but are not "proven".

Usage:
    python verify_witness.py witness/witness_0425_*.receipt.json
    python verify_witness.py --no-replay FILE [FILE ...]

Prints "OK INCLUSION|SET_ONLY|SIGNATURE <name>" per file.
Exit status: 0 when every file verifies, 1 when any file fails, 2 on a bad pin.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import verify_observation as vo
from verify_observation import ObservationError

WITNESS_PREDICATE = "https://szl.holdings/quant/witness/v1"
WITNESS_KIND = "szl-quant-witness"
ENGINE_PIN_KIND = "szl-quant-engine-pubkey"
# [0-9], not \d: Python's \d also matches non-ASCII digits, JS's does not.
WITNESS_NAME_RE = re.compile(r"witness_([0-9]{4})_([0-9]+)\.receipt\.json")
DEFAULT_ENGINE_PIN = Path(__file__).resolve().parent / "keys" / "engine_pubkey.json"
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")


def load_engine_pin(pin):
    """Validate the engine pin and return its ed25519 key; raises ObservationError."""
    if (
        not isinstance(pin, dict)
        or pin.get("kind") != ENGINE_PIN_KIND
        or isinstance(pin.get("v"), bool)
        or pin.get("v") != 1
        or pin.get("alg") != "ed25519"
    ):
        raise ObservationError("invalid engine public-key pin metadata")
    pinned_id = pin.get("keyId")
    if not isinstance(pinned_id, str) or not vo.KEY_ID_RE.match(pinned_id):
        raise ObservationError("invalid engine public-key pin keyId")
    if not isinstance(pin.get("publicKeySpkiBase64"), str) or not pin["publicKeySpkiBase64"]:
        raise ObservationError("missing engine public-key pin bytes")
    try:
        public_key = vo.load_public_key_spki_b64(pin["publicKeySpkiBase64"])
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ObservationError(f"engine public-key pin unreadable: {exc}") from None
    derived = vo.key_id(public_key)
    if derived != pinned_id:
        raise ObservationError(f"engine public-key pin keyId mismatch: expected {pinned_id}, derived {derived}")
    return public_key


def verify_engine_witness(envelope, pin, rekor_pem=None):
    """Verify one witness receipt against the pinned engine key.

    With rekor_pem (the pinned Rekor log key, PEM bytes) the Rekor anchor is
    also replayed (see check_anchor).

    Returns {"statement", "summary", "seq", "engine_key_id", "anchor"}, where
    anchor is "INCLUSION", "SET_ONLY", or None without replay; raises
    ObservationError on any failure.
    """
    public_key = load_engine_pin(pin)
    result = vo.verify_envelope(envelope, public_key)
    if not result["ok"]:
        raise ObservationError(f"engine witness signature verification failed: {result['reason']}")
    if result["keyid"] != pin["keyId"]:
        raise ObservationError(
            f"engine witness signature keyId mismatch: expected {pin['keyId']}, verified {result['keyid']}"
        )
    statement = result["payload"]
    if not isinstance(statement, dict) or statement.get("_type") != vo.IN_TOTO_STATEMENT:
        raise ObservationError("engine witness payload is not an in-toto Statement/v1")
    if statement.get("predicateType") != WITNESS_PREDICATE:
        raise ObservationError(f"unexpected predicateType: {statement.get('predicateType')}")
    predicate = statement.get("predicate")
    summary = predicate.get("summary") if isinstance(predicate, dict) else None
    if not isinstance(summary, dict) or summary.get("kind") != WITNESS_KIND:
        raise ObservationError(
            f"unexpected witness receipt kind: {summary.get('kind') if isinstance(summary, dict) else None}"
        )
    chain = summary.get("chain")
    seq = chain.get("seq") if isinstance(chain, dict) else None
    if not vo.is_safe_integer(seq) or seq < 0:
        raise ObservationError("engine witness chain sequence is invalid")
    anchor = None
    if rekor_pem is not None:
        anchor = check_anchor(summary, public_key, vo.load_rekor_pin(rekor_pem))
    return {
        "statement": statement,
        "summary": summary,
        "seq": int(seq),
        "engine_key_id": result["keyid"],
        "anchor": anchor,
    }


def assert_witness_filename_binding(name, summary):
    """The file name's 4-digit sequence must equal the signed chain.seq; returns it."""
    match = WITNESS_NAME_RE.fullmatch(name) if isinstance(name, str) else None
    if not match:
        raise ObservationError(f"invalid witness filename: {name}")
    file_seq = int(match.group(1))
    chain = summary.get("chain") if isinstance(summary, dict) else None
    seq = chain.get("seq") if isinstance(chain, dict) else None
    if not vo.is_safe_integer(seq) or file_seq != seq:
        raise ObservationError(f"witness filename sequence {file_seq} does not match signed chain sequence {seq}")
    return file_seq


# --------------------------------------------------------------------------
# Rekor anchor replay: entry binding, SET, RFC 6962 inclusion. Twins of
# vendor/szl-quant/witness.mjs setMessageBytes / rfc6962Root /
# verifyInclusionProof.


def rfc6962_leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_root(leaf_index, tree_size, leaf_hash, path_hex):
    """Walk an RFC 6962 audit path from a leaf to the root; the same walk as rfc6962Root.

    Raises ObservationError on an index outside the tree, a path too short,
    or unconsumed siblings.
    """
    if (
        not (vo.is_safe_integer(leaf_index) and vo.is_safe_integer(tree_size))
        or leaf_index < 0
        or tree_size < 1
        or leaf_index >= tree_size
    ):
        raise ObservationError(f"inclusion proof rejected: leafIndex {leaf_index} outside tree of size {tree_size}")
    if path_hex is not None and not isinstance(path_hex, list):
        raise ObservationError("inclusion proof rejected: audit path is not a list")
    path = [vo._hex32(h, "inclusion proof rejected: sibling hash is not 32 bytes") for h in (path_hex or [])]
    node, idx, last, used = leaf_hash, int(leaf_index), int(tree_size) - 1, 0
    while last > 0:
        if idx % 2 == 1:
            if used >= len(path):
                raise ObservationError("inclusion proof rejected: audit path too short")
            node = vo.rfc6962_node_hash(path[used], node)
            used += 1
        elif idx < last:
            if used >= len(path):
                raise ObservationError("inclusion proof rejected: audit path too short")
            node = vo.rfc6962_node_hash(node, path[used])
            used += 1
        idx //= 2
        last //= 2
    if used != len(path):
        raise ObservationError(f"inclusion proof rejected: {len(path) - used} unconsumed sibling hash(es)")
    return node


def verify_inclusion_proof(entry_body_b64, proof, log_key):
    """Offline inclusion: entry bytes, leaf hash, audit path, signed root.

    The same checks as verifyInclusionProof. Returns the verified checkpoint;
    raises ObservationError.
    """
    if (
        not isinstance(proof, dict)
        or not vo.is_safe_integer(proof.get("logIndex"))
        or not vo.is_safe_integer(proof.get("treeSize"))
        or not isinstance(proof.get("hashes"), list)
        or not isinstance(proof.get("rootHash"), str)
        or not isinstance(proof.get("checkpoint"), str)
    ):
        raise ObservationError("inclusion proof missing required fields")
    cp = vo.verify_checkpoint(proof["checkpoint"], log_key)
    if cp["tree_size"] != proof["treeSize"]:
        raise ObservationError(
            f"tree size mismatch: proof says {proof['treeSize']}, signed checkpoint says {cp['tree_size']}"
        )
    if cp["root_hex"] != proof["rootHash"]:
        raise ObservationError("root hash mismatch: proof root differs from the signed checkpoint root")
    try:
        entry = vo.b64decode_strict(entry_body_b64)
    except (ValueError, binascii.Error):
        raise ObservationError("inclusion proof rejected: entry body is not base64") from None
    computed = rfc6962_root(proof["logIndex"], proof["treeSize"], rfc6962_leaf_hash(entry), proof["hashes"])
    if computed.hex() != cp["root_hex"]:
        raise ObservationError("audit path does not land on the signed root: entry not proven in this tree")
    return cp


def set_message_bytes(body_b64, integrated_time, log_id, log_index):
    """The bytes Rekor signs in its SET: RFC 8785 JSON of exactly four fields.

    Limited to the shapes Rekor emits (ASCII strings, safe integers), for which
    sorted, separator-free json.dumps is the RFC 8785 serialization.
    """
    if (
        not isinstance(body_b64, str)
        or not isinstance(log_id, str)
        or not _SHA256_HEX_RE.fullmatch(log_id)
        or not (vo.is_safe_integer(integrated_time) and vo.is_safe_integer(log_index))
        or integrated_time < 0
        or log_index < 0
    ):
        raise ObservationError("rekor SET fields are malformed")
    fields = {"body": body_b64, "integratedTime": int(integrated_time), "logID": log_id, "logIndex": int(log_index)}
    return json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("ascii")


def _rekord_fields(entry_body_b64):
    """Hash, signature and key of a rekord entry body, as extractRekordFields reads them."""
    try:
        entry = vo.loads_strict(vo.b64decode_strict(entry_body_b64).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise ObservationError("rekor entry body is not base64 JSON") from None
    spec = entry.get("spec") if isinstance(entry, dict) and entry.get("kind") == "rekord" else None
    data = spec.get("data") if isinstance(spec, dict) else None
    digest = data.get("hash") if isinstance(data, dict) else None
    sig = spec.get("signature") if isinstance(spec, dict) else None
    key = sig.get("publicKey") if isinstance(sig, dict) else None
    if (
        not isinstance(digest, dict)
        or digest.get("algorithm") != "sha256"
        or not isinstance(digest.get("value"), str)
        or not isinstance(key, dict)
        or not isinstance(key.get("content"), str)
    ):
        raise ObservationError("rekor entry is not a sha256 rekord entry with a public key")
    return digest["value"], key["content"]


def check_anchor(summary, engine_key, log_key):
    """Replay the Rekor anchor inside a signature-verified witness receipt.

    The entry must anchor this chain head under the engine key, its SET must
    verify under the pinned log key and, when an inclusion proof is present,
    the proof must land on a signed checkpoint. Returns "INCLUSION" or
    "SET_ONLY"; raises ObservationError.
    """
    chain, rekor = summary.get("chain"), summary.get("rekor")
    if not isinstance(chain, dict) or not isinstance(rekor, dict):
        raise ObservationError("witness receipt lacks chain or rekor fields")
    head = chain.get("sha256")
    if not isinstance(head, str) or not _SHA256_HEX_RE.fullmatch(head):
        raise ObservationError("witness chain.sha256 is not 64 lowercase hex digits")
    entry_hash, entry_key_b64 = _rekord_fields(rekor.get("entryBodyBase64"))
    if entry_hash != head:
        raise ObservationError(f"rekor entry does not anchor this chain head: entry hash {entry_hash}, chain.sha256 {head}")
    try:
        entry_key = load_pem_public_key(vo.b64decode_strict(entry_key_b64))
    except (ValueError, TypeError, binascii.Error):
        entry_key = None
    if not isinstance(entry_key, Ed25519PublicKey) or vo.key_id(entry_key) != vo.key_id(engine_key):
        raise ObservationError("rekor entry is not signed by the pinned engine key")
    log_id = hashlib.sha256(vo.spki_der(log_key)).hexdigest()
    if rekor.get("logID") != log_id:
        raise ObservationError(f"rekor logID {rekor.get('logID')} is not the pinned log key's id {log_id}")
    message = set_message_bytes(rekor.get("entryBodyBase64"), rekor.get("integratedTime"), log_id, rekor.get("logIndex"))
    try:
        log_key.verify(vo.b64decode_strict(rekor.get("signedEntryTimestampBase64")), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, binascii.Error):
        raise ObservationError("rekor SET signature invalid under the pinned log key") from None
    if "inclusionProof" not in rekor:
        return "SET_ONLY"
    verify_inclusion_proof(rekor["entryBodyBase64"], rekor["inclusionProof"], log_key)
    return "INCLUSION"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path, help="witness .receipt.json files")
    parser.add_argument("--pin", type=Path, default=DEFAULT_ENGINE_PIN, help="engine pin JSON")
    parser.add_argument("--rekor-pin", type=Path, default=vo.DEFAULT_REKOR_PIN, help="Rekor log public key PEM")
    parser.add_argument("--no-replay", action="store_true", help="signature checks only; skip the Rekor anchor replay")
    args = parser.parse_args(argv)
    try:
        pin = vo.loads_strict(args.pin.read_text(encoding="utf-8"))
        load_engine_pin(pin)
        rekor_pem = None if args.no_replay else args.rekor_pin.read_bytes()
        if rekor_pem is not None:
            vo.load_rekor_pin(rekor_pem)
    except (OSError, ValueError, ObservationError) as exc:
        print(f"PIN-ERROR {exc}", file=sys.stderr)
        return 2
    failed = 0
    for path in args.files:
        try:
            envelope = vo.loads_strict(path.read_text(encoding="utf-8"))
            verified = verify_engine_witness(envelope, pin, rekor_pem)
            assert_witness_filename_binding(path.name, verified["summary"])
            print(f"OK {verified['anchor'] or 'SIGNATURE'} {path.name}")
        except (OSError, ValueError, ObservationError) as exc:
            failed += 1
            print(f"FAIL {exc} {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
