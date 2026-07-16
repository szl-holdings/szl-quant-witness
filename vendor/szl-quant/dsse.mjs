/**
 * dsse.mjs — DSSE (Dead Simple Signing Envelope), spec-exact PAE, ed25519.
 * Pattern: szl-govsign (DSSE + in-toto Statement), key convention: khipu/forge.
 *
 * PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 * with LEN = ASCII decimal byte length. Signature is over PAE bytes.
 */
import { sign as edSign, verify as edVerify } from 'node:crypto';
import { canonicalBytes } from './canonical-json.mjs';
import { keyIdFromPublicKey, publicKeySpkiBase64, loadPublicKeyFromSpkiBase64 } from './keys.mjs';

export const PAYLOAD_TYPE = 'application/vnd.in-toto+json';

export function pae(payloadType, payloadBytes) {
  const head = Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payloadBytes.length} `, 'utf8');
  return Buffer.concat([head, payloadBytes]);
}

/** Sign a JSON-serializable payload (canonicalized) into a DSSE envelope. */
export function signEnvelope(payloadObj, privateKey, publicKey) {
  const payloadBytes = canonicalBytes(payloadObj);
  const sig = edSign(null, pae(PAYLOAD_TYPE, payloadBytes), privateKey);
  return {
    payloadType: PAYLOAD_TYPE,
    payload: payloadBytes.toString('base64'),
    signatures: [{
      keyid: keyIdFromPublicKey(publicKey),
      sig: sig.toString('base64'),
    }],
    // Convenience for third-party verification without key distribution
    // infrastructure. Verifiers MUST treat an embedded key as
    // trust-on-first-use unless the keyid is pinned out-of-band.
    publicKeySpkiBase64: publicKeySpkiBase64(publicKey),
  };
}

/**
 * Verify a DSSE envelope. Returns { ok, keyid, payload } — ok=false with a
 * reason on ANY failure (fail closed; never throws on bad input).
 */
export function verifyEnvelope(envelope, publicKeyOrNull) {
  try {
    if (!envelope || envelope.payloadType !== PAYLOAD_TYPE) return { ok: false, reason: 'bad payloadType' };
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) return { ok: false, reason: 'no signatures' };
    const payloadBytes = Buffer.from(envelope.payload, 'base64');
    const pub = publicKeyOrNull ?? (envelope.publicKeySpkiBase64
      ? loadPublicKeyFromSpkiBase64(envelope.publicKeySpkiBase64)
      : null);
    if (!pub) return { ok: false, reason: 'no public key available' };
    const expectedKeyId = keyIdFromPublicKey(pub);
    const entry = envelope.signatures.find((s) => s.keyid === expectedKeyId);
    if (!entry) return { ok: false, reason: `no signature for keyid ${expectedKeyId}` };
    const ok = edVerify(null, pae(PAYLOAD_TYPE, payloadBytes), pub, Buffer.from(entry.sig, 'base64'));
    if (!ok) return { ok: false, reason: 'signature invalid' };
    return { ok: true, keyid: expectedKeyId, payload: JSON.parse(payloadBytes.toString('utf8')) };
  } catch (e) {
    return { ok: false, reason: `verify error: ${e.message}` };
  }
}
