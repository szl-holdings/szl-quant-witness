import { verifyEnvelope } from './vendor/szl-quant/dsse.mjs';
import { keyIdFromPublicKey, loadPublicKeyFromSpkiBase64 } from './vendor/szl-quant/keys.mjs';

const IN_TOTO_STATEMENT = 'https://in-toto.io/Statement/v1';
const WITNESS_KIND = 'szl-quant-witness';
const WITNESS_NAME_RE = /^witness_(\d{4})_(\d+)\.receipt\.json$/;

export function verifyEngineWitnessEnvelope(envelope, enginePin) {
  if (!enginePin || enginePin.kind !== 'szl-quant-engine-pubkey' || enginePin.v !== 1 || enginePin.alg !== 'ed25519') {
    throw new Error('invalid engine public-key pin metadata');
  }
  if (typeof enginePin.keyId !== 'string' || !/^[0-9a-f]{16}$/.test(enginePin.keyId)) {
    throw new Error('invalid engine public-key pin keyId');
  }
  if (typeof enginePin.publicKeySpkiBase64 !== 'string' || !enginePin.publicKeySpkiBase64) {
    throw new Error('missing engine public-key pin bytes');
  }

  const publicKey = loadPublicKeyFromSpkiBase64(enginePin.publicKeySpkiBase64);
  const derivedKeyId = keyIdFromPublicKey(publicKey);
  if (derivedKeyId !== enginePin.keyId) {
    throw new Error(`engine public-key pin keyId mismatch: expected ${enginePin.keyId}, derived ${derivedKeyId}`);
  }

  const verified = verifyEnvelope(envelope, publicKey);
  if (!verified.ok) throw new Error(`engine witness signature verification failed: ${verified.reason}`);
  if (verified.keyid !== enginePin.keyId) {
    throw new Error(`engine witness signature keyId mismatch: expected ${enginePin.keyId}, verified ${verified.keyid}`);
  }

  const statement = verified.payload;
  if (statement?._type !== IN_TOTO_STATEMENT) throw new Error('engine witness payload is not an in-toto Statement/v1');
  const summary = statement?.predicate?.summary;
  if (summary?.kind !== WITNESS_KIND) throw new Error(`unexpected witness receipt kind: ${summary?.kind}`);
  if (!Number.isSafeInteger(summary?.chain?.seq) || summary.chain.seq < 0) throw new Error('engine witness chain sequence is invalid');

  return { statement, summary, engineKeyId: derivedKeyId };
}

export function assertWitnessFilenameBinding(name, summary) {
  const match = WITNESS_NAME_RE.exec(name);
  if (!match) throw new Error(`invalid witness filename: ${name}`);
  const fileSeq = Number(match[1]);
  if (fileSeq !== summary?.chain?.seq) {
    throw new Error(`witness filename sequence ${fileSeq} does not match signed chain sequence ${summary?.chain?.seq}`);
  }
  return fileSeq;
}
