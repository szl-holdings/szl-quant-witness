/**
 * keys.mjs — ed25519 signing identity for the engine.
 *
 * House convention (khipu/forge): keyId = first 16 hex chars of
 * sha256(SPKI DER of the public key). Public key ships as SPKI base64.
 * The PRIVATE key is never committed to the repo.
 */
import { generateKeyPairSync, createPublicKey, createPrivateKey, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function keyIdFromPublicKey(pubKeyObj) {
  const spki = pubKeyObj.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('hex').slice(0, 16);
}

export function publicKeySpkiBase64(pubKeyObj) {
  return pubKeyObj.export({ type: 'spki', format: 'der' }).toString('base64');
}

export function generateEngineKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, keyId: keyIdFromPublicKey(publicKey) };
}

/** Load private key PEM from path; returns null if absent (fail closed upstream). */
export function loadPrivateKey(path) {
  if (!existsSync(path)) return null;
  return createPrivateKey(readFileSync(path, 'utf8'));
}

export function loadPublicKeyFromSpkiBase64(b64) {
  return createPublicKey({ key: Buffer.from(b64, 'base64'), type: 'spki', format: 'der' });
}

/**
 * Ensure a signing identity exists: loads privateKeyPath if present, else
 * generates one, writes the private key PEM to privateKeyPath (mode 0600)
 * and the public JSON to pubJsonPath.
 */
export function ensureIdentity(privateKeyPath, pubJsonPath) {
  let privateKey = loadPrivateKey(privateKeyPath);
  let publicKey;
  if (privateKey) {
    publicKey = createPublicKey(privateKey);
  } else {
    const kp = generateEngineKeypair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
    mkdirSync(dirname(privateKeyPath), { recursive: true });
    writeFileSync(privateKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  }
  const keyId = keyIdFromPublicKey(publicKey);
  const pubJson = {
    kind: 'szl-quant-engine-pubkey',
    v: 1,
    alg: 'ed25519',
    keyId,
    publicKeySpkiBase64: publicKeySpkiBase64(publicKey),
    note: 'Engine signing identity for advisory signal receipts. Private key is NOT in this repo.',
  };
  mkdirSync(dirname(pubJsonPath), { recursive: true });
  writeFileSync(pubJsonPath, JSON.stringify(pubJson, null, 2) + '\n');
  return { privateKey, publicKey, keyId, pubJson };
}
