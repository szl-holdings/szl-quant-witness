import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { signEnvelope } from '../vendor/szl-quant/dsse.mjs';
import { generateEngineKeypair, keyIdFromPublicKey, publicKeySpkiBase64 } from '../vendor/szl-quant/keys.mjs';
import { assertWitnessFilenameBinding, verifyEngineWitnessEnvelope } from '../engine-witness.mjs';

const statement = (seq = 13) => ({
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'fixture', digest: { sha256: '0'.repeat(64) } }],
  predicateType: 'https://szl.holdings/quant/witness/v1',
  predicate: { summary: { kind: 'szl-quant-witness', chain: { seq } } },
});

function makeFixture(seq = 13, modifyStatement = (value) => value) {
  const { privateKey, publicKey } = generateEngineKeypair();
  const pin = {
    kind: 'szl-quant-engine-pubkey',
    v: 1,
    alg: 'ed25519',
    keyId: keyIdFromPublicKey(publicKey),
    publicKeySpkiBase64: publicKeySpkiBase64(publicKey),
  };
  return { envelope: signEnvelope(modifyStatement(statement(seq)), privateKey, publicKey), pin };
}

test('accepts a witness envelope signed by the pinned engine key', () => {
  const { envelope, pin } = makeFixture(13);
  const verified = verifyEngineWitnessEnvelope(envelope, pin);
  assert.equal(verified.summary.chain.seq, 13);
  assert.equal(verified.engineKeyId, pin.keyId);
  assert.equal(assertWitnessFilenameBinding('witness_0013_1784233307672.receipt.json', verified.summary), 13);
});

test('rejects payload tampering after signing', () => {
  const { envelope, pin } = makeFixture(13);
  const tampered = structuredClone(envelope);
  tampered.payload = Buffer.from(JSON.stringify(statement(14)), 'utf8').toString('base64');
  assert.throws(() => verifyEngineWitnessEnvelope(tampered, pin), /signature verification failed/);
});

test('rejects a valid engine signature over a different or missing predicate type', async (t) => {
  const cases = [
    ['missing', undefined],
    ['null', null],
    ['empty', ''],
    ['observation', 'https://szl.holdings/quant/gossip-observation/v1'],
    ['unknown version', 'https://szl.holdings/quant/witness/v2'],
    ['trailing whitespace', 'https://szl.holdings/quant/witness/v1 '],
    ['object', {}],
    ['array', ['https://szl.holdings/quant/witness/v1']],
  ];
  for (const [name, predicateType] of cases) {
    await t.test(name, () => {
      const { envelope, pin } = makeFixture(13, (value) => {
        if (predicateType === undefined) delete value.predicateType;
        else value.predicateType = predicateType;
        return value;
      });
      assert.throws(() => verifyEngineWitnessEnvelope(envelope, pin), /unexpected witness predicate type/);
    });
  }
});

test('preserves verification of the retained engine witness fixtures', () => {
  const pin = JSON.parse(readFileSync(new URL('../keys/engine_pubkey.json', import.meta.url), 'utf8'));
  for (const name of [
    'witness_0001_1784228300881.receipt.json',
    'witness_0009_1784226998334.receipt.json',
    'witness_0009_1784228302184.receipt.json',
    'witness_0425_1793212259840.receipt.json',
  ]) {
    const envelope = JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8'));
    const verified = verifyEngineWitnessEnvelope(envelope, pin);
    assertWitnessFilenameBinding(name, verified.summary);
  }
});

test('rejects a witness signed by a key other than the pinned engine key', () => {
  const trusted = makeFixture(13);
  const attacker = makeFixture(13);
  assert.throws(() => verifyEngineWitnessEnvelope(attacker.envelope, trusted.pin), /signature verification failed/);
});

test('rejects filename sequence drift from the signed witness chain sequence', () => {
  const { envelope, pin } = makeFixture(13);
  const verified = verifyEngineWitnessEnvelope(envelope, pin);
  assert.throws(
    () => assertWitnessFilenameBinding('witness_9999_1784233307672.receipt.json', verified.summary),
    /does not match signed chain sequence/,
  );
});

test('repository engine key pin is structurally valid and self-consistent', () => {
  const pin = JSON.parse(readFileSync(new URL('../keys/engine_pubkey.json', import.meta.url), 'utf8'));
  const fake = { payloadType: 'application/vnd.in-toto+json', payload: '', signatures: [] };
  assert.throws(
    () => verifyEngineWitnessEnvelope(fake, pin),
    /engine witness signature verification failed: no signatures/,
  );
});
