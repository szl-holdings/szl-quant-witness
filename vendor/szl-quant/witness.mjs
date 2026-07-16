/**
 * witness.mjs — external witness: anchor sealed chain heads in the
 * Sigstore Rekor public transparency log (rekor.sigstore.dev).
 *
 * The hash chain's confessed honest limit is head truncation: wholesale
 * deletion of the newest link(s) is locally undetectable. Witnessing
 * closes that gap for every anchored head: the head's exact bytes are
 * ed25519-signed and submitted to an append-only, publicly operated log.
 * Once integrated, the anchor cannot be unpublished — deleting the local
 * ledger does not delete the Rekor entry, and the entry stays
 * discoverable by this engine's public key.
 *
 * Doctrine: Rekor's response is REPORTED (an external service's
 * statement). What makes it usable offline:
 * - the SET — Rekor's ECDSA signature over {body, integratedTime,
 *   logID, logIndex} — replayable against the pinned Rekor public key;
 * - the INCLUSION PROOF — an RFC 6962 Merkle audit path from this
 *   entry's leaf to a signed tree head (checkpoint). The verifier
 *   recomputes the leaf hash from the entry bytes, walks the path to
 *   the root, and checks the checkpoint's signed note against the same
 *   pinned key. Zero network.
 *
 * Entry type is `rekord` (full content), not `hashedrekord`: PureEdDSA
 * signs the raw message, so Rekor can only server-side-verify an ed25519
 * signature when it has the artifact bytes. The chain receipt is public
 * data in a public repo — submitting its bytes discloses nothing.
 *
 * HONEST LIMITS (stated in every receipt):
 * - Only witnessed heads are protected; coverage gaps (Rekor outages)
 *   are counted in the open, never papered over.
 * - Inclusion is proven against the checkpoint captured at anchor time.
 *   Generation-3 consistency receipts additionally prove each captured
 *   checkpoint is a prefix of the next (RFC 6962 consistency proofs) —
 *   append-only growth across the whole observation window, replayed
 *   offline. Single observer: no cross-witness gossip is claimed.
 * - An anchor proves the head's bytes existed no later than
 *   integratedTime; for backfilled links that is later than sealing.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalBytes } from './canonical-json.mjs';

export const WITNESS_FILE_RE = /^witness_\d{4}_\d+\.receipt\.json$/;
export const REKOR_SERVER = 'https://rekor.sigstore.dev';

export function witnessFileName(seq, nowMs) {
  return `witness_${String(seq).padStart(4, '0')}_${nowMs}.receipt.json`;
}

/** Proposed rekord entry: full artifact content + raw ed25519 sig + SPKI PEM. */
export function buildRekordProposal({ artifactBytes, signatureBase64, publicKeyPem }) {
  return {
    apiVersion: '0.0.1',
    kind: 'rekord',
    spec: {
      data: { content: Buffer.from(artifactBytes).toString('base64') },
      signature: {
        format: 'x509',
        content: signatureBase64,
        publicKey: { content: Buffer.from(publicKeyPem, 'utf8').toString('base64') },
      },
    },
  };
}

/**
 * The exact bytes Rekor signs in its SET: RFC 8785-canonical JSON of
 * exactly these four fields (alphabetical keys, no whitespace).
 */
export function setMessageBytes({ entryBodyBase64, integratedTime, logID, logIndex }) {
  return canonicalBytes({ body: entryBodyBase64, integratedTime, logID, logIndex });
}

/**
 * Pull verifier-relevant fields from a canonicalized rekord entry body
 * (Rekor strips data.content and stores data.hash). Null on shape miss —
 * callers fail closed.
 */
export function extractRekordFields(entryBodyBase64) {
  let e;
  try { e = JSON.parse(Buffer.from(entryBodyBase64, 'base64').toString('utf8')); } catch { return null; }
  if (e?.kind !== 'rekord') return null;
  const hash = e.spec?.data?.hash;
  const sig = e.spec?.signature;
  if (hash?.algorithm !== 'sha256' || !hash?.value || !sig?.content || !sig?.publicKey?.content) return null;
  return {
    dataSha256: hash.value,
    signatureBase64: sig.content,
    publicKeyPemBase64: sig.publicKey.content,
    format: sig.format ?? null,
  };
}

// ── RFC 6962 Merkle inclusion, recomputed from first principles ──────────
// The leaf is the canonicalized entry body as stored by the log; hashing
// is domain-separated: leaf = sha256(0x00 || bytes), node = sha256(0x01
// || left || right). No shortcuts: the path must consume EXACTLY its
// sibling list and land EXACTLY on the claimed root, or the proof fails.

const sha256 = (buf) => createHash('sha256').update(buf).digest();

export function rfc6962LeafHash(bytes) {
  return sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]));
}

export function rfc6962NodeHash(left, right) {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

/**
 * Walk an RFC 6962 audit path from a leaf to the tree root.
 * Throws on any structural violation (fail closed): index out of range,
 * path too short, or unconsumed siblings.
 */
export function rfc6962Root({ leafIndex, treeSize, leafHash, pathHex }) {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize) || leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) {
    throw new Error(`inclusion proof rejected: leafIndex ${leafIndex} outside tree of size ${treeSize}`);
  }
  const path = (pathHex ?? []).map((h) => {
    const b = Buffer.from(String(h), 'hex');
    if (b.length !== 32) throw new Error('inclusion proof rejected: sibling hash is not 32 bytes');
    return b;
  });
  let hash = Buffer.from(leafHash);
  let idx = leafIndex;
  let last = treeSize - 1;
  let used = 0;
  while (last > 0) {
    if (idx % 2 === 1) {
      if (used >= path.length) throw new Error('inclusion proof rejected: audit path too short');
      hash = rfc6962NodeHash(path[used++], hash);
    } else if (idx < last) {
      if (used >= path.length) throw new Error('inclusion proof rejected: audit path too short');
      hash = rfc6962NodeHash(hash, path[used++]);
    }
    idx = Math.floor(idx / 2);
    last = Math.floor(last / 2);
  }
  if (used !== path.length) throw new Error(`inclusion proof rejected: ${path.length - used} unconsumed sibling hash(es)`);
  return hash;
}

/**
 * Parse a Rekor checkpoint (signed note). Strict: origin line, decimal
 * tree size, base64 root hash, blank separator, then signature lines of
 * the form "— <name> <base64(4-byte key hint || DER sig)>". Throws on
 * any malformation — a checkpoint we cannot parse is a checkpoint we
 * refuse to trust.
 */
export function parseCheckpoint(text) {
  if (typeof text !== 'string') throw new Error('checkpoint rejected: not a string');
  const sep = text.indexOf('\n\n');
  if (sep < 0) throw new Error('checkpoint rejected: no blank-line separator');
  const noteBody = text.slice(0, sep + 1); // through the newline ending the root-hash line — the EXACT signed bytes
  const bodyLines = noteBody.split('\n');
  if (bodyLines.length < 4) throw new Error('checkpoint rejected: note body too short');
  const origin = bodyLines[0];
  if (!/^\S+ - \d+$/.test(origin)) throw new Error('checkpoint rejected: malformed origin line');
  if (!/^\d+$/.test(bodyLines[1])) throw new Error('checkpoint rejected: malformed tree-size line');
  const treeSize = Number(bodyLines[1]);
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) throw new Error('checkpoint rejected: tree size out of range');
  const rootHash = Buffer.from(bodyLines[2], 'base64');
  if (rootHash.length !== 32 || rootHash.toString('base64') !== bodyLines[2]) throw new Error('checkpoint rejected: root hash is not canonical 32-byte base64');
  const sigs = [];
  for (const line of text.slice(sep + 2).split('\n')) {
    if (!line) continue;
    const m = line.match(/^\u2014 (\S+) (\S+)$/);
    if (!m) throw new Error('checkpoint rejected: malformed signature line');
    const raw = Buffer.from(m[2], 'base64');
    if (raw.length < 5) throw new Error('checkpoint rejected: signature too short');
    sigs.push({ name: m[1], keyHintHex: raw.slice(0, 4).toString('hex'), signature: raw.slice(4) });
  }
  if (sigs.length === 0) throw new Error('checkpoint rejected: no signature lines');
  return { origin, treeSize, rootHashHex: rootHash.toString('hex'), noteBody, sigs };
}

/**
 * Verify a checkpoint's signed note against a pinned log public key.
 * The signature's 4-byte key hint must equal sha256(SPKI)[0..4] of the
 * pinned key AND the ECDSA signature must verify over the note body.
 * Returns { ok, reason?, treeSize, rootHashHex, origin }.
 */
export function verifyCheckpoint(text, logPublicKeyPem) {
  let cp;
  try { cp = parseCheckpoint(text); } catch (e) { return { ok: false, reason: e.message }; }
  let key;
  try { key = createPublicKey(logPublicKeyPem); } catch (e) { return { ok: false, reason: `pinned log key unusable: ${e.message}` }; }
  const hint = sha256(key.export({ type: 'spki', format: 'der' })).slice(0, 4).toString('hex');
  const candidates = cp.sigs.filter((s) => s.keyHintHex === hint);
  if (candidates.length === 0) return { ok: false, reason: `no checkpoint signature carries the pinned key's hint ${hint}` };
  for (const s of candidates) {
    try {
      if (cryptoVerify('sha256', Buffer.from(cp.noteBody, 'utf8'), key, s.signature)) {
        return { ok: true, treeSize: cp.treeSize, rootHashHex: cp.rootHashHex, origin: cp.origin };
      }
    } catch { /* try next candidate; fail closed below */ }
  }
  return { ok: false, reason: 'checkpoint signature INVALID over the signed note body' };
}

/**
 * Full offline inclusion check: entry bytes → leaf hash → audit path →
 * root, which must equal BOTH the proof's claimed root and the signed
 * checkpoint's root, with matching tree sizes.
 * Returns { ok, reason? }.
 */
export function verifyInclusionProof({ entryBodyBase64, proof, logPublicKeyPem }) {
  if (!proof || !Number.isInteger(proof.logIndex) || !Number.isInteger(proof.treeSize) || !Array.isArray(proof.hashes) || typeof proof.rootHash !== 'string' || typeof proof.checkpoint !== 'string') {
    return { ok: false, reason: 'inclusion proof missing required fields' };
  }
  const cp = verifyCheckpoint(proof.checkpoint, logPublicKeyPem);
  if (!cp.ok) return { ok: false, reason: cp.reason };
  if (cp.treeSize !== proof.treeSize) return { ok: false, reason: `tree size mismatch: proof says ${proof.treeSize}, signed checkpoint says ${cp.treeSize}` };
  if (cp.rootHashHex !== proof.rootHash) return { ok: false, reason: 'root hash mismatch: proof root differs from the signed checkpoint root' };
  let computed;
  try {
    const leaf = rfc6962LeafHash(Buffer.from(entryBodyBase64, 'base64'));
    computed = rfc6962Root({ leafIndex: proof.logIndex, treeSize: proof.treeSize, leafHash: leaf, pathHex: proof.hashes });
  } catch (e) {
    return { ok: false, reason: e.message };
  }
  if (computed.toString('hex') !== cp.rootHashHex) return { ok: false, reason: 'audit path does NOT land on the signed root — entry not proven in this tree' };
  return { ok: true };
}

/** Signed witness receipt body (pure; IO and network live in bin/). */
export function buildWitnessBody({ chain, rekor, inclusion, nowIso }) {
  const body = {
    kind: 'szl-quant-witness',
    generatedAtIso: nowIso,
    chain: { seq: chain.seq, runDir: chain.runDir, file: chain.file, sha256: chain.sha256 },
    rekor: {
      server: rekor.server,
      uuid: rekor.uuid,
      logIndex: rekor.logIndex,
      logID: rekor.logID,
      integratedTime: rekor.integratedTime,
      entryBodyBase64: rekor.entryBodyBase64,
      signedEntryTimestampBase64: rekor.signedEntryTimestampBase64,
    },
    labels: {
      anchor: 'REPORTED',
      note: 'rekor integration data is an external service statement; its SET is offline-verifiable against the pinned rekor public key',
    },
    note: 'external witness: this sealed chain head is anchored in a public append-only transparency log — deleting the ledger does not delete the anchor',
    limits: [
      'protects only witnessed heads; coverage gaps (rekor outages) are counted, not hidden',
      'an anchor proves the head bytes existed no later than integratedTime — for backfilled links that is later than sealing',
    ],
  };
  if (inclusion) {
    body.rekor.inclusionProof = {
      logIndex: inclusion.logIndex,       // leaf index within the active shard tree (NOT the global logIndex)
      treeSize: inclusion.treeSize,
      rootHash: inclusion.rootHash,
      hashes: [...inclusion.hashes],
      checkpoint: inclusion.checkpoint,
    };
    body.limits.push('inclusion is proven against the checkpoint captured at anchor time, not the log current tree head — checkpoint-to-checkpoint consistency is not verified offline');
  } else {
    body.limits.push('SET proves rekor accepted the entry at integratedTime; Merkle inclusion proof is not verified offline here');
  }
  return body;
}

/**
 * Which chain links still need a proof-bearing witness receipt?
 * A link is DONE only if some receipt for its seq carries an inclusion
 * proof; SET-only receipts (generation 1) stay valid but do not satisfy
 * --all. Pure: pass in the seqs found on disk.
 */
export function witnessTargets({ chainLinks, receipts, all }) {
  const proven = new Set(receipts.filter((r) => r.hasInclusionProof).map((r) => r.seq));
  const anchored = new Set(receipts.map((r) => r.seq));
  const sorted = [...chainLinks].sort((a, b) => a.seq - b.seq);
  if (all) return sorted.filter((l) => !proven.has(l.seq));
  const head = sorted[sorted.length - 1];
  if (!head) return [];
  return anchored.has(head.seq) ? [] : [head];
}

// ── RFC 6962 checkpoint CONSISTENCY, recomputed from first principles ────
// An inclusion proof pins one entry into one signed tree head. A
// consistency proof goes further: it proves the tree at an EARLIER
// checkpoint is a strict PREFIX of the tree at a LATER one — the log
// only appended between the two observations. A log that rewrote or
// forked history cannot produce a valid proof between two signed roots.
// NOTE: rekor tree sizes will exceed 2^31, so no 32-bit bitwise ops on
// sizes — parity via %, halving via Math.floor, power-of-two by division.

export const CONSISTENCY_FILE_RE = /^consistency_\d+-\d+_\d+\.receipt\.json$/;

export function consistencyFileName(firstSize, secondSize, nowMs) {
  return `consistency_${firstSize}-${secondSize}_${nowMs}.receipt.json`;
}

function isPowerOfTwo(n) {
  while (n % 2 === 0 && n > 1) n /= 2;
  return n === 1;
}

/**
 * Verify an RFC 6962 §2.1.4.2 consistency proof. Throws on ANY failure
 * (fail closed); returns true only when the earlier tree is proven a
 * prefix of the later tree.
 */
export function rfc6962VerifyConsistency({ firstSize, secondSize, firstRootHex, secondRootHex, proofHex }) {
  if (!Number.isSafeInteger(firstSize) || !Number.isSafeInteger(secondSize) || firstSize < 1 || secondSize < firstSize) {
    throw new Error(`consistency proof rejected: invalid tree sizes ${firstSize} -> ${secondSize}`);
  }
  const first = Buffer.from(String(firstRootHex), 'hex');
  const second = Buffer.from(String(secondRootHex), 'hex');
  if (first.length !== 32 || second.length !== 32) throw new Error('consistency proof rejected: root hash is not 32 bytes');
  const proof = (proofHex ?? []).map((h) => {
    const b = Buffer.from(String(h), 'hex');
    if (b.length !== 32) throw new Error('consistency proof rejected: proof hash is not 32 bytes');
    return b;
  });
  if (firstSize === secondSize) {
    if (proof.length !== 0) throw new Error('consistency proof rejected: same-size proof must be empty');
    if (!first.equals(second)) throw new Error('consistency proof rejected: same tree size but DIFFERENT roots — split-view evidence');
    return true;
  }
  const items = isPowerOfTwo(firstSize) ? [first, ...proof] : proof;
  if (items.length === 0) throw new Error('consistency proof rejected: empty proof for a grown tree');
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = items[0];
  let sr = items[0];
  for (let i = 1; i < items.length; i++) {
    if (sn === 0) throw new Error('consistency proof rejected: too many proof hashes');
    if (fn % 2 === 1 || fn === sn) {
      fr = rfc6962NodeHash(items[i], fr);
      sr = rfc6962NodeHash(items[i], sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = rfc6962NodeHash(sr, items[i]);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (!fr.equals(first)) throw new Error('consistency proof rejected: recomputed OLD root differs — the earlier checkpoint is not a prefix of the later tree');
  if (!sr.equals(second)) throw new Error('consistency proof rejected: recomputed NEW root differs — proof does not land on the later signed root');
  if (sn !== 0) throw new Error('consistency proof rejected: proof hashes exhausted before reaching the root');
  return true;
}

/** Signed consistency receipt body (pure; IO and network live in bin/). */
export function buildConsistencyBody({ origin, prev, next, proofHashes, nowIso }) {
  return {
    kind: 'szl-quant-witness-consistency',
    generatedAtIso: nowIso,
    origin,
    prev: { treeSize: prev.treeSize, rootHash: prev.rootHash, receiptFile: prev.receiptFile, receiptSha256: prev.receiptSha256 },
    next: { treeSize: next.treeSize, rootHash: next.rootHash, receiptFile: next.receiptFile, receiptSha256: next.receiptSha256 },
    proofHashes: [...(proofHashes ?? [])],
    labels: {
      proof: 'REPORTED',
      note: 'consistency hashes are an external service statement; they replay offline against the two signed checkpoint roots',
    },
    note: 'log consistency: the tree observed at the earlier checkpoint is proven a PREFIX of the tree at the later one — the log only appended between these two observations',
    limits: [
      'proves append-only growth between checkpoints THIS engine captured — a single observer, not cross-witness gossip',
      'meaningful only if both endpoint checkpoints verify against the pinned rekor key — the verifier enforces exactly that',
    ],
  };
}

/**
 * Which adjacent checkpoint pairs still need a consistency receipt?
 * Checkpoints are grouped by origin (log shard), deduped by tree size
 * (first observation wins; same-size disagreement is the verifier's
 * split-view check), sorted ascending, and paired adjacently. Pure.
 */
export function consistencyTargets({ checkpoints, covered }) {
  const done = new Set((covered ?? []).map((c) => `${c.origin}|${c.prevTreeSize}|${c.nextTreeSize}`));
  const byOrigin = new Map();
  for (const cp of checkpoints ?? []) {
    if (!byOrigin.has(cp.origin)) byOrigin.set(cp.origin, []);
    byOrigin.get(cp.origin).push(cp);
  }
  const targets = [];
  for (const [origin, list] of byOrigin) {
    const bySize = new Map();
    for (const cp of [...list].sort((a, b) => a.treeSize - b.treeSize)) {
      if (!bySize.has(cp.treeSize)) bySize.set(cp.treeSize, cp);
    }
    const uniq = [...bySize.values()];
    for (let i = 1; i < uniq.length; i++) {
      if (!done.has(`${origin}|${uniq[i - 1].treeSize}|${uniq[i].treeSize}`)) {
        targets.push({ origin, prev: uniq[i - 1], next: uniq[i] });
      }
    }
  }
  return targets;
}
