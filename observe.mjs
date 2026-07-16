#!/usr/bin/env node
/**
 * observe.mjs — the second observer (cross-witness gossip, generation 5).
 *
 * szl-quant's witness receipts state their residual limit plainly: one
 * observer, one schedule, one vantage point. This repo is the second
 * vantage point: on its own schedule, under its own signing identity, it
 * clones the szl-quant ledger, re-verifies the newest head binding with
 * its own hands, captures Rekor's live checkpoint as IT sees it, replays
 * the consistency proof from the engine's captured checkpoint to the live
 * one BEFORE signing, and publishes a signed observation. A split view —
 * Rekor showing this observer a different history than it showed the
 * engine — becomes signed, timestamped evidence instead of an invisible
 * possibility.
 *
 * Honesty: REPORTED (network reads of a public git remote + the Rekor
 * API); every checkable claim is replayed offline before signing. Both
 * repos share one GitHub org and one maintainer — this narrows the
 * single-process vantage limit, NOT the single-operator limit, and says so.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, appendFileSync, rmSync } from 'node:fs';
import { createHash, createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { canonicalBytes } from './vendor/szl-quant/canonical-json.mjs';
import { signEnvelope, verifyEnvelope } from './vendor/szl-quant/dsse.mjs';
import { loadPrivateKey, keyIdFromPublicKey } from './vendor/szl-quant/keys.mjs';
import { verifyCheckpoint, rfc6962VerifyConsistency, WITNESS_FILE_RE, REKOR_SERVER } from './vendor/szl-quant/witness.mjs';

const IN_TOTO_STATEMENT = 'https://in-toto.io/Statement/v1';
export const PREDICATE_OBSERVATION = 'https://szl.holdings/quant/gossip-observation/v1';
export const OBS_FILE_RE = /^obs_(\d{4})_\d+\.observation\.json$/;
const LEDGER_REPO = 'https://github.com/szl-holdings/szl-quant.git';
const HERE = new URL('.', import.meta.url).pathname;

const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');
const sh = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8' }).trim();

async function main() {
  const keyPath = process.env.SZL_OBSERVER_KEY;
  const privateKey = keyPath ? loadPrivateKey(keyPath) : null;
  if (!privateKey) {
    console.error('OBSERVER UNAVAILABLE: SZL_OBSERVER_KEY missing — refusing to observe unsigned (absence is honest)');
    process.exit(2);
  }
  const publicKey = createPublicKey(privateKey);
  const rekorPin = readFileSync(join(HERE, 'keys/rekor_pubkey.pem'), 'utf8');

  // 1 — independent shallow clone of the public ledger branch
  const work = join(HERE, '.work-ledger');
  rmSync(work, { recursive: true, force: true });
  sh('git', ['clone', '--quiet', '--depth', '1', '-b', 'ledger', LEDGER_REPO, work]);
  const ledgerCommit = sh('git', ['-C', work, 'rev-parse', 'HEAD']);

  // 2 — newest engine witness receipt (greatest seq, newest capture wins)
  const wDir = join(work, 'witness');
  const cand = readdirSync(wDir).filter((n) => WITNESS_FILE_RE.test(n));
  if (!cand.length) throw new Error('no witness receipts in the ledger — nothing to observe');
  let wName = null; let bestSeq = -1; let bestTs = -1;
  for (const n of cand) {
    const m = /^witness_(\d{4})_(\d+)\./.exec(n);
    const s = Number(m[1]); const t = Number(m[2]);
    if (s > bestSeq || (s === bestSeq && t > bestTs)) { wName = n; bestSeq = s; bestTs = t; }
  }
  const wBytes = readFileSync(join(wDir, wName));
  const wSha = sha256Hex(wBytes);
  const st = JSON.parse(Buffer.from(JSON.parse(wBytes.toString('utf8')).payload, 'base64').toString('utf8'));
  const summary = st.predicate?.summary;
  if (summary?.kind !== 'szl-quant-witness') throw new Error(`unexpected witness receipt kind: ${summary?.kind}`);
  const seq = summary.chain.seq;

  // 3 — re-verify the head binding with our own hands
  const chainPath = join(work, 'ledger', summary.chain.runDir, summary.chain.file);
  const chainShaActual = existsSync(chainPath) ? sha256Hex(readFileSync(chainPath)) : null;
  const chainBindingVerified = chainShaActual === summary.chain.sha256;

  // 4 — the checkpoint the ENGINE captured, verified under our rekor pin
  const eCp = verifyCheckpoint(summary.rekor.inclusionProof.checkpoint, rekorPin);
  if (!eCp.ok) throw new Error(`engine-captured checkpoint failed note verification: ${eCp.reason}`);

  // 5 — the checkpoint WE see live, verified before anything is signed
  const logRes = await fetch(`${REKOR_SERVER}/api/v1/log`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
  if (!logRes.ok) {
    console.error(`OBSERVER UNAVAILABLE: rekor /api/v1/log HTTP ${logRes.status} — no observation written (absence is honest)`);
    process.exit(3);
  }
  const log = await logRes.json();
  const lCp = verifyCheckpoint(log.signedTreeHead, rekorPin);
  if (!lCp.ok) {
    console.error(`OBSERVER UNAVAILABLE: live checkpoint failed note verification (${lCp.reason}) — refusing to sign an unverified claim`);
    process.exit(3);
  }

  // 6 — gossip: is the engine's anchored history a prefix of what WE see?
  let verdict; let consistency;
  if (eCp.origin !== lCp.origin) {
    verdict = 'SHARD_ROTATED';
    consistency = { mode: 'none', reason: `engine shard ${eCp.origin} vs live shard ${lCp.origin} — no consistency path across shards` };
  } else if (lCp.treeSize < eCp.treeSize) {
    verdict = 'LOG_REGRESSED';
    consistency = { mode: 'none', reason: 'live tree is SMALLER than the engine-captured checkpoint — split-view evidence' };
  } else if (lCp.treeSize === eCp.treeSize) {
    verdict = lCp.rootHashHex === eCp.rootHashHex ? 'ROOTS_EQUAL' : 'SPLIT_VIEW';
    consistency = { mode: 'same-size', firstSize: eCp.treeSize, lastSize: lCp.treeSize, proofHashes: [] };
  } else {
    const treeID = eCp.origin.split(' - ')[1];
    const url = `${REKOR_SERVER}/api/v1/log/proof?firstSize=${eCp.treeSize}&lastSize=${lCp.treeSize}&treeID=${treeID}`;
    const pRes = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
    if (!pRes.ok) {
      console.error(`OBSERVER UNAVAILABLE: rekor consistency proof HTTP ${pRes.status} — no observation written (absence is honest)`);
      process.exit(3);
    }
    const proofHashes = (await pRes.json()).hashes;
    try {
      rfc6962VerifyConsistency({ firstSize: eCp.treeSize, secondSize: lCp.treeSize, firstRootHex: eCp.rootHashHex, secondRootHex: lCp.rootHashHex, proofHex: proofHashes });
      verdict = 'PREFIX_OK';
    } catch (e) {
      verdict = 'SPLIT_VIEW';
      consistency = { mode: 'replay-failed', firstSize: eCp.treeSize, lastSize: lCp.treeSize, proofHashes, reason: e.message };
    }
    consistency ??= { mode: 'replayed-before-signing', firstSize: eCp.treeSize, lastSize: lCp.treeSize, proofHashes };
  }
  if (!chainBindingVerified && (verdict === 'PREFIX_OK' || verdict === 'ROOTS_EQUAL')) verdict = 'LEDGER_BINDING_MISMATCH';

  // 7 — signed observation (REPORTED, limits stated)
  const nowIso = new Date().toISOString();
  const body = {
    kind: 'szl-quant-gossip-observation',
    label: 'REPORTED',
    observedAtIso: nowIso,
    observer: {
      repo: 'szl-holdings/szl-quant-witness',
      keyId: keyIdFromPublicKey(publicKey),
      workflowRunId: process.env.GITHUB_RUN_ID ?? 'local',
    },
    ledger: {
      repo: 'szl-holdings/szl-quant', branch: 'ledger', commit: ledgerCommit,
      headSeq: seq, witnessFile: wName, witnessSha256: wSha,
      chainRunDir: summary.chain.runDir, chainFile: summary.chain.file,
      chainSha256: summary.chain.sha256, chainBindingVerified,
    },
    engineCheckpoint: { origin: eCp.origin, treeSize: eCp.treeSize, rootHex: eCp.rootHashHex, source: 'newest witness receipt inclusionProof.checkpoint', noteVerified: true },
    liveCheckpoint: { origin: lCp.origin, treeSize: lCp.treeSize, rootHex: lCp.rootHashHex, rawNote: log.signedTreeHead, noteVerified: true, fetchedAtIso: nowIso },
    consistency,
    verdict,
    limits: [
      'both repos live in one GitHub org under one maintainer — a second vantage point and key, NOT a second operator; stated, not hidden',
      'REPORTED: reads a public git remote and the Rekor API at observation time; checkpoint signatures and the consistency proof are replayed offline before signing',
      'the rekor public-key pin is shared with the observed repo: a wrong pin blinds both observers, but cannot forge Rekor note signatures',
    ],
    note: 'gossip observation: a split view between what Rekor shows this observer and what it showed the engine becomes signed evidence here',
  };
  const statement = {
    _type: IN_TOTO_STATEMENT,
    subject: [{ name: `szl-quant-witness/observation-seq-${seq}`, digest: { sha256: wSha } }],
    predicateType: PREDICATE_OBSERVATION,
    predicate: { summary: body },
  };
  canonicalBytes(statement); // refuse to sign anything non-canonicalizable
  const envelope = signEnvelope(statement, privateKey, publicKey);
  const self = verifyEnvelope(envelope, publicKey);
  if (!self.ok) throw new Error(`self-verification failed after signing: ${self.reason}`);

  mkdirSync(join(HERE, 'observations'), { recursive: true });
  const fname = `obs_${String(seq).padStart(4, '0')}_${Date.now()}.observation.json`;
  writeFileSync(join(HERE, 'observations', fname), JSON.stringify(envelope, null, 2) + '\n');
  const mdPath = join(HERE, 'OBSERVATIONS.md');
  if (!existsSync(mdPath)) writeFileSync(mdPath, '# Observations — second-observer gossip log\n\n| observed (UTC) | head seq | verdict | live tree size | file |\n|---|---|---|---|---|\n');
  appendFileSync(mdPath, `| ${nowIso} | ${seq} | ${verdict} | ${lCp.treeSize} | \`${fname}\` |\n`);
  writeFileSync(join(HERE, '.last-verdict'), verdict + '\n');
  rmSync(work, { recursive: true, force: true });
  console.log(`OBSERVATION ${verdict}  head seq ${seq} (ledger ${ledgerCommit.slice(0, 7)})  engine checkpoint ${eCp.treeSize} → live ${lCp.treeSize}  → observations/${fname}  [REPORTED, consistency replayed offline before signing]`);
}

main().catch((e) => { console.error('OBSERVER FAILED:', e.message); process.exit(1); });
