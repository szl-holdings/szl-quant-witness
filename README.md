# szl-quant-witness — the second observer

**Cross-witness gossip for the [szl-quant](https://github.com/szl-holdings/szl-quant) ledger (generation 5).** Advisory research estate, paper-only, not financial advice.

Every szl-quant witness receipt states the same residual limit: *one observer, no cross-witness gossip*. This repo is the answer — an independent scheduled vantage point that:

1. clones the public `ledger` branch and **re-verifies the newest head binding itself** (chain-file sha256),
2. verifies the checkpoint the engine captured, under its own pinned Rekor key,
3. fetches Rekor's **live** checkpoint as *this observer* sees it, verifies the signed note,
4. **replays the RFC 6962 consistency proof offline before signing** — proving (or refusing to pretend) that the engine's anchored history is a prefix of the tree this observer sees,
5. publishes a DSSE-signed observation (`observations/obs_*.observation.json`, ed25519, key `keys/observer_pubkey.json`).

A split view — Rekor showing this observer a different history than it showed the engine — becomes **signed evidence** with an alarming verdict (`SPLIT_VIEW`, `LOG_REGRESSED`, `LEDGER_BINDING_MISMATCH`) and a red workflow run, not an invisible possibility.

## Honesty labels & limits

Observations are **REPORTED**: network reads of a public git remote and the Rekor API at observation time; every checkable claim (note signatures, consistency proof) is replayed offline *before* signing. Stated plainly: both repos live in one GitHub org under one maintainer — this adds a second vantage point, schedule, and key, **not** a second operator. The Rekor pin is shared with the observed repo; a wrong pin blinds both observers but cannot forge Rekor's signatures.

## Verify an observation

Each observation is a standard DSSE envelope over an in-toto Statement. Independent verification (including cross-checking observations against the engine's own witness receipts) ships in szl-quant's `verify/verify.mjs` — see that repo's README. Quick standalone signature check:

```bash
node --input-type=module -e "
import { verifyEnvelope } from './vendor/szl-quant/dsse.mjs';
import { loadPublicKeyFromSpkiBase64 } from './vendor/szl-quant/keys.mjs';
import { readFileSync } from 'node:fs';
const pin = JSON.parse(readFileSync('keys/observer_pubkey.json', 'utf8'));
const env = JSON.parse(readFileSync(process.argv[1], 'utf8'));
const r = verifyEnvelope(env, loadPublicKeyFromSpkiBase64(pin.publicKeySpkiBase64));
console.log(r.ok ? 'OK ' + r.payload.predicate.summary.verdict : 'FAIL ' + r.reason);
" observations/obs_0013_*.observation.json
```

## Repo map

| path | what |
|---|---|
| `observe.mjs` | the observer — clone, re-verify, live checkpoint, consistency replay, sign |
| `observations` branch | signed gossip observations + `OBSERVATIONS.md` index (append-only data branch — same convention as szl-quant's `ledger` branch; `main` is code, PR-gated) |
| `keys/observer_pubkey.json` | observer's public key (private key lives ONLY in this repo's Actions secret) |
| `keys/rekor_pubkey.pem` | pinned Rekor public key (same pin as szl-quant — stated limit) |
| `vendor/szl-quant/` | pinned primitives from the engine repo (`VENDOR.md` has the commit + hashes) |
| `.github/workflows/observe.yml` | every 6h, offset from the engine's schedule; SHA-pinned actions |

<sub>SZL Holdings · [a-11-oy.com](https://a-11-oy.com) · Doctrine v11 · REPORTED observations, replayed offline before signing · Apache-2.0 · **paper-only estate, not financial advice**</sub>
