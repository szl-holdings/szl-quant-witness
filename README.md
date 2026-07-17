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

## Maturity & horizon

**This repo is young.** Observation start: `2026-07-16T20:33:37Z` (first commit); first published observation `2026-07-16T20:35:37Z`. Cadence: scheduled every 6h, offset ~3h from the engine's own schedule (`.github/workflows/observe.yml`), plus `workflow_dispatch` for manual runs. As of this writing the `observations` branch holds a handful of entries spanning under a day.

What that means, stated plainly:

- The cross-witness **signal** — a second vantage point independently re-deriving the same Rekor checkpoints and replaying the same consistency proof — strengthens with **observation history**, not with any single observation. One clean `PREFIX_OK` says the two vantage points agreed once; it says nothing about resilience to an outage, a delayed schedule, or a log event that only shows up between scheduled runs.
- Until a meaningful horizon accumulates (weeks of unbroken cadence, multiple log-checkpoint growth cycles, at least one exercised failure path), this observer's output should be cited as **REPORTED single-operator corroboration** — a second script, key, and schedule inside the same GitHub org and under the same maintainer — **not independent third-party verification**. Both repos still share one operator; that is stated in every observation (`limits[]`) and in `szl-quant`'s own README, and this section does not relax it.
- No amount of elapsed time upgrades this into proof of anything beyond what the RFC 6962 math itself proves (checkpoint signatures, inclusion, consistency). It only makes the *absence of a missed or failed observation* more informative — a long, unbroken run of `PREFIX_OK`/`ROOTS_EQUAL` with no gaps is evidence the schedule and signing path are healthy, not evidence of predictive edge, trading performance, or "true" independence.
- Gaps count against maturity, not around it: missed runs, `workflow_dispatch` backfills, and any non-`PREFIX_OK`/`ROOTS_EQUAL` verdict are visible in `OBSERVATIONS.md`'s append-only history and in this repo's own Actions run log — nothing here is trimmed to look cleaner than it is.

Practically: cite this repo today as "a second script, in the same org, corroborating the ledger head — REPORTED, single-operator" and revisit that language as real history accumulates. It does not become "independent third-party verification" merely by staying up.

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
| `.github/workflows/observe.yml` | every 6h, offset from the engine's schedule; SHA-pinned actions; a failing/alarming verdict turns the run red (non-zero exit) |
| `.github/workflows/ci.yml` | on every push/PR to `main`: syntax-checks `observe.mjs` and confirms the vendored primitives still match their `VENDOR.md` sha256 pins — catches a broken or silently-drifted commit before the next scheduled run hits it |

<sub>SZL Holdings · [a-11-oy.com](https://a-11-oy.com) · Doctrine v11 · REPORTED observations, replayed offline before signing · Apache-2.0 · **paper-only estate, not financial advice**</sub>
