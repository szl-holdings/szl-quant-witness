/**
 * canon.mjs — SZL doctrine constants (Doctrine v11). LAW for this engine.
 *
 * Honesty labels: every displayed/emitted value carries exactly one.
 * Never invent numbers. Empty values get honest labeled empties.
 */

export const LABELS = Object.freeze({
  LIVE: 'LIVE',               // real-time, verified at source
  MEASURED: 'MEASURED',       // observed with evidence (e.g. backtest on real history)
  REPORTED: 'REPORTED',       // external feed, unverified by us
  MODELED: 'MODELED',         // synthetic / inferred (e.g. cost model)
  HEURISTIC: 'HEURISTIC',     // rule-based
  DEMO: 'DEMO',               // staged (amber)
  UNAVAILABLE: 'UNAVAILABLE', // missing (red) — carries NO value
});

/** Abstention states — carry NO value, ever. */
export const ABSTENTIONS = Object.freeze(['NOT-RUN', 'NOT-MEASURED', 'NOT-TESTED']);

/** Trust ceiling — no confidence/conviction may exceed this. Never 1.0. */
export const TRUST_CEILING = 0.97;

/**
 * Locked-proven canonical set — EXACTLY 8, machine-enforced upstream by the
 * no-axiom Lean theorem `locked_count_eight` (szl-holdings/lutar-lean).
 * The F-numbering is lutar-lean's corpus. This engine's local formula
 * implementations are NOT asserted to map onto these F-ids (UNKNOWN — never
 * fabricated). The engine NEVER claims its signals are "proven".
 */
export const LOCKED_PROVEN_FORMULA_IDS = Object.freeze([
  'F1', 'F4', 'F7', 'F11', 'F12', 'F18', 'F19', 'F22',
]);

/** Λ status — Conjecture 1 (OPEN). Never 'theorem'. Roll-ups are ADVISORY only. */
export const LAMBDA_STATUS = 'Conjecture 1 (open) — uniqueness unproven; Λ roll-ups are ADVISORY only, never proven trust';

/** Gate verdicts. A BLOCKED verdict is emitted as BLOCKED — never flipped. */
export const VERDICTS = Object.freeze({ ALLOWED: 'ALLOWED', BLOCKED: 'BLOCKED' });

/** Engine posture — structurally locked. There is no execution code path. */
export const POSTURE = Object.freeze({
  mode: 'ADVISORY_PAPER_ONLY',
  execution: false,           // no order routing exists in this codebase
  custody: false,             // no wallet/exchange keys are read or stored
  financialAdvice: false,     // research output only
  provenTrust: false,         // structurally locked false (govsign pattern)
});

/** Clamp a confidence-like score to [0, TRUST_CEILING]. */
export function capTrust(x) {
  if (!Number.isFinite(x)) return null; // honest: no value
  return Math.min(Math.max(x, 0), TRUST_CEILING);
}

/** A labeled value. Label must be a canon label; UNAVAILABLE carries no value. */
export function labeled(value, label, note) {
  if (!Object.values(LABELS).includes(label)) throw new Error(`non-canon label: ${label}`);
  if (label === LABELS.UNAVAILABLE) return note ? { label, note } : { label };
  if (value === undefined || value === null) throw new Error(`label ${label} requires a value; use UNAVAILABLE for missing data`);
  return note ? { value, label, note } : { value, label };
}

/** Honest empty for a missing feed/value. */
export function unavailable(note) {
  return labeled(undefined, LABELS.UNAVAILABLE, note);
}
