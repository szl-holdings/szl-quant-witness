/**
 * canonical-json.mjs — deterministic JSON: recursively sorted object keys,
 * no whitespace. Same convention as the forge/khipu receipt `canonical`
 * field (sorted-key JSON.stringify). Arrays keep their order.
 *
 * Numbers: serialized via JSON.stringify (ECMAScript shortest round-trip).
 * Receipts avoid floating ambiguity by storing decimals as strings where
 * exactness matters (prices, PnL) — see portfolio.mjs.
 */

export function canonicalize(value) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new Error('canonical JSON forbids non-finite numbers');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${canonicalize(v)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`cannot canonicalize type ${typeof value}`);
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}
