/**
 * RFC 8785 JSON Canonicalization Scheme (JCS). Zero dependencies.
 *
 * Nimbus Foundation NF-WP-1 §14 (no npm, no build step, web-standard APIs only).
 *
 * Why this exists at all: an EdDSA signature is a signature over *bytes*. A Consent
 * Grant is a JSON object. Unless the issuer and every verifier serialise that object to
 * byte-for-byte identical output, the signature is meaningless — it will verify for the
 * issuer and fail for everyone else, or worse, two different objects will produce the
 * same bytes and a signature over one will authenticate the other. `JSON.stringify` is
 * not sufficient: it preserves property insertion order, so the same grant reconstructed
 * from a D1 row in a different column order canonicalises differently.
 *
 * The design posture here is *reject, never guess*. Every case where a JSON-ish
 * JavaScript value has no faithful canonical form is a thrown `JcsError`, not a
 * best-effort serialisation. The reason is specific rather than fastidious: silent
 * mis-canonicalisation is a signature-forgery surface. `JSON.stringify` drops
 * `undefined` properties, turns array holes into `null`, coerces `Date` via `toJSON`,
 * invokes getters, and ignores symbol keys. Every one of those is a case where the
 * bytes that get signed differ from the object the caller believes they signed, which
 * means an attacker who controls a dropped or coerced field controls a difference
 * between what was authorised and what was authenticated. Loud failure is the only safe
 * behaviour.
 *
 * Two deliberate deviations from strict RFC 8785, both in the fail-closed direction:
 *
 *  1. Negative zero. RFC 8785 inherits the ECMAScript number serialisation, under which
 *     `-0` becomes `"0"`. That is a lossy normalisation: two distinct inputs produce one
 *     output, so a caller cannot round-trip and cannot tell which value was signed. We
 *     throw instead and require the caller to normalise deliberately.
 *  2. Lone surrogates. A JavaScript string is a sequence of UTF-16 code units and may
 *     contain an unpaired surrogate, which is not a Unicode scalar value and therefore
 *     has no UTF-8 encoding. RFC 8785 output is defined as UTF-8 bytes. Historic ES6
 *     `JSON.stringify` emitted such code units raw (producing invalid UTF-8);
 *     ES2019 well-formed stringify escapes them as `\udXXX`. Both behaviours exist in
 *     the wild, so the same input can canonicalise two ways depending on runtime age.
 *     We refuse the input rather than pick a winner.
 *
 * Everything else follows RFC 8785 exactly: object keys sorted by UTF-16 code unit,
 * no insignificant whitespace, the seven two-character escapes, `\u00xx` lowercase for
 * remaining C0 controls, and ECMAScript `Number::toString` for numbers.
 */

/**
 * Recursion ceiling. Canonicalisation is recursive, so unbounded nesting is a stack
 * overflow reachable from any untrusted JSON body — a crash, not a wrong answer, but
 * still an availability bug in a Worker that verifies grants for other people.
 * A Consent Grant nests three levels; 64 is generous by two orders of magnitude.
 */
const MAX_DEPTH = 64

/**
 * The integer-safety limit: 2^53 - 1.
 *
 * IEEE-754 doubles represent every integer up to this value exactly, and none above it.
 * Past the limit consecutive integers collapse onto the same double, so two distinct
 * values canonicalise to the same bytes — `9007199254740993` and `9007199254740992`
 * both serialise as `9007199254740992`. RFC 8259 §6 already warns that interoperable
 * implementations should expect no more precision than this, and RFC 8785's number
 * rules inherit it.
 *
 * Consequence for this codebase: any integer whose value is security-relevant — Unix
 * timestamps, delegation depth, pseudonym epochs, monetary quantities if there ever are
 * any — must be inside the limit, or an attacker can supply a distinct value that
 * canonicalises identically to an authorised one. Guard those with `assertSafeInteger`.
 */
export const MAX_JCS_SAFE_INTEGER = Number.MAX_SAFE_INTEGER

/** Thrown for every input this module refuses to canonicalise. */
export class JcsError extends Error {
  constructor(message) {
    super(message)
    this.name = 'JcsError'
  }
}

/** RFC 8785 §3.2.2.2: the only escapes that are two characters rather than \u00xx. */
const TWO_CHAR_ESCAPES = Object.freeze({
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x22: '\\"',
  0x5c: '\\\\',
})

/**
 * Canonicalise a JSON value to an RFC 8785 string.
 *
 * Accepts only the JSON data model: `null`, boolean, finite non-negative-zero number,
 * well-formed string, array, and plain object. Anything else throws.
 *
 * @param {unknown} value
 * @returns {string} canonical JSON. Sign the UTF-8 encoding of this — see
 *          `canonicalizeToBytes`, which is the form the RFC actually defines.
 */
export function canonicalize(value) {
  return write(value, new Set(), 0, '$')
}

/**
 * Canonicalise and UTF-8 encode. This is the byte string RFC 8785 specifies and the
 * only thing that should ever be handed to a signing or hashing primitive; going
 * through the JS string and letting some other layer choose an encoding is how
 * implementations end up signing UTF-16.
 *
 * @param {unknown} value
 * @returns {Uint8Array}
 */
export function canonicalizeToBytes(value) {
  return new TextEncoder().encode(canonicalize(value))
}

/**
 * UTF-16 code-unit ordering, exported because object-key order and any *array* whose
 * order must be canonical have to agree. JCS gives arrays no sort — array order is
 * semantically significant — so a producer that wants one canonical form for an
 * unordered set has to sort the set itself, with exactly this comparator.
 *
 * Not `localeCompare`: that is locale-dependent and would make the canonical form of a
 * grant depend on the server's ICU data.
 */
export function compareCodeUnits(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    throw new JcsError('compareCodeUnits operates on strings')
  }
  // `<` on JS strings is defined as an unsigned UTF-16 code-unit comparison, which is
  // precisely RFC 8785 §3.2.3. Note this is *not* code-point order: U+FFFD sorts before
  // a supplementary-plane character under code points and after it under code units.
  // The RFC chose code units, so we do too.
  if (a === b) return 0
  return a < b ? -1 : 1
}

/**
 * Require an integer inside the JCS/IEEE-754 safe range.
 *
 * @param {unknown} value
 * @param {string} label field name, for the error message
 * @returns {number} the value, unchanged
 */
export function assertSafeInteger(value, label = 'value') {
  if (typeof value !== 'number') {
    throw new JcsError(`${label} must be a number, got ${typeof value}`)
  }
  if (!Number.isInteger(value)) {
    throw new JcsError(`${label} must be an integer, got ${String(value)}`)
  }
  if (!Number.isSafeInteger(value)) {
    throw new JcsError(
      `${label} = ${String(value)} exceeds the JCS integer-safety limit of ` +
        `±${MAX_JCS_SAFE_INTEGER} (2^53 - 1); beyond it distinct integers canonicalise ` +
        'to identical bytes, so a signature over one would authenticate the other',
    )
  }
  return value
}

// ---------------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------------

/**
 * `ancestors` holds only the containers on the current path, so a repeated *sibling*
 * reference (legal, and common when a grant reuses a frozen constant) is fine while a
 * true cycle is caught. A visited-set that never shrank would reject the former.
 */
function write(v, ancestors, depth, path) {
  if (depth > MAX_DEPTH) {
    throw new JcsError(`structure nests deeper than ${MAX_DEPTH} levels at ${path}`)
  }

  if (v === null) return 'null'

  const t = typeof v
  switch (t) {
    case 'boolean':
      return v ? 'true' : 'false'
    case 'number':
      return serializeNumber(v, path)
    case 'string':
      return serializeString(v, path)
    case 'undefined':
      throw new JcsError(
        `undefined at ${path} has no JSON representation; JSON.stringify would silently ` +
          'drop it, so the signed bytes would not describe the object you passed',
      )
    case 'bigint':
      throw new JcsError(
        `BigInt at ${path} cannot be canonicalised: JSON has one numeric type and RFC 8785 ` +
          'serialises it as an IEEE-754 double, which cannot hold an arbitrary-precision ' +
          'integer. Encode it as a string and document the encoding',
      )
    case 'symbol':
      throw new JcsError(`symbol at ${path} has no JSON representation`)
    case 'function':
      throw new JcsError(`function at ${path} has no JSON representation`)
    case 'object':
      break
    default:
      throw new JcsError(`unsupported type "${t}" at ${path}`)
  }

  if (ancestors.has(v)) {
    throw new JcsError(`cyclic reference at ${path}: canonicalisation would not terminate`)
  }
  ancestors.add(v)
  try {
    return Array.isArray(v)
      ? serializeArray(v, ancestors, depth, path)
      : serializeObject(v, ancestors, depth, path)
  } finally {
    ancestors.delete(v)
  }
}

/**
 * RFC 8785 §3.2.2.3: ECMAScript `Number::toString`, which `String(n)` is exactly.
 * Hand-rolling shortest-round-trip double formatting would be the single most likely
 * place to introduce an interoperability bug, so we don't.
 */
function serializeNumber(n, path) {
  if (Number.isNaN(n)) {
    throw new JcsError(`NaN at ${path} is not a JSON number and has no canonical form`)
  }
  if (!Number.isFinite(n)) {
    throw new JcsError(`${n > 0 ? 'Infinity' : '-Infinity'} at ${path} is not a JSON number`)
  }
  if (Object.is(n, -0)) {
    throw new JcsError(
      `negative zero at ${path}: RFC 8785 would serialise it as "0", which is lossy — ` +
        'the caller cannot tell afterwards which value was signed. Normalise to 0 ' +
        'explicitly if that is what you mean',
    )
  }
  return String(n)
}

function serializeString(s, path) {
  let out = '"'
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i)

    // Surrogate handling first: a well-formed pair is emitted verbatim (TextEncoder
    // turns it into the correct 4-byte UTF-8 sequence), an unpaired unit is refused.
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new JcsError(
          `unpaired high surrogate U+${hex4(c)} at ${path} (index ${i}): not a Unicode ` +
            'scalar value, so it has no UTF-8 encoding and no unambiguous canonical form',
        )
      }
      out += s[i] + s[i + 1]
      i += 1
      continue
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
      throw new JcsError(
        `unpaired low surrogate U+${hex4(c)} at ${path} (index ${i}): not a Unicode ` +
          'scalar value, so it has no UTF-8 encoding and no unambiguous canonical form',
      )
    }

    const two = TWO_CHAR_ESCAPES[c]
    if (two !== undefined) {
      out += two
      continue
    }
    // Remaining C0 controls only. Everything else — including U+007F and all non-ASCII —
    // is emitted literally; RFC 8785 does not \u-escape what UTF-8 can carry.
    if (c < 0x20) {
      out += `\\u${hex4(c)}`
      continue
    }
    out += s[i]
  }
  return `${out}"`
}

function serializeArray(arr, ancestors, depth, path) {
  // Holes and non-index own properties are both silent-drop surfaces: JSON.stringify
  // renders a hole as `null` and ignores `arr.note = 'x'` entirely.
  if (Object.getOwnPropertyNames(arr).length !== arr.length + 1) {
    throw new JcsError(
      `array at ${path} carries own properties other than its indices and length; ` +
        'JSON serialisation would drop them',
    )
  }
  const parts = []
  for (let i = 0; i < arr.length; i += 1) {
    if (!Object.hasOwn(arr, i)) {
      throw new JcsError(
        `hole at ${path}[${i}]: a sparse array serialises the gap as null, which is a ` +
          'value the caller never wrote',
      )
    }
    parts.push(write(arr[i], ancestors, depth + 1, `${path}[${i}]`))
  }
  return `[${parts.join(',')}]`
}

function serializeObject(obj, ancestors, depth, path) {
  const proto = Object.getPrototypeOf(obj)
  if (proto !== Object.prototype && proto !== null) {
    // Date, Map, Set, RegExp, typed arrays, boxed primitives and class instances all
    // land here. Each has either no JSON form or a `toJSON` coercion, and coercion is
    // exactly the guessing this module refuses to do. Convert explicitly at the call
    // site so the encoding is visible in the code that owns the meaning.
    const name = obj?.constructor?.name ?? 'exotic object'
    throw new JcsError(
      `only plain objects can be canonicalised; got ${name} at ${path}. Convert it to ` +
        'plain JSON data explicitly rather than relying on toJSON coercion',
    )
  }

  if (Object.getOwnPropertySymbols(obj).length > 0) {
    throw new JcsError(
      `object at ${path} has symbol-keyed properties, which JSON serialisation ignores ` +
        'silently',
    )
  }

  const descriptors = Object.getOwnPropertyDescriptors(obj)
  for (const [key, d] of Object.entries(descriptors)) {
    if (!d.enumerable) {
      throw new JcsError(
        `non-enumerable property "${key}" at ${path} would be dropped by JSON serialisation`,
      )
    }
    if (!('value' in d)) {
      throw new JcsError(
        `accessor property "${key}" at ${path}: canonicalisation must be a pure function ` +
          'of data, and invoking a getter makes the signed bytes depend on side-effecting code',
      )
    }
  }

  const keys = Object.keys(obj).sort(compareCodeUnits)
  const parts = []
  for (const key of keys) {
    const k = serializeString(key, `${path} (key)`)
    const v = write(obj[key], ancestors, depth + 1, `${path}.${key}`)
    parts.push(`${k}:${v}`)
  }
  return `{${parts.join(',')}}`
}

/** Lowercase four-digit hex, as RFC 8785 requires for \u escapes. */
function hex4(codeUnit) {
  return codeUnit.toString(16).padStart(4, '0')
}
