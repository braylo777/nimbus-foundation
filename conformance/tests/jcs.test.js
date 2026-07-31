/**
 * NF-5 conformance — RFC 8785 JSON canonicalisation. MODULE profile, over
 * `broker/src/jcs.js`.
 *
 * Nimbus Foundation NF-5 §4.3 (harness constraints), §5 NT-005 (lone surrogates),
 * §6 DD-001 (integer safety). NF-WP-1 §14.
 *
 * WHY THIS FILE IS AS PARANOID AS IT IS. An EdDSA signature is a signature over bytes; a
 * Consent Grant is an object. Every case where a JavaScript value has no faithful canonical
 * form is a case where the bytes that get signed differ from the object the caller believes
 * they signed — and an attacker who controls a dropped, coerced or reordered field controls
 * the difference between what was authorised and what was authenticated. So the assertions
 * here are overwhelmingly about REFUSAL, and each refusal names the silent-corruption path
 * it closes.
 *
 * The two deliberate deviations from strict RFC 8785 — negative zero and lone surrogates —
 * are tested as refusals rather than as serialisations, because both are places where the
 * RFC's own behaviour is lossy or runtime-dependent and picking a winner would mean signing
 * a value the caller cannot recover afterwards.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  JcsError,
  MAX_JCS_SAFE_INTEGER,
  assertSafeInteger,
  canonicalize,
  canonicalizeToBytes,
  compareCodeUnits,
} from '../../broker/src/jcs.js'

/** Build `n` nested arrays around a scalar. Depth of the scalar is `n`. */
function nest(n) {
  let v = 0
  for (let i = 0; i < n; i += 1) v = [v]
  return v
}

// ---------------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------------

test('[control] canonicalisation is independent of property insertion order', () => {
  // The motivating case is mundane and therefore likely: a grant reconstructed from a D1
  // row arrives with its columns in a different order than the object that was signed.
  const a = { b: 1, a: 2, c: 3 }
  const c = { c: 3, b: 1, a: 2 }
  const b = { a: 2, c: 3, b: 1 }
  assert.equal(canonicalize(a), '{"a":2,"b":1,"c":3}')
  assert.equal(canonicalize(a), canonicalize(b))
  assert.equal(canonicalize(b), canonicalize(c))
})

test('[control] canonicalisation is recursive and stable at every level', () => {
  const first = { z: { y: [1, { b: 2, a: 1 }], x: 'v' }, a: null }
  const second = { a: null, z: { x: 'v', y: [1, { a: 1, b: 2 }] } }
  assert.equal(canonicalize(first), '{"a":null,"z":{"x":"v","y":[1,{"a":1,"b":2}]}}')
  assert.equal(canonicalize(first), canonicalize(second))
})

test('[control] repeated calls on the same value are byte-identical', () => {
  const value = { grant: { fields: ['make', 'odometer_km'], depth: 2 }, ok: true }
  const once = canonicalize(value)
  for (let i = 0; i < 32; i += 1) assert.equal(canonicalize(value), once)
})

test('array order is significant and is never sorted', () => {
  // RFC 8785 gives arrays no sort because order carries meaning. A producer that wants one
  // canonical form for an unordered SET must sort the set itself — which is exactly why
  // `compareCodeUnits` is exported and why a grant's `fields` array is sorted at assembly.
  assert.equal(canonicalize([2, 1]), '[2,1]')
  assert.equal(canonicalize([1, 2]), '[1,2]')
  assert.notEqual(canonicalize([2, 1]), canonicalize([1, 2]))
  assert.equal(canonicalize([]), '[]')
  assert.equal(canonicalize({}), '{}')
})

test('[control] the JSON data model round-trips through JSON.parse', () => {
  const value = { a: [1, 'two', true, null, { b: 3.5 }], z: '' }
  assert.deepEqual(JSON.parse(canonicalize(value)), value)
})

// ---------------------------------------------------------------------------------
// Key ordering — UTF-16 code units, not code points, not locale
// ---------------------------------------------------------------------------------

test('object keys sort by UTF-16 code unit', () => {
  const obj = { z: 0, a: 0, A: 0, 0: 0, _: 0, '': 0 }
  assert.equal(canonicalize(obj), '{"":0,"0":0,"A":0,"_":0,"a":0,"z":0}')
})

test('code-unit order is NOT code-point order, and the RFC chose code units', () => {
  // U+FFFD is one code unit 0xFFFD. U+1F600 is the pair 0xD83D 0xDE00. Under CODE POINTS
  // U+FFFD (65533) sorts first; under CODE UNITS 0xD83D (55357) sorts first. RFC 8785 §3.2.3
  // specifies code units, so the astral key must come FIRST. Getting this backwards is
  // invisible until an implementation on the other side of the wire disagrees about which
  // bytes a signature covered.
  const obj = { '�': 1, '\u{1f600}': 2 }
  const out = canonicalize(obj)
  assert.ok(
    out.indexOf('\u{1f600}') < out.indexOf('�'),
    `astral key must precede U+FFFD under code-unit order: ${JSON.stringify(out)}`,
  )
  assert.equal(out, '{"\u{1f600}":2,"�":1}')
})

test('key ordering does not depend on locale collation', () => {
  // `localeCompare` would make the canonical form of a grant depend on the server's ICU
  // data — the same object canonicalising differently in two regions of the same fleet.
  const keys = ['z', 'a', 'A', 'Z', 'ä', 'ä', 'b', 'B']
  const obj = {}
  for (const k of keys) obj[k] = 0
  const expected = [...new Set(keys)].sort((x, y) => (x === y ? 0 : x < y ? -1 : 1))
  const emitted = [...canonicalize(obj).matchAll(/"((?:[^"\\]|\\.)*)":/g)].map((m) =>
    JSON.parse(`"${m[1]}"`),
  )
  assert.deepEqual(emitted, expected)
  assert.notDeepEqual(expected, [...new Set(keys)].sort((x, y) => x.localeCompare(y)))
})

test('compareCodeUnits is a total order agreeing with JS string comparison', () => {
  assert.equal(compareCodeUnits('a', 'b'), -1)
  assert.equal(compareCodeUnits('b', 'a'), 1)
  assert.equal(compareCodeUnits('a', 'a'), 0)
  assert.equal(compareCodeUnits('', 'a'), -1)
  assert.equal(compareCodeUnits('A', 'a'), -1)
  assert.equal(compareCodeUnits('make', 'make_2'), -1)
  assert.equal(compareCodeUnits('\u{1f600}', '�'), -1)

  const sample = ['odometer_km', 'make', 'dtc_codes', 'aggregation_window_s', 'zzz', '']
  const viaComparator = [...sample].sort(compareCodeUnits)
  const viaOperator = [...sample].sort((x, y) => (x === y ? 0 : x < y ? -1 : 1))
  assert.deepEqual(viaComparator, viaOperator)
})

test('compareCodeUnits refuses non-strings rather than coercing them', () => {
  for (const bad of [1, null, undefined, {}, [], true, Symbol('s'), 1n]) {
    assert.throws(() => compareCodeUnits('a', bad), JcsError)
    assert.throws(() => compareCodeUnits(bad, 'a'), JcsError)
  }
})

// ---------------------------------------------------------------------------------
// Numbers — RFC 8785 §3.2.2.3, ECMAScript Number::toString
// ---------------------------------------------------------------------------------

test('[control] numbers serialise as ECMAScript Number::toString', () => {
  const cases = [
    [0, '0'],
    [1, '1'],
    [-1, '-1'],
    [1.0, '1'],
    [1.5, '1.5'],
    [-1.5, '-1.5'],
    [0.1, '0.1'],
    [100, '100'],
    [1e21, '1e+21'],
    [1e-7, '1e-7'],
    [Number.MAX_SAFE_INTEGER, '9007199254740991'],
    [-Number.MAX_SAFE_INTEGER, '-9007199254740991'],
    [Number.MIN_VALUE, '5e-324'],
  ]
  for (const [input, expected] of cases) {
    assert.equal(canonicalize(input), expected, String(input))
    assert.equal(canonicalize(input), String(input), 'must be exactly String(n)')
  }
})

test('NaN and both infinities are refused: they are not JSON numbers', () => {
  // JSON.stringify renders all three as `null`, which is a value the caller never wrote and
  // which an attacker controlling one field could use to collide two different objects.
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalize(bad), JcsError, String(bad))
    assert.throws(() => canonicalize({ a: bad }), JcsError)
    assert.throws(() => canonicalize([bad]), JcsError)
  }
  assert.throws(() => canonicalize(NaN), /NaN at \$ is not a JSON number/)
  assert.throws(() => canonicalize(Infinity), /Infinity at \$ is not a JSON number/)
  assert.throws(() => canonicalize(-Infinity), /-Infinity at \$ is not a JSON number/)
})

test('negative zero is refused rather than normalised to "0"', () => {
  // Deliberate deviation from RFC 8785, in the fail-closed direction: the RFC's ECMAScript
  // number rules map -0 onto "0", so two distinct inputs produce one output and the caller
  // cannot tell afterwards which one was signed.
  assert.throws(() => canonicalize(-0), JcsError)
  assert.throws(() => canonicalize(-0), /negative zero/)
  assert.throws(() => canonicalize({ depth: -0 }), /negative zero at \$\.depth/)
  assert.throws(() => canonicalize([-0]), /negative zero at \$\[0\]/)
  assert.equal(canonicalize(0), '0', 'positive zero is fine')
  assert.equal(canonicalize(0 * -1 + 0), '0')
})

test('the error path names the JSON pointer of the offending value', () => {
  // A refusal that cannot be located is a refusal an operator will work around.
  assert.throws(() => canonicalize({ a: { b: [1, NaN] } }), /\$\.a\.b\[1\]/)
})

// ---------------------------------------------------------------------------------
// Strings — RFC 8785 §3.2.2.2
// ---------------------------------------------------------------------------------

test('[control] the seven two-character escapes are emitted, and nothing else is', () => {
  assert.equal(canonicalize('\b'), '"\\b"')
  assert.equal(canonicalize('\t'), '"\\t"')
  assert.equal(canonicalize('\n'), '"\\n"')
  assert.equal(canonicalize('\f'), '"\\f"')
  assert.equal(canonicalize('\r'), '"\\r"')
  assert.equal(canonicalize('"'), '"\\""')
  assert.equal(canonicalize('\\'), '"\\\\"')
  // NOT escaped: forward slash is a JSON escape but not a REQUIRED one, and escaping it
  // would put two canonical forms on one string.
  assert.equal(canonicalize('/'), '"/"')
})

test('remaining C0 controls use lowercase \\u00xx and nothing above U+001F does', () => {
  assert.equal(canonicalize(' '), '"\\u0000"')
  assert.equal(canonicalize(''), '"\\u0001"')
  assert.equal(canonicalize(''), '"\\u000b"')
  assert.equal(canonicalize(''), '"\\u000e"')
  assert.equal(canonicalize(''), '"\\u001f"')
  assert.match(canonicalize(''), /\\u001a/, 'hex digits must be lowercase')
  // U+007F (DEL) and everything non-ASCII is emitted literally: RFC 8785 does not escape
  // what UTF-8 can carry, and escaping it would be a second canonical form.
  assert.equal(canonicalize(''), '""')
  assert.equal(canonicalize(''), '""')
  assert.equal(canonicalize('é'), '"é"')
  assert.equal(canonicalize('€'), '"€"')
  assert.equal(canonicalize('\u{1f600}'), '"\u{1f600}"')
})

test('a well-formed surrogate pair is emitted verbatim and encodes to 4 UTF-8 bytes', () => {
  const bytes = canonicalizeToBytes('\u{1f600}')
  assert.deepEqual([...bytes], [0x22, 0xf0, 0x9f, 0x98, 0x80, 0x22])
})

test('a lone surrogate is refused in a value, in a key, and at any depth', () => {
  // A lone surrogate is not a Unicode scalar value and has no UTF-8 encoding. Historic ES6
  // JSON.stringify emitted such code units raw (invalid UTF-8); ES2019 escapes them. Both
  // behaviours exist in the wild, so the same input canonicalises two ways depending on
  // runtime age — and a field set is inside signed bytes, so a value that canonicalises two
  // ways is a value whose signature means two things.
  for (const bad of ['\ud800', '\udbff', '\udc00', '\udfff', 'a\ud800b', '\ud800\ud800']) {
    assert.throws(() => canonicalize(bad), JcsError, JSON.stringify(bad))
    assert.throws(() => canonicalize({ k: bad }), JcsError)
    assert.throws(() => canonicalize([bad]), JcsError)
    assert.throws(() => canonicalize({ [bad]: 1 }), JcsError, `key ${JSON.stringify(bad)}`)
  }
  assert.throws(() => canonicalize('\ud800'), /unpaired high surrogate U\+d800/)
  assert.throws(() => canonicalize('\udc00'), /unpaired low surrogate U\+dc00/)
  // A high surrogate followed by a NON-low code unit is still unpaired.
  assert.throws(() => canonicalize('\ud800A'), /unpaired high surrogate/)
})

test('an empty string and a string of every escape class together', () => {
  assert.equal(canonicalize(''), '""')
  assert.equal(canonicalize('a"b\\c\nde'), '"a\\"b\\\\c\\nd\\u0001e"')
})

// ---------------------------------------------------------------------------------
// Types with no JSON form — reject, never guess
// ---------------------------------------------------------------------------------

test('undefined is refused everywhere, because JSON.stringify would silently drop it', () => {
  assert.throws(() => canonicalize(undefined), JcsError)
  assert.throws(() => canonicalize({ a: undefined }), /undefined at \$\.a/)
  assert.throws(() => canonicalize([undefined]), /undefined at \$\[0\]/)
  assert.throws(() => canonicalize({ a: 1, b: undefined }), JcsError)
})

test('functions and symbols are refused, in values and in keys', () => {
  assert.throws(() => canonicalize(() => 1), JcsError)
  assert.throws(() => canonicalize({ a: () => 1 }), /function at \$\.a/)
  assert.throws(() => canonicalize({ a() {} }), JcsError)
  assert.throws(() => canonicalize([function named() {}]), JcsError)
  assert.throws(() => canonicalize(Symbol('s')), /symbol at \$/)
  assert.throws(() => canonicalize({ a: Symbol('s') }), /symbol at \$\.a/)
  assert.throws(() => canonicalize({ [Symbol('s')]: 1 }), /symbol-keyed properties/)
  assert.throws(() => canonicalize({ a: 1, [Symbol('s')]: 2 }), /symbol-keyed properties/)
})

test('BigInt is refused rather than narrowed to a double', () => {
  // JSON has one numeric type and RFC 8785 serialises it as an IEEE-754 double, which cannot
  // hold an arbitrary-precision integer. Encoding it silently would mean signing a different
  // number than the caller supplied.
  assert.throws(() => canonicalize(1n), /BigInt at \$/)
  assert.throws(() => canonicalize({ a: 2n ** 70n }), /BigInt at \$\.a/)
  assert.throws(() => canonicalize([0n]), JcsError)
})

test('exotic objects are refused rather than coerced through toJSON', () => {
  // Date is the dangerous one: it HAS a toJSON, so JSON.stringify succeeds and produces a
  // string whose format and precision are a choice nobody in this codebase made.
  class Grant {
    constructor() {
      this.a = 1
    }
  }
  const cases = [
    new Date(0),
    new Map([['a', 1]]),
    new Set([1]),
    /re/,
    new Uint8Array([1, 2]),
    new ArrayBuffer(4),
    // eslint-disable-next-line no-new-wrappers
    new Number(1),
    // eslint-disable-next-line no-new-wrappers
    new String('a'),
    // eslint-disable-next-line no-new-wrappers
    new Boolean(true),
    new Error('e'),
    new Grant(),
    Promise.resolve(1),
    new WeakMap(),
  ]
  for (const value of cases) {
    assert.throws(() => canonicalize(value), JcsError, String(value?.constructor?.name))
    assert.throws(() => canonicalize({ k: value }), JcsError)
  }
  assert.throws(() => canonicalize(new Date(0)), /only plain objects can be canonicalised/)
})

test('an object with a toJSON method gets no special treatment', () => {
  const sneaky = { a: 1, toJSON: () => ({ a: 2 }) }
  // toJSON is an own enumerable data property holding a function, so the function check
  // fires. What must NOT happen is the function being invoked and {"a":2} being signed.
  assert.throws(() => canonicalize(sneaky), /function at \$\.toJSON/)
})

test('a null-prototype object is accepted: it is plain JSON data', () => {
  const bare = Object.create(null)
  bare.b = 1
  bare.a = 2
  assert.equal(canonicalize(bare), '{"a":2,"b":1}')
})

// ---------------------------------------------------------------------------------
// Object shapes that JSON serialisation corrupts silently
// ---------------------------------------------------------------------------------

test('an accessor property is refused: canonicalisation must be a pure function of data', () => {
  const obj = { a: 1 }
  Object.defineProperty(obj, 'b', { get: () => 2, enumerable: true, configurable: true })
  assert.throws(() => canonicalize(obj), /accessor property "b"/)

  // A setter-only property is equally an accessor.
  const setterOnly = {}
  Object.defineProperty(setterOnly, 'c', { set: () => {}, enumerable: true, configurable: true })
  assert.throws(() => canonicalize(setterOnly), /accessor property "c"/)

  // And the getter must not have been invoked on the way to the refusal.
  let invoked = 0
  const counting = {}
  Object.defineProperty(counting, 'd', {
    get: () => {
      invoked += 1
      return 1
    },
    enumerable: true,
    configurable: true,
  })
  assert.throws(() => canonicalize(counting), JcsError)
  assert.equal(invoked, 0, 'the getter ran; the signed bytes would depend on side-effecting code')
})

test('a non-enumerable own property is refused, not dropped', () => {
  const obj = { a: 1 }
  Object.defineProperty(obj, 'hidden', { value: 2, enumerable: false, configurable: true })
  assert.throws(() => canonicalize(obj), /non-enumerable property "hidden"/)
})

test('a sparse array is refused rather than having its holes rendered as null', () => {
  assert.throws(() => canonicalize([1, , 3]), JcsError)
  assert.throws(() => canonicalize(new Array(3)), JcsError)
  const deleted = [1, 2, 3]
  delete deleted[1]
  assert.throws(() => canonicalize(deleted), JcsError)
  assert.throws(() => canonicalize({ a: [1, , 2] }), JcsError)
  // The hole-specific message is reachable when the own-property COUNT still matches, which
  // is what a delete plus an added property produces.
  const masked = [1, 2]
  delete masked[0]
  masked.note = 'x'
  assert.throws(() => canonicalize(masked), /hole at \$\[0\]/)
})

test('an array carrying non-index own properties is refused', () => {
  const arr = [1, 2]
  arr.note = 'dropped by JSON.stringify'
  assert.throws(() => canonicalize(arr), /own properties other than its indices and length/)
})

test('cycles are refused, direct and mutual, through objects and arrays', () => {
  const selfObj = {}
  selfObj.me = selfObj
  assert.throws(() => canonicalize(selfObj), /cyclic reference at \$\.me/)

  const selfArr = []
  selfArr.push(selfArr)
  assert.throws(() => canonicalize(selfArr), /cyclic reference at \$\[0\]/)

  const a = { name: 'a' }
  const b = { name: 'b', a }
  a.b = b
  assert.throws(() => canonicalize(a), JcsError)

  const viaArray = { list: [] }
  viaArray.list.push({ back: viaArray })
  assert.throws(() => canonicalize(viaArray), JcsError)
})

test('[control] a repeated SIBLING reference is not a cycle', () => {
  // The ancestors set holds only the containers on the current path. A visited-set that
  // never shrank would reject a grant that legitimately reuses one frozen constant twice.
  const shared = Object.freeze({ x: 1 })
  assert.equal(canonicalize({ p: shared, q: shared }), '{"p":{"x":1},"q":{"x":1}}')
  assert.equal(canonicalize([shared, shared, shared]), '[{"x":1},{"x":1},{"x":1}]')
})

// ---------------------------------------------------------------------------------
// Depth ceiling
// ---------------------------------------------------------------------------------

test('nesting is bounded at 64 levels: unbounded recursion is a reachable crash', () => {
  // Not a wrong answer, but an availability bug in a Worker that verifies grants for other
  // people, reachable from any untrusted JSON body. A Consent Grant nests three levels.
  assert.equal(canonicalize(nest(64)), `${'['.repeat(64)}0${']'.repeat(64)}`)
  assert.throws(() => canonicalize(nest(65)), JcsError)
  assert.throws(() => canonicalize(nest(65)), /nests deeper than 64 levels/)
  assert.throws(() => canonicalize(nest(4096)), /nests deeper than 64 levels/)
})

test('the depth ceiling applies to objects as well as arrays', () => {
  let deep = 0
  for (let i = 0; i < 65; i += 1) deep = { n: deep }
  assert.throws(() => canonicalize(deep), /nests deeper than 64 levels/)

  let ok = 0
  for (let i = 0; i < 64; i += 1) ok = { n: ok }
  assert.equal(typeof canonicalize(ok), 'string')
})

// ---------------------------------------------------------------------------------
// canonicalizeToBytes — the form the RFC actually defines
// ---------------------------------------------------------------------------------

test('[control] canonicalizeToBytes is the UTF-8 encoding of canonicalize', () => {
  for (const value of [
    { a: 1 },
    'é',
    [1, 2, 3],
    { '\u{1f600}': 'smile', a: null },
    { nested: { deep: [true, false, null] } },
  ]) {
    const bytes = canonicalizeToBytes(value)
    assert.ok(bytes instanceof Uint8Array)
    assert.deepEqual([...bytes], [...new TextEncoder().encode(canonicalize(value))])
    assert.equal(new TextDecoder().decode(bytes), canonicalize(value))
  }
})

test('canonicalizeToBytes signs UTF-8, never UTF-16', () => {
  // Going through the JS string and letting some other layer choose an encoding is how
  // implementations end up signing UTF-16 and disagreeing across the wire.
  const bytes = canonicalizeToBytes('é')
  assert.deepEqual([...bytes], [0x22, 0xc3, 0xa9, 0x22])
})

test('canonicalizeToBytes propagates every refusal', () => {
  for (const bad of [undefined, NaN, -0, 1n, Symbol('s'), new Date(0), '\ud800']) {
    assert.throws(() => canonicalizeToBytes(bad), JcsError, String(bad))
  }
})

// ---------------------------------------------------------------------------------
// Integer safety
// ---------------------------------------------------------------------------------

test('MAX_JCS_SAFE_INTEGER is 2^53 - 1, and the reason is demonstrable', () => {
  assert.equal(MAX_JCS_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)
  assert.equal(MAX_JCS_SAFE_INTEGER, 9007199254740991)
  // The whole justification in one assertion: past the limit two DISTINCT integers
  // canonicalise to identical bytes, so a signature over one authenticates the other.
  assert.equal(String(2 ** 53), String(2 ** 53 + 1))
  assert.equal(canonicalize(2 ** 53), canonicalize(2 ** 53 + 1))
})

test('[control] assertSafeInteger returns safe integers unchanged', () => {
  for (const value of [0, 1, -1, 2, 45 * 24 * 60 * 60, 1_800_000_000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]) {
    assert.equal(assertSafeInteger(value, 'v'), value, String(value))
  }
})

test('assertSafeInteger refuses everything that would make a signature ambiguous', () => {
  const bad = [
    2 ** 53,
    2 ** 53 + 1,
    -(2 ** 53),
    Number.MAX_VALUE,
    1.5,
    -0.5,
    NaN,
    Infinity,
    -Infinity,
    '2',
    '',
    null,
    undefined,
    true,
    false,
    {},
    [],
    [2],
    1n,
    Symbol('s'),
    () => 2,
  ]
  for (const value of bad) {
    assert.throws(() => assertSafeInteger(value, 'delegationDepth'), JcsError, String(value))
  }
  // String coercion in particular is a FAIL and not a convenience: "2" and 2 canonicalise
  // differently, so the same semantic value would carry two commitments and a revocation
  // entry filed against one would miss the other.
  assert.throws(() => assertSafeInteger('2', 'delegationDepth'), /must be a number, got string/)
  assert.throws(() => assertSafeInteger(1.5, 'delegationDepth'), /must be an integer/)
  assert.throws(() => assertSafeInteger(2 ** 53, 'delegationDepth'), /integer-safety limit/)
})

test('assertSafeInteger names the field in its message', () => {
  // The label is how an operator finds the offending field in a rejected grant.
  assert.throws(() => assertSafeInteger('x', 'pseudonymEpoch'), /pseudonymEpoch/)
  assert.throws(() => assertSafeInteger('x', 'issuedAt'), /issuedAt/)
  assert.throws(() => assertSafeInteger('x'), /value must be a number/)
})

test('JcsError is a distinguishable Error subclass', () => {
  // Callers fail closed on it specifically; if it were a plain Error, a catch that meant to
  // handle canonicalisation failure would swallow unrelated bugs.
  const err = new JcsError('x')
  assert.ok(err instanceof Error)
  assert.ok(err instanceof JcsError)
  assert.equal(err.name, 'JcsError')
  try {
    canonicalize(undefined)
    assert.fail('expected a throw')
  } catch (caught) {
    assert.ok(caught instanceof JcsError)
    assert.equal(caught.name, 'JcsError')
  }
})
