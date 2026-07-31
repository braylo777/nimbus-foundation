/**
 * NF-5 Group VC — the static half: "absence of any code path that resolves a VIN to a
 * credential" (NF-5 §4.9, group `VC`; NF-WP-1 §8.3, §10.1 Refusal 1).
 *
 * WHAT THIS PROGRAM IS. A source scanner over the declared JavaScript surface of the broker
 * and the worker entry points. It looks for the *shape* Refusal 1 forbids — a function that
 * takes a vehicle name and hands back something a holder could present as authority — and it
 * fails the run when it finds one.
 *
 * WHAT THIS PROGRAM IS NOT, stated here rather than in a footnote because overclaiming here
 * would be worse than not running it at all. **A passing scan is evidence, not proof.** It is
 * a syntactic argument about names, parameter lists and returned object literals. It performs
 * no dataflow analysis, builds no call graph, and cannot follow a value across a function
 * boundary. §"Limitations" at the bottom of this file, and the matching section of
 * conformance/README.md, enumerate exactly what defeats it. The behavioural evidence for VC
 * is `conformance/tests/resolve.test.js` and `conformance/tests/vin.test.js`, which exercise
 * the real code paths; this scan exists to catch the class of regression those tests would
 * miss because nobody thought to write a test for it — a NEW export, on a NEW route, with a
 * credential-shaped return.
 *
 * WHY IT IS NOT A GREP. A regular expression over raw source cannot tell a `return { token }`
 * from the word `token` in a comment, or from the string `'token'` inside
 * `NF3_FORBIDDEN_KEY_NAMES` — and `nf3-resolve.js` contains that exact list, so a naive grep
 * reports the guard as the violation. This file therefore lexes first: comments, string
 * literals, regular-expression literals and template raw text are blanked out (positions
 * preserved) before any structural search runs, and functions are recovered by real
 * paren/brace matching. Regular expressions are used *inside* that lexed surface as a
 * tokenizer aid; they are not the argument.
 *
 * NF-5 §4.3: plain ES modules, no npm, Node built-ins and web-standard APIs only.
 * NF-5 §4.8: every forbidden name below is stated HERE, by the suite. Nothing is read back
 * out of the module under test — an implementation that emptied its own forbidden list would
 * otherwise pass perfectly, which is the defect §4.8 exists to prevent.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import process from 'node:process'

/** conformance/static-scan.js -> conformance/ -> repository root. */
export const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))

// ---------------------------------------------------------------------------------
// The declared scan surface (NF-5 §8.2 in spirit: the scan states what it read)
// ---------------------------------------------------------------------------------

/**
 * Directories scanned, in full, recursively, for `.js`. The Worker entry points are here
 * because Refusal 1 is a property of what crosses the wire, and the wire is `index.js`.
 * A file outside this list is a file this scan says nothing about, which is why the report
 * prints the inventory rather than a bare verdict.
 */
export const SCAN_ROOTS = Object.freeze([
  'broker/src',
  'm0-vin-yield/src',
  'm3-drop-compliance/src',
])

/**
 * Modules whose entire job is naming, vocabulary and resolution. NF-3 resolution answers
 * "where do I ask", never "you may". These modules therefore have no legitimate reason to
 * construct a credential-shaped object anywhere, at any depth, so VC-S6 holds them to the
 * stricter rule. `nf2-grant.js` and `index.js` are deliberately excluded from VC-S6 and the
 * exclusion is a real weakening, recorded in Limitations: NF-2 mints capability objects by
 * design, and the broker verifies operator sessions by design, so a blanket "no
 * authority-shaped return" rule over those two files would fire on the thing they exist to do.
 */
export const NAME_LAYER_FILES = Object.freeze([
  'broker/src/vin.js',
  'broker/src/fields.js',
  'broker/src/nf3-resolve.js',
])

// ---------------------------------------------------------------------------------
// Vocabulary (NF-5 §4.8 — stated by the suite)
// ---------------------------------------------------------------------------------

/**
 * Words that name a bearer of authority. Matching is on whole words after splitting an
 * identifier on camel-case boundaries, `_`, `-` and digits — so `authenticated` (a boolean
 * about whether a signature verified) is NOT `authorization`, and does not match.
 */
export const CREDENTIAL_WORDS = Object.freeze([
  'token', 'tokens', 'accesstoken', 'idtoken', 'refreshtoken',
  'credential', 'credentials',
  'session', 'sessions', 'sessionid', 'sessiontoken',
  'bearer', 'authorization', 'authorisation', 'auth',
  'jwt', 'cookie', 'setcookie',
  'apikey', 'apisecret', 'secret', 'secrets', 'password', 'passphrase',
  'privatekey', 'keymaterial',
  'assertion', 'saml', 'oauth', 'sso', 'otp',
  'signedurl', 'presignedurl', 'sastoken',
  'login', 'signin', 'logon',
])

/**
 * Words that name a capability object. Separated from CREDENTIAL_WORDS because the split is
 * load-bearing: NF-2 issues Consent Grants, so `buildGrant` and `mintDelegatedGrant` are the
 * system working. A capability word is only a finding when the *only* inputs are names
 * (VC-S2) or when it is welded to an identifier word (VC-S1c).
 */
export const CAPABILITY_WORDS = Object.freeze([
  'grant', 'grants', 'capability', 'capabilities', 'entitlement', 'permission', 'authority',
])

/**
 * Words that name a vehicle *index*. NF-WP-1 §8.3: the VIN is a public name, like a DNS name.
 * `id` is deliberately absent — `generateGrantId` is not a VIN-to-grant path, and including
 * `id` would say it was.
 */
export const IDENTIFIER_WORDS = Object.freeze([
  'vin', 'vins', 'rawvin', 'plate', 'plates', 'licenseplate', 'numberplate',
  'imei', 'imsi', 'msisdn', 'esn', 'serial', 'qname', 'wmi', 'identifier', 'ident',
])

/** Verbs that mean "bring into existence" or "hand over". */
export const MINT_WORDS = Object.freeze([
  'mint', 'issue', 'issued', 'create', 'make', 'build', 'generate', 'produce', 'provision',
  'obtain', 'exchange', 'redeem', 'grant', 'granted', 'get', 'fetch', 'lookup', 'resolve',
  'derive', 'vend', 'sign', 'authorize', 'authorise', 'authenticate',
])

/**
 * Words that mark a symbol as a *guard* over the vocabulary rather than a producer of it.
 * `assertNoCredentialSurface` is the enforcement of Refusal 1; flagging it would invert the
 * finding, and a scanner that reports the lock as the burglar teaches its readers to ignore it.
 */
export const GUARD_WORDS = Object.freeze([
  'assert', 'no', 'not', 'never', 'without', 'reject', 'refuse', 'refused', 'forbid',
  'forbidden', 'deny', 'denied', 'screen', 'check', 'validate', 'verify', 'scan', 'detect',
  'invariant', 'error', 'errors', 'code', 'codes', 'reason', 'reasons', 'test', 'tests',
])

/**
 * Parameter names that carry no authority and are therefore ignored when VC-S2 asks whether a
 * function's inputs are "names only". A resolver legitimately takes an environment binding and
 * an options bag alongside the name.
 */
const NEUTRAL_PARAMS = new Set([
  'opts', 'options', 'env', 'ctx', 'context', 'config', 'now', 'signal', 'log', 'logger',
])

/**
 * The core forbidden-key list VC-S5 requires `NF3_FORBIDDEN_KEY_NAMES` to cover. Per §4.8 the
 * suite states it; the module may be stricter but may not be laxer.
 */
const REQUIRED_FORBIDDEN_KEYS = Object.freeze([
  'token', 'credential', 'session', 'bearer', 'authorization', 'secret', 'password', 'jwt',
  'cookie', 'grant', 'decision',
])

/** Keys a resolution result may never carry, whatever else it carries. */
const FORBIDDEN_RESULT_WORDS = Object.freeze([
  ...CREDENTIAL_WORDS, ...CAPABILITY_WORDS, 'decision', 'allowed', 'permitted', 'authorized',
  'authorised',
])

// ---------------------------------------------------------------------------------
// Lexer — blank out everything that is not code, preserving byte positions
// ---------------------------------------------------------------------------------

const IDENT_START = /[A-Za-z_$]/
const IDENT_PART = /[A-Za-z0-9_$]/

/** Keywords after which a `/` opens a regular-expression literal rather than a division. */
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'case', 'do',
  'else', 'yield', 'await',
])

const REGEX_PRECEDING_PUNCT = new Set([
  '', '(', '[', '{', ',', ';', ':', '=', '!', '&', '|', '?', '+', '-', '*', '%', '~', '^',
  '<', '>',
])

/**
 * Returns `{ code, strings }`.
 *
 * `code` is the same length as `source`, with the contents of comments, string literals,
 * regex literals and template raw text replaced by spaces (newlines preserved, so line
 * numbers computed against `code` are line numbers in `source`). Template *substitutions* —
 * the code inside `${ … }` — are kept, because that is real code and a `return \`${mint()}\``
 * would otherwise be invisible; the `${` and its matching `}` are blanked so that brace
 * matching over `code` stays balanced.
 *
 * `strings` is every string literal, in source order, as `{ start, end, value }`, so that a
 * structural pass can recover a quoted object key or the members of a frozen array literal
 * after the quotes themselves have been blanked.
 */
export function stripNonCode(source) {
  const n = source.length
  const out = new Array(n)
  const strings = []
  // Context stack. 'code' is the root; 'tpl' is template raw text; 'sub' is a `${ … }`
  // substitution, which is code again and must track its own brace depth so the closing
  // brace of the substitution is distinguishable from the closing brace of an object literal.
  const stack = [{ kind: 'code' }]
  let i = 0
  let prevSig = ''
  let prevWord = ''

  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k += 1) out[k] = source[k] === '\n' ? '\n' : ' '
  }
  const emit = (k) => {
    const c = source[k]
    out[k] = c
    if (c.trim() !== '') {
      prevSig = c
      if (!IDENT_PART.test(c)) prevWord = ''
    }
  }

  while (i < n) {
    const top = stack[stack.length - 1]

    if (top.kind === 'tpl') {
      const c = source[i]
      if (c === '\\') {
        blank(i, i + 2)
        i += 2
        continue
      }
      if (c === '`') {
        blank(i, i + 1)
        i += 1
        stack.pop()
        prevSig = '`'
        prevWord = ''
        continue
      }
      if (c === '$' && source[i + 1] === '{') {
        blank(i, i + 2)
        i += 2
        stack.push({ kind: 'sub', depth: 0 })
        prevSig = '('
        prevWord = ''
        continue
      }
      blank(i, i + 1)
      i += 1
      continue
    }

    const c = source[i]

    // Line comment.
    if (c === '/' && source[i + 1] === '/') {
      let j = i
      while (j < n && source[j] !== '\n') j += 1
      blank(i, j)
      i = j
      continue
    }

    // Block comment.
    if (c === '/' && source[i + 1] === '*') {
      let j = i + 2
      while (j < n && !(source[j] === '*' && source[j + 1] === '/')) j += 1
      blank(i, Math.min(j + 2, n))
      i = Math.min(j + 2, n)
      continue
    }

    // String literal.
    if (c === '"' || c === "'") {
      let j = i + 1
      let value = ''
      while (j < n) {
        if (source[j] === '\\') {
          value += source[j + 1] ?? ''
          j += 2
          continue
        }
        if (source[j] === c) break
        if (source[j] === '\n') break // unterminated; fail soft rather than run away
        value += source[j]
        j += 1
      }
      const end = Math.min(j + 1, n)
      strings.push({ start: i, end, value })
      blank(i, end)
      i = end
      prevSig = '"'
      prevWord = ''
      continue
    }

    // Template literal.
    if (c === '`') {
      blank(i, i + 1)
      i += 1
      stack.push({ kind: 'tpl' })
      continue
    }

    // Regex literal, distinguished from division by what precedes it.
    if (
      c === '/' &&
      (REGEX_PRECEDING_PUNCT.has(prevSig) || REGEX_PRECEDING_KEYWORDS.has(prevWord))
    ) {
      let j = i + 1
      let inClass = false
      while (j < n) {
        const d = source[j]
        if (d === '\\') {
          j += 2
          continue
        }
        if (d === '[') inClass = true
        else if (d === ']') inClass = false
        else if (d === '/' && !inClass) break
        else if (d === '\n') break
        j += 1
      }
      let k = Math.min(j + 1, n)
      while (k < n && /[a-z]/.test(source[k])) k += 1 // flags
      blank(i, k)
      i = k
      prevSig = ')'
      prevWord = ''
      continue
    }

    // Substitution close: the `}` that ends `${ … }` belongs to the template, not to code.
    if (c === '}' && top.kind === 'sub' && top.depth === 0) {
      blank(i, i + 1)
      i += 1
      stack.pop()
      prevSig = ')'
      prevWord = ''
      continue
    }
    if (c === '{' && top.kind === 'sub') top.depth += 1
    if (c === '}' && top.kind === 'sub') top.depth -= 1

    // Identifier — tracked whole so that `return /x/` lexes as a regex.
    if (IDENT_START.test(c)) {
      let j = i
      while (j < n && IDENT_PART.test(source[j])) j += 1
      for (let k = i; k < j; k += 1) out[k] = source[k]
      prevWord = source.slice(i, j)
      prevSig = source[j - 1]
      i = j
      continue
    }

    emit(i)
    i += 1
  }

  for (let k = 0; k < n; k += 1) if (out[k] === undefined) out[k] = ' '
  return { code: out.join(''), strings }
}

// ---------------------------------------------------------------------------------
// Structural recovery — functions, parameters, returned object literals
// ---------------------------------------------------------------------------------

const BLOCK_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof', 'do', 'else',
  'with', 'yield', 'await', 'new', 'delete', 'void', 'in', 'of', 'case', 'try', 'finally',
  'class', 'import', 'export', 'const', 'let', 'var', 'throw',
])

function matchPair(code, start, open, close) {
  if (code[start] !== open) return -1
  let depth = 0
  for (let i = start; i < code.length; i += 1) {
    if (code[i] === open) depth += 1
    else if (code[i] === close) {
      depth -= 1
      if (depth === 0) return i
    }
  }
  return -1
}

function skipSpace(code, i) {
  while (i < code.length && /\s/.test(code[i])) i += 1
  return i
}

function skipSpaceBack(code, i) {
  while (i >= 0 && /\s/.test(code[i])) i -= 1
  return i
}

function readIdentBack(code, end) {
  let i = end
  while (i >= 0 && IDENT_PART.test(code[i])) i -= 1
  return { name: code.slice(i + 1, end + 1), start: i + 1 }
}

/** Split a raw parameter list into binding names, flattening destructuring patterns. */
export function paramNames(raw) {
  const { code } = stripNonCode(raw)
  const names = []
  let depth = 0
  let i = 0
  let expectName = true
  while (i < code.length) {
    const c = code[i]
    if ('([{'.includes(c)) {
      depth += 1
      expectName = true
      i += 1
      continue
    }
    if (')]}'.includes(c)) {
      depth -= 1
      i += 1
      continue
    }
    if (c === ',') {
      expectName = true
      i += 1
      continue
    }
    if (c === '=') {
      // Skip a default value at whatever depth it appears.
      expectName = false
      i += 1
      continue
    }
    if (c === ':') {
      // `{ a: b }` — the binding is `b`, not `a`; drop the key we just recorded.
      names.pop()
      expectName = true
      i += 1
      continue
    }
    if (IDENT_START.test(c)) {
      let j = i
      while (j < code.length && IDENT_PART.test(code[j])) j += 1
      if (expectName) {
        names.push(code.slice(i, j))
        expectName = false
      }
      i = j
      continue
    }
    i += 1
  }
  return names.filter(Boolean)
}

/**
 * Recover every function in a lexed file: `function` declarations and expressions, arrow
 * functions bound to a name, and object/class method shorthand. Returns
 * `{ name, params, bodyStart, bodyEnd, start }`, positions in `code`.
 */
export function findFunctions(code) {
  const fns = []
  const seen = new Set()

  const push = (fn) => {
    const key = `${fn.start}:${fn.bodyStart}`
    if (!seen.has(key)) {
      seen.add(key)
      fns.push(fn)
    }
  }

  // 1. `function` declarations and expressions.
  const fnKw = /\bfunction\b/g
  let m
  while ((m = fnKw.exec(code)) !== null) {
    let i = skipSpace(code, m.index + 8)
    if (code[i] === '*') i = skipSpace(code, i + 1)
    let name = '<anonymous>'
    if (IDENT_START.test(code[i] ?? '')) {
      let j = i
      while (j < code.length && IDENT_PART.test(code[j])) j += 1
      name = code.slice(i, j)
      i = skipSpace(code, j)
    }
    if (code[i] !== '(') continue
    const pEnd = matchPair(code, i, '(', ')')
    if (pEnd < 0) continue
    const params = code.slice(i + 1, pEnd)
    const bStart = skipSpace(code, pEnd + 1)
    if (code[bStart] !== '{') continue
    const bEnd = matchPair(code, bStart, '{', '}')
    if (bEnd < 0) continue
    push({ name, params, start: m.index, bodyStart: bStart, bodyEnd: bEnd, kind: 'function' })
  }

  // 2. Arrow functions. Walk every `=>` and recover its parameters and (if bound) its name.
  const arrow = /=>/g
  while ((m = arrow.exec(code)) !== null) {
    let left = skipSpaceBack(code, m.index - 1)
    let params = ''
    let nameEnd = -1
    if (code[left] === ')') {
      // Find the matching '(' by scanning backwards.
      let depth = 0
      let k = left
      for (; k >= 0; k -= 1) {
        if (code[k] === ')') depth += 1
        else if (code[k] === '(') {
          depth -= 1
          if (depth === 0) break
        }
      }
      if (k < 0) continue
      params = code.slice(k + 1, left)
      nameEnd = skipSpaceBack(code, k - 1)
    } else if (IDENT_PART.test(code[left] ?? '')) {
      const id = readIdentBack(code, left)
      params = id.name
      nameEnd = skipSpaceBack(code, id.start - 1)
    } else {
      continue
    }
    // Optional `async`, then optional `= name` / `name(` binding.
    let name = '<anonymous>'
    if (nameEnd >= 0) {
      const maybeAsync = readIdentBack(code, nameEnd)
      let cursor = nameEnd
      if (maybeAsync.name === 'async') cursor = skipSpaceBack(code, maybeAsync.start - 1)
      if (code[cursor] === '=' && code[cursor - 1] !== '=' && code[cursor + 1] !== '=') {
        const bound = readIdentBack(code, skipSpaceBack(code, cursor - 1))
        if (bound.name) name = bound.name
      } else if (code[cursor] === ':') {
        const bound = readIdentBack(code, skipSpaceBack(code, cursor - 1))
        if (bound.name) name = bound.name
      }
    }
    const bStart = skipSpace(code, m.index + 2)
    let bodyStart
    let bodyEnd
    if (code[bStart] === '{') {
      bodyStart = bStart
      bodyEnd = matchPair(code, bStart, '{', '}')
      if (bodyEnd < 0) continue
    } else {
      // Expression body — treat it as an implicit `return`. Scan balanced to the end of the
      // expression so that `=> ({ … })` is picked up as a returned object literal.
      let depth = 0
      let k = bStart
      for (; k < code.length; k += 1) {
        const ch = code[k]
        if ('([{'.includes(ch)) depth += 1
        else if (')]}'.includes(ch)) {
          if (depth === 0) break
          depth -= 1
        } else if (depth === 0 && (ch === ',' || ch === ';')) break
      }
      bodyStart = bStart
      bodyEnd = k
    }
    push({
      name,
      params,
      start: m.index,
      bodyStart,
      bodyEnd,
      kind: code[bStart] === '{' ? 'arrow' : 'arrow-expr',
    })
  }

  // 3. Method shorthand: `name(params) {` in an object literal or class body.
  const method = /([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g
  while ((m = method.exec(code)) !== null) {
    const name = m[1]
    if (BLOCK_KEYWORDS.has(name)) continue
    const open = code.indexOf('(', m.index)
    const pEnd = matchPair(code, open, '(', ')')
    if (pEnd < 0) continue
    const bStart = skipSpace(code, pEnd + 1)
    if (code[bStart] !== '{') continue
    // Reject `f(x) {` where `f(x)` was a call statement: require the preceding significant
    // character to be one that can precede a method definition.
    const before = skipSpaceBack(code, m.index - 1)
    const prevIdent = IDENT_PART.test(code[before] ?? '') ? readIdentBack(code, before).name : ''
    const prevChar = code[before] ?? ''
    const okPrev =
      before < 0 ||
      prevChar === '{' ||
      prevChar === ',' ||
      prevChar === ';' ||
      prevChar === '}' ||
      ['async', 'static', 'get', 'set'].includes(prevIdent)
    if (!okPrev) continue
    const bEnd = matchPair(code, bStart, '{', '}')
    if (bEnd < 0) continue
    push({ name, params: code.slice(open + 1, pEnd), start: m.index, bodyStart: bStart, bodyEnd: bEnd, kind: 'method' })
  }

  return fns.sort((a, b) => a.start - b.start)
}

/**
 * Top-level keys of the object literal beginning at `open`. Quoted keys are recovered from
 * the lexer's string table, since the quotes themselves have been blanked. `...spread` is
 * recorded as `<spread>` — an honest "this scan cannot see through it" marker rather than a
 * silent omission.
 */
function objectKeys(code, strings, open) {
  const close = matchPair(code, open, '{', '}')
  if (close < 0) return []
  const keys = []
  let depth = 0
  let expectKey = true
  let i = open
  while (i <= close) {
    const c = code[i]
    if ('([{'.includes(c)) {
      depth += 1
      if (depth === 1) expectKey = true
      i += 1
      continue
    }
    if (')]}'.includes(c)) {
      depth -= 1
      i += 1
      continue
    }
    if (depth === 1 && c === ',') {
      expectKey = true
      i += 1
      continue
    }
    if (depth === 1 && expectKey) {
      if (c === '.' && code[i + 1] === '.' && code[i + 2] === '.') {
        keys.push('<spread>')
        expectKey = false
        i += 3
        continue
      }
      if (IDENT_START.test(c)) {
        let j = i
        while (j < code.length && IDENT_PART.test(code[j])) j += 1
        keys.push(code.slice(i, j))
        expectKey = false
        i = j
        continue
      }
      const lit = strings.find((s) => s.start === i)
      if (lit) {
        keys.push(lit.value)
        expectKey = false
        i = lit.end
        continue
      }
    }
    i += 1
  }
  return keys
}

/** Every string literal inside the array literal that starts at `open`. */
function arrayStrings(code, strings, open) {
  const close = matchPair(code, open, '[', ']')
  if (close < 0) return []
  return strings.filter((s) => s.start > open && s.end <= close).map((s) => s.value)
}

/**
 * Object-literal keys returned by `fn`, excluding returns that belong to a nested function.
 * A `return` statement is scanned to its first `{`, so `return Object.freeze({ … })`,
 * `return json({ … })` and `return new Response(JSON.stringify({ … }))` are all covered.
 */
function returnedKeys(code, strings, fn, allFns) {
  const nested = allFns.filter(
    (g) => g !== fn && g.bodyStart > fn.bodyStart && g.bodyEnd <= fn.bodyEnd,
  )
  const inNested = (idx) => nested.some((g) => idx >= g.bodyStart && idx <= g.bodyEnd)
  const keys = new Set()

  if (fn.kind === 'arrow-expr') {
    const open = code.indexOf('{', fn.bodyStart)
    if (open >= 0 && open < fn.bodyEnd) for (const k of objectKeys(code, strings, open)) keys.add(k)
    return [...keys]
  }

  const body = code.slice(fn.bodyStart, fn.bodyEnd + 1)
  const re = /\breturn\b/g
  let m
  while ((m = re.exec(body)) !== null) {
    const abs = fn.bodyStart + m.index
    if (inNested(abs)) continue
    // Walk to the end of the return statement, balanced, and take the first `{`.
    let depth = 0
    let firstBrace = -1
    for (let k = abs + 6; k <= fn.bodyEnd; k += 1) {
      const c = code[k]
      if (c === '{') {
        if (firstBrace < 0) firstBrace = k
        depth += 1
      } else if (c === '(' || c === '[') depth += 1
      else if (c === '}' || c === ')' || c === ']') {
        depth -= 1
        if (depth < 0) break
      } else if (depth === 0 && (c === ';' || c === '\n')) break
    }
    if (firstBrace >= 0) for (const k of objectKeys(code, strings, firstBrace)) keys.add(k)
  }
  return [...keys]
}

/** Exported binding names: declarations, `export { a as b }`, and `export default`. */
export function exportedNames(code) {
  const names = new Set()
  const decl = /\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?|class|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g
  let m
  while ((m = decl.exec(code)) !== null) names.add(m[1])
  const list = /\bexport\s*\{([^}]*)\}/g
  while ((m = list.exec(code)) !== null) {
    for (const part of m[1].split(',')) {
      const t = part.trim()
      if (!t) continue
      const as = t.split(/\s+as\s+/)
      names.add((as[1] ?? as[0]).trim())
    }
  }
  return [...names]
}

// ---------------------------------------------------------------------------------
// Word analysis
// ---------------------------------------------------------------------------------

/** Split an identifier into lowercase words on camel-case boundaries, `_`, `-` and digits. */
export function words(identifier) {
  return String(identifier)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase())
}

const has = (ws, list) => ws.some((w) => list.includes(w))
const asSet = (ws) => new Set(ws)

/** `credentialForVin` -> true; `authenticated` -> false. Whole-word, plus glued compounds. */
function hasCredentialWord(identifier) {
  const ws = words(identifier)
  if (has(ws, CREDENTIAL_WORDS)) return true
  // Glued forms that camel-case splitting cannot separate, e.g. `apikey`, `sessionid`.
  return ws.some((w) => CREDENTIAL_WORDS.includes(w))
}

// ---------------------------------------------------------------------------------
// File inventory
// ---------------------------------------------------------------------------------

function walkJs(absDir, acc) {
  let entries
  try {
    entries = readdirSync(absDir)
  } catch {
    return acc
  }
  for (const name of entries.sort()) {
    const abs = join(absDir, name)
    const st = statSync(abs)
    if (st.isDirectory()) walkJs(abs, acc)
    else if (name.endsWith('.js')) acc.push(abs)
  }
  return acc
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function lineOf(code, index) {
  let line = 1
  for (let i = 0; i < index && i < code.length; i += 1) if (code[i] === '\n') line += 1
  return line
}

// ---------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------

export const CHECKS = Object.freeze([
  { id: 'VC-S1', title: 'No export name mints authority from an identifier' },
  { id: 'VC-S2', title: 'No name-only input produces an authority-shaped output' },
  { id: 'VC-S3', title: 'No VIN-parameter function returns a credential-shaped object' },
  { id: 'VC-S4', title: 'No dynamic code construction on the declared surface' },
  { id: 'VC-S5', title: 'The declared NF-3 result surface carries no authority key' },
  { id: 'VC-S6', title: 'The name layer constructs no credential-shaped object at all' },
])

/**
 * Run every check over one source text. Split out from `scan()` so that the self-controls
 * below can feed it synthetic violations: a scanner whose zero findings might equally mean
 * "clean codebase" or "broken scanner" is exactly the vacuous pass NF-5 §4.7 forbids, and the
 * only cure is to make the scanner demonstrate, on every run, that each check still fires.
 *
 * `report(checkId, index, symbol, detail)` is called for each finding; `bump(checkId)` counts
 * an examination so that an unevidenced check is distinguishable from a clean one.
 */
export function scanSource(rel, source, emitFinding, bump) {
  const { code, strings } = stripNonCode(source)
  const report = (checkId, index, symbol, detail) =>
    emitFinding({ check: checkId, file: rel, line: lineOf(code, index), symbol, detail })
  {
    // ---- VC-S4: dynamic construction ------------------------------------------------
    // Checked first because everything below is unsound in its presence, and because NF-5
    // §4.5 CH-2 says in as many words that the conformance-hook reachability check is only
    // decidable while these are absent.
    bump('VC-S4')
    const dynamic = [
      { re: /\beval\s*\(/g, what: 'eval()' },
      { re: /\bnew\s+Function\s*\(/g, what: 'new Function()' },
      { re: /(?<![.\w])import\s*\(/g, what: 'dynamic import()' },
      { re: /\bglobalThis\s*\[/g, what: 'computed global access' },
    ]
    for (const { re, what } of dynamic) {
      let m
      while ((m = re.exec(code)) !== null) {
        report('VC-S4', m.index, what, `${what} defeats every static claim in this file and makes NF-5 §4.5 CH-2 undecidable`)
      }
    }

    // ---- VC-S1: export names ---------------------------------------------------------
    for (const name of exportedNames(code)) {
      bump('VC-S1')
      const ws = words(name)
      if (has(ws, GUARD_WORDS)) continue
      const idWord = has(ws, IDENTIFIER_WORDS)
      const credWord = hasCredentialWord(name)
      const capWord = has(ws, CAPABILITY_WORDS)
      const mintWord = has(ws, MINT_WORDS)
      const at = code.indexOf(name)
      if (idWord && credWord) {
        report('VC-S1', at, name, 'export name pairs a vehicle identifier with a credential noun (Refusal 1 shape)')
      } else if (idWord && capWord) {
        report('VC-S1', at, name, 'export name pairs a vehicle identifier with a capability noun: a name must not yield a grant')
      } else if (mintWord && credWord) {
        report('VC-S1', at, name, 'export name reads as minting a credential')
      }
    }

    // ---- function-level checks --------------------------------------------------------
    const fns = findFunctions(code)
    const isNameLayer = NAME_LAYER_FILES.includes(rel)

    for (const fn of fns) {
      const params = paramNames(fn.params)
      const paramWords = params.map((p) => ({ p, ws: words(p) }))
      const idParams = paramWords.filter(({ ws }) => has(ws, IDENTIFIER_WORDS))
      const meaningful = paramWords.filter(({ p }) => !NEUTRAL_PARAMS.has(p))
      const keys = returnedKeys(code, strings, fn, fns)
      const authorityKeys = keys.filter((k) => {
        const ws = words(k)
        return hasCredentialWord(k) || has(ws, CAPABILITY_WORDS)
      })
      const credentialKeys = keys.filter((k) => hasCredentialWord(k))

      // VC-S2 — inputs are names only, output carries authority.
      if (idParams.length > 0 && meaningful.length > 0) {
        bump('VC-S2')
        const nameOnly = meaningful.every(({ ws }) => has(ws, IDENTIFIER_WORDS))
        if (nameOnly && authorityKeys.length > 0) {
          report(
            'VC-S2',
            fn.start,
            fn.name,
            `takes only identifier-shaped inputs (${params.join(', ')}) and returns authority-shaped keys: ${authorityKeys.join(', ')}`,
          )
        }
      }

      // VC-S3 — a VIN goes in, a credential-shaped object comes out.
      if (idParams.length > 0) {
        bump('VC-S3')
        if (credentialKeys.length > 0) {
          report(
            'VC-S3',
            fn.start,
            fn.name,
            `takes ${idParams.map((x) => x.p).join(', ')} and returns credential-shaped keys: ${credentialKeys.join(', ')}`,
          )
        }
      }

      // VC-S6 — the name layer builds no credential-shaped object anywhere.
      if (isNameLayer) {
        bump('VC-S6')
        if (credentialKeys.length > 0) {
          report(
            'VC-S6',
            fn.start,
            fn.name,
            `a naming/resolution module returned a credential-shaped object: ${credentialKeys.join(', ')}`,
          )
        }
      }
    }

    // ---- VC-S5: the declared NF-3 result surface --------------------------------------
    if (rel === 'broker/src/nf3-resolve.js') {
      for (const constName of ['NF3_RESULT_KEYS', 'NF3_ENDPOINT_KEYS', 'NF3_ANSWER_KEYS']) {
        const at = code.indexOf(`${constName} = `)
        if (at < 0) {
          report('VC-S5', 0, constName, 'the declared result surface is missing; VC-S5 cannot be evaluated (NF-5 §4.6: INCONCLUSIVE counts as FAIL)')
          continue
        }
        bump('VC-S5')
        const open = code.indexOf('[', at)
        const members = arrayStrings(code, strings, open)
        if (members.length === 0) {
          report('VC-S5', at, constName, 'declared key set is empty or unreadable')
          continue
        }
        for (const key of members) {
          if (has(words(key), FORBIDDEN_RESULT_WORDS)) {
            report('VC-S5', at, `${constName}.${key}`, 'a resolution result key names authority; NF-3 answers "where", never "you may"')
          }
        }
      }
      const fbAt = code.indexOf('NF3_FORBIDDEN_KEY_NAMES = ')
      if (fbAt < 0) {
        report('VC-S5', 0, 'NF3_FORBIDDEN_KEY_NAMES', 'the module declares no forbidden-key screen')
      } else {
        bump('VC-S5')
        const declared = new Set(arrayStrings(code, strings, code.indexOf('[', fbAt)).map((s) => s.toLowerCase()))
        for (const required of REQUIRED_FORBIDDEN_KEYS) {
          if (!declared.has(required)) {
            report('VC-S5', fbAt, `NF3_FORBIDDEN_KEY_NAMES.${required}`, `the suite requires this name in the screen (NF-5 §4.8: the suite states the list, not the IUT)`)
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------------
// Self-controls (NF-5 §4.7, applied to the scanner)
// ---------------------------------------------------------------------------------

/**
 * A scan that reports nothing is indistinguishable from a scan that does nothing, and "we ran
 * the scanner and it was quiet" is the single most common way a static check becomes theatre.
 * §4.7 requires a positive control per group; these are the scanner's own. Each POSITIVE
 * fixture is a synthetic violation the named check MUST report; each NEGATIVE fixture is a
 * real shape from this codebase that it MUST NOT report. Both directions matter: a check that
 * fires on `assertNoCredentialSurface` would train its readers to ignore it.
 *
 * These run on every invocation. If any control fails, the whole scan is FAIL regardless of
 * what it found in the repository, because its findings are no longer trustworthy.
 */
export const SELF_CONTROLS = Object.freeze([
  {
    id: 'VC-S1/pos-a', check: 'VC-S1', expect: 'finding',
    file: 'fixture.js',
    source: 'export function credentialForVin(vin) { return null }',
  },
  {
    id: 'VC-S1/pos-b', check: 'VC-S1', expect: 'finding',
    file: 'fixture.js',
    source: 'export const vinToGrant = (vin) => null',
  },
  {
    id: 'VC-S1/pos-c', check: 'VC-S1', expect: 'finding',
    file: 'fixture.js',
    source: 'export function mintSessionToken() { return null }',
  },
  {
    id: 'VC-S1/neg-guard', check: 'VC-S1', expect: 'clean',
    file: 'fixture.js',
    source: 'export function assertNoCredentialSurface(v) { return v }',
  },
  {
    id: 'VC-S1/neg-issuance', check: 'VC-S1', expect: 'clean',
    file: 'fixture.js',
    source: 'export async function buildGrant(params) { return {} }\nexport function generateGrantId() { return "" }\nexport function mintDelegatedGrant(parent, params) { return {} }',
  },
  {
    id: 'VC-S2/pos', check: 'VC-S2', expect: 'finding',
    file: 'fixture.js',
    source: 'function lookupByVin(vin, opts) {\n  return { grant: 1, expires_at: 2 }\n}',
  },
  {
    id: 'VC-S2/neg-location', check: 'VC-S2', expect: 'clean',
    file: 'fixture.js',
    source: 'function resolveVin(vin, env, opts) {\n  return { v: 1, status: "resolved", endpoint: null, reasons: [] }\n}',
  },
  {
    id: 'VC-S3/pos', check: 'VC-S3', expect: 'finding',
    file: 'fixture.js',
    source: 'function serve(vin, requestBody, db) {\n  return new Response(JSON.stringify({ access_token: "x" }))\n}',
  },
  {
    id: 'VC-S3/neg-comment', check: 'VC-S3', expect: 'clean',
    // The lexer earns its place here: the words below are in a comment and a string literal,
    // which is exactly the shape of `NF3_FORBIDDEN_KEY_NAMES`. A grep fails this control.
    file: 'fixture.js',
    source: '// never return a session token for a vin\nconst FORBIDDEN = ["token", "session", "bearer"]\nfunction check(vin) {\n  return { ok: FORBIDDEN.length > 0 }\n}',
  },
  {
    id: 'VC-S4/pos', check: 'VC-S4', expect: 'finding',
    file: 'fixture.js',
    source: 'const f = new Function("return 1")',
  },
  {
    id: 'VC-S4/neg-string', check: 'VC-S4', expect: 'clean',
    file: 'fixture.js',
    source: 'const msg = "eval() is forbidden here"\n// new Function() is forbidden too\n',
  },
  {
    id: 'VC-S5/pos-key', check: 'VC-S5', expect: 'finding',
    file: 'broker/src/nf3-resolve.js',
    source: 'export const NF3_RESULT_KEYS = Object.freeze(["v", "session_token"])\nexport const NF3_ENDPOINT_KEYS = Object.freeze(["url"])\nexport const NF3_ANSWER_KEYS = Object.freeze(["v"])\nexport const NF3_FORBIDDEN_KEY_NAMES = Object.freeze(["token","credential","session","bearer","authorization","secret","password","jwt","cookie","grant","decision"])',
  },
  {
    id: 'VC-S5/pos-emptied-screen', check: 'VC-S5', expect: 'finding',
    file: 'broker/src/nf3-resolve.js',
    source: 'export const NF3_RESULT_KEYS = Object.freeze(["v"])\nexport const NF3_ENDPOINT_KEYS = Object.freeze(["url"])\nexport const NF3_ANSWER_KEYS = Object.freeze(["v"])\nexport const NF3_FORBIDDEN_KEY_NAMES = Object.freeze([])',
  },
  {
    id: 'VC-S6/pos', check: 'VC-S6', expect: 'finding',
    file: 'broker/src/vin.js',
    source: 'function helper(x) {\n  return { bearer: x }\n}',
  },
  {
    id: 'VC-S6/neg-verdict', check: 'VC-S6', expect: 'clean',
    file: 'broker/src/vin.js',
    source: 'export function validateVin(vin, opts = {}) {\n  return { ok: true, syntaxValid: true, checkDigitValid: true, normalized: vin, wmi: null, reason: null }\n}',
  },
])

/** Execute the self-controls. Returns `{ id, check, expect, observed, ok }[]`. */
export function runSelfControls() {
  return SELF_CONTROLS.map((c) => {
    const hits = []
    scanSource(c.file, c.source, (f) => hits.push(f), () => {})
    const relevant = hits.filter((h) => h.check === c.check)
    const observed = relevant.length
    const ok = c.expect === 'finding' ? observed > 0 : observed === 0
    return { id: c.id, check: c.check, expect: c.expect, observed, ok, hits: relevant }
  })
}

/**
 * Run the self-controls and then every check over the declared surface. Returns
 * `{ files, checks, findings, controls, ok }`. Reads the filesystem; never writes to it.
 */
export async function scan(repoRoot = REPO_ROOT) {
  const controls = runSelfControls()

  const files = []
  for (const root of SCAN_ROOTS) walkJs(join(repoRoot, root), files)

  const findings = []
  const inventory = []
  const perCheck = Object.fromEntries(CHECKS.map((c) => [c.id, { examined: 0, findings: 0 }]))

  for (const abs of files) {
    const rel = relative(repoRoot, abs).split('\\').join('/')
    const raw = readFileSync(abs)
    inventory.push({ file: rel, bytes: raw.length, sha256: await sha256Hex(raw) })
    scanSource(
      rel,
      raw.toString('utf8'),
      (f) => {
        perCheck[f.check].findings += 1
        findings.push(f)
      },
      (id) => {
        perCheck[id].examined += 1
      },
    )
  }

  const checks = CHECKS.map((c) => {
    const ctrls = controls.filter((x) => x.check === c.id)
    const controlsOk = ctrls.length > 0 && ctrls.every((x) => x.ok)
    return {
      ...c,
      examined: perCheck[c.id].examined,
      findings: perCheck[c.id].findings,
      controls: `${ctrls.filter((x) => x.ok).length}/${ctrls.length}`,
      // A check with no examinations is UNEVIDENCED, never PASS: NF-5 §4.6 makes "could not
      // check" count as failure, and silent absence of coverage is the failure mode a badge
      // system must not have.
      verdict: !controlsOk
        ? 'BROKEN'
        : perCheck[c.id].findings > 0
          ? 'FAIL'
          : perCheck[c.id].examined > 0
            ? 'PASS'
            : 'UNEVIDENCED',
    }
  })

  return {
    suite: 'NF5/1.0',
    group: 'VC',
    roots: [...SCAN_ROOTS],
    files: inventory,
    checks,
    findings,
    controls,
    limitations: [...LIMITATIONS],
    ok: findings.length === 0 && checks.every((c) => c.verdict === 'PASS'),
  }
}

// ---------------------------------------------------------------------------------
// Limitations — what defeats this scan
// ---------------------------------------------------------------------------------

/**
 * Enumerated as data, not prose, so `run.js` can print it next to the verdict and nobody can
 * read a PASS without reading the caveat. Each entry is a concrete way a real VIN-to-credential
 * path would survive every check above.
 */
export const LIMITATIONS = Object.freeze([
  'No dataflow. The scan is intraprocedural. A VIN passed to a helper that returns a token is invisible: neither function has both halves of the shape.',
  'No call graph. `return issue(vin)` is not followed into `issue`.',
  'Naming only. Call the token `hint`, `ref`, `blob`, `payload`, `x` or `endpoint_extra` and every name-based rule is silent. The vocabulary is the suite\'s guess at what a defect would be called.',
  'Computed and indirect keys. `obj[k] = v`, `Object.assign(out, secretBag)`, `{ ...credentials }` and JSON assembled from a template string are not object literals and are not read as keys. `<spread>` is recorded but not resolved.',
  'Non-return channels. Authority handed back through a mutated argument, a closure variable, a module-level cache, a `Set-Cookie` header, a D1 row or a KV write is not a return value and is not seen.',
  'Derived identifiers. The parameter heuristic looks for a VIN-shaped *name*. A path that takes a pseudonym, a `qname_digest` or an opaque `vehicle_ref` derived from a VIN satisfies Refusal 1\'s concern and trips nothing here.',
  'Unscanned code. Only the roots listed in SCAN_ROOTS, only `.js`. SQL in `schema.sql`, configuration in `wrangler.toml`, anything served by an upstream, and any file added outside those roots are outside the claim.',
  'Runtime construction. VC-S4 exists precisely because `eval`, `new Function` and dynamic `import()` would make the rest unsound — but VC-S4 only proves they are absent from the text, not that the deployed bundle is the text.',
  'Deliberate exclusions. `broker/src/nf2-grant.js` and `broker/src/index.js` are exempt from VC-S6 because NF-2 mints capability objects and the broker verifies operator sessions by design. That exemption is a hole, and it is where a real defect would be cheapest to hide.',
  'A lexer is not a parser. Positions are recovered by paren/brace matching over a de-commented, de-stringified source. Exotic syntax (decorators, unusual ASI, deeply nested template substitutions) can misalign a body span and silently drop a function from the scan.',
])

// ---------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------

export function formatReport(result) {
  const L = []
  L.push('NF-5 GROUP VC — STATIC SCAN (evidence, not proof)')
  L.push(`suite ${result.suite} · roots: ${result.roots.join(', ')}`)
  L.push('')
  L.push(`FILES SCANNED (${result.files.length})`)
  for (const f of result.files) {
    L.push(`  ${f.sha256.slice(0, 16)}  ${String(f.bytes).padStart(7)}  ${f.file}`)
  }
  L.push('')
  L.push('SELF-CONTROLS (NF-5 §4.7 — a quiet scanner must prove it is not a broken one)')
  for (const c of result.controls) {
    L.push(
      `  ${c.ok ? 'ok  ' : 'FAIL'}  ${c.id.padEnd(24)} expect ${c.expect.padEnd(8)} observed ${c.observed}`,
    )
  }
  L.push('')
  L.push('CHECKS')
  for (const c of result.checks) {
    L.push(
      `  ${c.id}  ${c.verdict.padEnd(11)} ctrl ${c.controls}  examined ${String(c.examined).padStart(5)}  findings ${String(c.findings).padStart(3)}  ${c.title}`,
    )
  }
  L.push('')
  if (result.findings.length === 0) {
    L.push('FINDINGS  none')
  } else {
    L.push(`FINDINGS (${result.findings.length})`)
    for (const f of result.findings) {
      L.push(`  [${f.check}] ${f.file}:${f.line}  ${f.symbol}`)
      L.push(`           ${f.detail}`)
    }
  }
  L.push('')
  L.push('WHAT A PASS HERE MEANS, AND WHAT IT DOES NOT')
  L.push('  A pass is evidence that no VIN-to-credential path exists IN THE SHAPES THIS SCAN CAN SEE.')
  L.push('  It is not proof. The following would defeat it entirely:')
  for (const lim of LIMITATIONS) {
    const wrapped = lim.match(/.{1,92}(\s|$)/g) ?? [lim]
    L.push(`    - ${wrapped[0].trim()}`)
    for (const w of wrapped.slice(1)) L.push(`      ${w.trim()}`)
  }
  L.push('')
  L.push(`RESULT  ${result.ok ? 'PASS' : 'FAIL'}`)
  return L.join('\n')
}

async function main(argv) {
  const json = argv.includes('--json')
  let result
  try {
    result = await scan()
  } catch (err) {
    process.stderr.write(`static-scan: harness error: ${err?.stack ?? err}\n`)
    return 2
  }
  process.stdout.write(json ? `${JSON.stringify(result, null, 2)}\n` : `${formatReport(result)}\n`)
  return result.ok ? 0 : 1
}

// Run only when invoked directly; `run.js` imports `scan()` from here.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((c) => {
    process.exitCode = c
  })
}
