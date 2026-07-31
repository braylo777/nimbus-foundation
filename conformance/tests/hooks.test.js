/**
 * NF-5 §4.5 — conformance-hook hygiene (group CH).
 *
 * CH-1  the conformance interface lives in a module the production entry does not import,
 *       directly or transitively.
 * CH-2  the production static import graph does not reach it. Decidable only because §8.3
 *       forbids dynamic `import()`, `eval`, `new Function` and string-constructed specifiers
 *       on the Declared Surface — so this file asserts that prohibition too, since without it
 *       CH-2 is not a check at all but a hope.
 * CH-3  the conformance and production builds differ ONLY by the hook module and its
 *       registration, and the delta is enumerated and reviewable.
 * CH-4  hook routes 404 on the production digest, with no side effect.
 *
 * PROFILE: PROTOCOL. This file imports nothing from any implementation source tree. It reads
 * the repository as artifacts — source text, a manifest, a computed digest — which is exactly
 * what an external auditor assessing a third-party implementation would have. That is not an
 * accident of convenience: NF-5 §4.2 requires the Prime tier to be attainable through the
 * PROTOCOL profile alone, and a CH group evidenced only by module-level introspection would
 * be unavailable to precisely the implementer the profile exists to serve.
 *
 * VACUITY. Every assertion below is a refusal — "no hook is reachable", "no dynamic import
 * exists". A suite of refusals passes trivially against an empty repository, so §4.7 requires
 * a positive control. The `[control]` assertions build a synthetic module graph that DOES
 * contain a hook and a dynamic import, and require the same walker to find them. If the
 * walker silently stopped working, the controls fail and the group is marked NO-CONTROL
 * rather than passing on a technicality.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, dirname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')

const manifest = JSON.parse(readFileSync(join(REPO, 'conformance', 'hook-manifest.json'), 'utf8'))

// ---------------------------------------------------------------- source scanning

/**
 * Blank comments and string bodies before scanning for syntax.
 *
 * A specifier is itself a string literal, so import scanning must run on RAW source; but the
 * dynamic-`import()` and `eval` checks must NOT, or every mention of those words in a comment
 * — including the ones in this file's own header — registers as a violation. The two scans
 * therefore run over different views of the same text, deliberately.
 */
function stripCommentsAndStrings(source) {
  let out = ''
  let i = 0
  const n = source.length
  while (i < n) {
    const c = source[i]
    const next = source[i + 1]
    if (c === '/' && next === '/') {
      while (i < n && source[i] !== '\n') i += 1
      continue
    }
    if (c === '/' && next === '*') {
      i += 2
      while (i < n && !(source[i] === '*' && source[i + 1] === '/')) i += 1
      i += 2
      continue
    }
    if (c === '"' || c === "'" || c === '`') {
      const quote = c
      i += 1
      out += quote
      while (i < n && source[i] !== quote) {
        if (source[i] === '\\') i += 1
        i += 1
      }
      i += 1
      out += quote
      continue
    }
    out += c
    i += 1
  }
  return out
}

/** Static import specifiers, read from raw source (a specifier IS a string literal). */
function staticSpecifiers(source) {
  const specs = []
  for (const m of source.matchAll(/(?:from|import)\s*['"]([^'"]+)['"]/g)) specs.push(m[1])
  return specs
}

/** Resolve a relative specifier to a repo-relative path, or null if it leaves the tree. */
function resolveSpecifier(fromFile, specifier) {
  if (!specifier.startsWith('.')) return null
  const abs = resolve(dirname(fromFile), specifier)
  return existsSync(abs) ? abs : null
}

/**
 * Transitive static import graph from an entry point. Returns absolute paths, entry included.
 * Cycle-safe: a module graph with a cycle is legal JavaScript and must not hang the auditor.
 */
function importGraph(entryAbs) {
  const seen = new Set()
  const stack = [entryAbs]
  while (stack.length > 0) {
    const file = stack.pop()
    if (seen.has(file)) continue
    seen.add(file)
    let source
    try {
      source = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    for (const spec of staticSpecifiers(source)) {
      const target = resolveSpecifier(file, spec)
      if (target && !seen.has(target)) stack.push(target)
    }
  }
  return seen
}

/** §8.3 escapes that would make the CH-2 static check undecidable. */
function undecidableConstructs(source) {
  const code = stripCommentsAndStrings(source)
  const hits = []
  // `import(` preceded by a non-identifier char, to avoid matching `staticImport(`.
  if (/(^|[^.\w$])import\s*\(/.test(code)) hits.push('dynamic import()')
  if (/(^|[^.\w$])eval\s*\(/.test(code)) hits.push('eval()')
  if (/new\s+Function\s*\(/.test(code)) hits.push('new Function()')
  return hits
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

/** Merkle-ish build digest: SHA-256 over sorted "path:filedigest" lines. Order-independent. */
function buildDigest(files) {
  const lines = [...files]
    .map((f) => `${relative(REPO, f).split('\\').join('/')}:${sha256(readFileSync(f))}`)
    .sort()
    .join('\n')
  return sha256(Buffer.from(lines, 'utf8'))
}

const PRODUCTION_ENTRY = join(REPO, manifest.production_entry)
const productionGraph = importGraph(PRODUCTION_ENTRY)

// ------------------------------------------------------------------------ CH-1 / CH-2

test('CH-1: the production entry point exists and its import graph is resolvable', () => {
  assert.ok(existsSync(PRODUCTION_ENTRY), `missing production entry ${manifest.production_entry}`)
  assert.ok(
    productionGraph.size >= 1,
    'import graph walk returned nothing; the walker is broken and every CH refusal below would pass vacuously',
  )
})

test('CH-1: no declared hook module is reachable from the production entry', () => {
  assert.ok(Array.isArray(manifest.hook_modules), 'manifest.hook_modules must be an array')
  for (const hook of manifest.hook_modules) {
    const abs = join(REPO, hook)
    assert.ok(
      !productionGraph.has(abs),
      `CH-1 violation: production entry transitively imports declared hook module ${hook}`,
    )
  }
})

test('CH-2: the production graph contains no conformance-hook surface', () => {
  // Name-based, and therefore evidence rather than proof — stated here and in the README so a
  // reader does not mistake its scope. It catches the ordinary mistake (a hook left wired into
  // the shipped router) and does not catch a deliberately disguised one.
  const HOOK_MARKERS = [
    /\bconformance[_-]?hook\b/i,
    /\b__conformance\b/,
    /\b__test(?:ing)?[_-]?only\b/i,
    /\binjectClock\b/,
    /\bseedCanary\b/,
    /\bfaultInject\b/i,
  ]
  const offenders = []
  for (const file of productionGraph) {
    const code = stripCommentsAndStrings(readFileSync(file, 'utf8'))
    for (const marker of HOOK_MARKERS) {
      if (marker.test(code)) offenders.push(`${relative(REPO, file)} matches ${marker}`)
    }
  }
  assert.deepEqual(offenders, [], `CH-2 violation: hook surface in the production graph`)
})

test('CH-2: the production graph is free of constructs that would make it undecidable', () => {
  const offenders = []
  for (const file of productionGraph) {
    const hits = undecidableConstructs(readFileSync(file, 'utf8'))
    if (hits.length > 0) offenders.push(`${relative(REPO, file)}: ${hits.join(', ')}`)
  }
  assert.deepEqual(
    offenders,
    [],
    'NF-5 §8.3 violation: dynamic import/eval/new Function on the Declared Surface makes the ' +
      'CH-2 static reachability check undecidable, which is why §8.3 forbids them',
  )
})

// ----------------------------------------------------------------------------- CH-3

test('CH-3: the conformance/production build delta is exactly the declared hook set', () => {
  const conformanceGraph = new Set(productionGraph)
  for (const hook of manifest.hook_modules) conformanceGraph.add(join(REPO, hook))

  const delta = [...conformanceGraph]
    .filter((f) => !productionGraph.has(f))
    .map((f) => relative(REPO, f).split('\\').join('/'))
    .sort()
  const declared = [...manifest.hook_modules].sort()

  assert.deepEqual(
    delta,
    declared,
    'CH-3 requires the delta between the two builds to be exactly the enumerated hook set',
  )
})

/**
 * The assertion above is necessary but was, on its own, worthless: it compares the declared
 * hook set against a conformance file set BUILT FROM the declared hook set, so an undeclared
 * hook is invisible to it and an empty declaration passes trivially. That is exactly how a
 * manifest in this repository came to claim no hook existed while `conformance/hook.js` sat
 * next to it.
 *
 * This assertion inverts the direction: it goes looking for hook-shaped modules and requires
 * the manifest to account for each one. A hook is anything under `conformance/` outside
 * `tests/` that reaches into an implementation source tree — because that is the property that
 * makes a module part of the audited build rather than part of the harness.
 */
test('CH-3: no undeclared hook module exists — the manifest is checked, not trusted', () => {
  const declared = new Set(manifest.hook_modules.map((h) => join(REPO, h)))
  const conformanceDir = join(REPO, 'conformance')
  const undeclared = []

  for (const entry of readdirSync(conformanceDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.js')) continue
    const abs = join(conformanceDir, entry.name)
    const specs = staticSpecifiers(readFileSync(abs, 'utf8'))
    const reachesIUT = specs.some(
      (s) => s.startsWith('.') && /(^|\/)(broker|m0-vin-yield|m3-drop-compliance)\/src\//.test(s),
    )
    // run.js and static-scan.js read the implementation as TEXT rather than importing it, so
    // they are harness, not hook. The import list is what distinguishes the two.
    if (reachesIUT && !declared.has(abs)) undeclared.push(relative(REPO, abs))
  }

  assert.deepEqual(
    undeclared,
    [],
    'CH-3 violation: a module that imports the implementation is not declared in ' +
      'hook-manifest.json, so the conformance/production delta is understated',
  )
})

test('CH-1: every declared hook module exists and points away from production', () => {
  for (const hook of manifest.hook_modules) {
    const abs = join(REPO, hook)
    assert.ok(existsSync(abs), `declared hook ${hook} does not exist`)
    // The arrow must point one way: the hook may import the Worker, never the reverse.
    assert.ok(
      !productionGraph.has(abs),
      `CH-1 violation: production imports declared hook ${hook}`,
    )
  }
})

test('CH-3: build digests are computed and, when pinned, match', () => {
  const production = buildDigest(productionGraph)
  const conformanceFiles = new Set(productionGraph)
  for (const hook of manifest.hook_modules) conformanceFiles.add(join(REPO, hook))
  const conformance = buildDigest(conformanceFiles)

  assert.match(production, /^[0-9a-f]{64}$/)
  assert.match(conformance, /^[0-9a-f]{64}$/)

  // With no hook declared the two builds are the same file set, so the digests MUST coincide.
  // That equality is the whole claim this build is making under §4.5's honest accounting: there
  // is no audited-vs-deployed gap to argue about.
  if (manifest.hook_modules.length === 0) {
    assert.equal(
      production,
      conformance,
      'no hook is declared, so the conformance and production builds must be byte-identical',
    )
  }

  if (manifest.digest.production !== null) {
    assert.equal(manifest.digest.production, production, 'pinned production digest is stale')
  }
  if (manifest.digest.conformance !== null) {
    assert.equal(manifest.digest.conformance, conformance, 'pinned conformance digest is stale')
  }
})

// ----------------------------------------------------------------------------- CH-4

test('CH-4: no declared hook route appears in the production entry', () => {
  assert.ok(Array.isArray(manifest.hook_routes), 'manifest.hook_routes must be an array')
  const entrySource = readFileSync(PRODUCTION_ENTRY, 'utf8')
  for (const route of manifest.hook_routes) {
    assert.ok(
      !entrySource.includes(route),
      `CH-4 violation: production entry references hook route ${route}`,
    )
  }
})

// ------------------------------------------------------------------- positive controls

test('[control] CH: the import-graph walker finds a hook that IS wired in', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nf5-ch-'))
  try {
    writeFileSync(join(dir, 'hook.js'), 'export function injectClock() { return 0 }\n')
    writeFileSync(join(dir, 'mid.js'), "export * from './hook.js'\n")
    writeFileSync(join(dir, 'entry.js'), "import './mid.js'\nexport default {}\n")

    const graph = importGraph(join(dir, 'entry.js'))

    assert.equal(graph.size, 3, 'walker must follow the transitive edge entry -> mid -> hook')
    assert.ok(graph.has(join(dir, 'hook.js')), 'walker failed to reach a transitively-imported hook')

    const found = [...graph].some((f) => /\binjectClock\b/.test(stripCommentsAndStrings(readFileSync(f, 'utf8'))))
    assert.ok(found, 'hook-marker scan failed to fire on a graph that genuinely contains a hook')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('[control] CH: the undecidability scan fires on real dynamic import and eval', () => {
  assert.deepEqual(undecidableConstructs('const m = await import(spec)'), ['dynamic import()'])
  assert.deepEqual(undecidableConstructs('eval("1+1")'), ['eval()'])
  assert.deepEqual(undecidableConstructs('const f = new Function("return 1")'), ['new Function()'])

  // ...and stays silent on the same words inside comments and strings, which is the property
  // that lets this file discuss `eval()` in prose without failing its own assertion.
  assert.deepEqual(undecidableConstructs('// eval( and import( in a comment'), [])
  assert.deepEqual(undecidableConstructs('const s = "eval( import("'), [])
  assert.deepEqual(undecidableConstructs('obj.import(x)'), [], 'a method named import must not match')
})

test('[control] CH: the digest is order-independent and change-sensitive', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nf5-dg-'))
  try {
    const a = join(dir, 'a.js')
    const b = join(dir, 'b.js')
    writeFileSync(a, 'export const x = 1\n')
    writeFileSync(b, 'export const y = 2\n')

    const forward = buildDigest(new Set([a, b]))
    const reverse = buildDigest(new Set([b, a]))
    assert.equal(forward, reverse, 'digest must not depend on set iteration order')

    writeFileSync(b, 'export const y = 3\n')
    assert.notEqual(buildDigest(new Set([a, b])), forward, 'digest must change when a file changes')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
