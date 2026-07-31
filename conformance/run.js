/**
 * NF-5 conformance runner — one summarised verdict, per NF-5 area, fit for a badge decision.
 *
 * Nimbus Foundation NF-5 §4.1 (the suite is the definition), §4.2 (two profiles), §4.3
 * (harness constraints), §4.6 (verdicts), §4.7 (positive controls), §4.9 (assertion groups).
 *
 * WHY THIS IS NOT `node --test`. `node --test` prints a pass count, and a pass count is the
 * wrong shape for the decision this suite exists to inform. NF-5 §4.1 says the Prime tier
 * follows *automatically* from the outcome, which means the outcome has to be computed the
 * same way by anyone — and it means the outcome must not be able to read green for the one
 * reason a badge system can never survive: an area with no tests in it. A raw dump of 281
 * passing assertions says nothing about whether group CH was exercised at all. So this runner
 * maps every assertion to the NF-5 group it evidences, and an area with zero passing
 * assertions is UNEVIDENCED, which counts as FAIL exactly as §4.6 makes INCONCLUSIVE count as
 * FAIL. Silent absence of coverage is the failure mode a badge must not have.
 *
 * WHAT IT DOES NOT DO. It does not adjudicate. Every rule below is arithmetic over an
 * enumerated mapping, so a second implementer reading this file computes the same verdict
 * (§4.1, §4.4). There is no waiver flag, no `--force`, no allowlist and no way to mark a
 * failing area as accepted — NF-5 §2 says there is no partial credit and no waiver, and a
 * runner with an override switch is a runner that has re-introduced the discretion §1 removes.
 *
 * NF-5 §4.3: plain ES modules, no npm, no build step. `node:test` and `node:assert` are the
 * single permitted relaxation and are used only by the test files; this runner uses `node:test`'s
 * programmatic `run()` and nothing else beyond Node built-ins and web-standard APIs.
 */

import { run } from 'node:test'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import process from 'node:process'

import { LIMITATIONS, scan, stripNonCode } from './static-scan.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const TESTS_DIR = join(HERE, 'tests')
const SUITE_VERSION = 'NF5/1.0'

// ---------------------------------------------------------------------------------
// The areas (NF-5 §4.9)
// ---------------------------------------------------------------------------------

/**
 * The six assertion groups NF-5 §4.9 declares, plus one supplementary area that is explicitly
 * NOT an NF-5 group and is labelled as such everywhere it appears.
 *
 * `assertionsPublished` records a fact about the specification as it stands in this repository
 * rather than about the implementation: NF-5 as written stops after §6. Groups NT (§5) and DD
 * (§6) have numbered, normative assertions; RV (§7), VC (§8) and GC (§5.6) are declared in the
 * §4.9 table and in §3's terminology but their assertion text is absent from the document. The
 * runner reports that, because an area whose evidence is mapped by file rather than matched to
 * a published assertion id is an area where two implementers could disagree — which is exactly
 * what §4.9's closing sentence ("Two implementers reading Inputs + Procedure + Pass MUST be
 * able to produce tests that agree") requires not to happen.
 */
const AREAS = Object.freeze([
  {
    id: 'NT',
    title: 'Non-transactability of the forbidden field classes',
    spec: 'NF-5 §5',
    kind: 'nf5-group',
    assertionsPublished: true,
  },
  {
    id: 'DD',
    title: 'Delegation-depth enforcement',
    spec: 'NF-5 §6',
    kind: 'nf5-group',
    assertionsPublished: true,
  },
  {
    id: 'RV',
    title: 'Revocation propagation within the staleness bound',
    spec: 'NF-5 §7 (declared in §4.9; assertion text absent)',
    kind: 'nf5-group',
    assertionsPublished: false,
  },
  {
    id: 'VC',
    title: 'Absence of VIN-to-credential resolution',
    spec: 'NF-5 §8 (declared in §4.9; assertion text absent)',
    kind: 'nf5-group',
    assertionsPublished: false,
  },
  {
    id: 'GC',
    title: 'Grant core — shape, signature, commitment, non-transferability',
    spec: 'NF-5 §5.6 (declared in §4.9; assertion text absent)',
    kind: 'nf5-group',
    assertionsPublished: false,
  },
  {
    id: 'CH',
    title: 'Conformance-hook hygiene',
    spec: 'NF-5 §4.5 (CH-1..CH-4)',
    kind: 'nf5-group',
    assertionsPublished: true,
  },
  {
    id: 'DA',
    title: 'SUPPLEMENTARY — Delete Act / erasure cadence clocks',
    spec: 'not an NF-5 group; NF-WP-1 §9.5, NF-5 §1.1 disclaims legal-compliance certification',
    kind: 'supplementary',
    assertionsPublished: false,
  },
])

/**
 * Test file -> the area(s) it evidences.
 *
 * The mapping is declared, not inferred, for two reasons. First, §4.9 requires that the
 * evidence for a group be identifiable; a heuristic over test names would make the rollup a
 * guess. Second, a file that appears in `tests/` and is absent from this table is a file whose
 * assertions would be counted nowhere — so the runner treats an undeclared file as a harness
 * error rather than quietly running it and attributing it to nothing.
 *
 * `route` is used where one file evidences several groups. Only `grant.test.js` does; its
 * assertions carry §4.9 identifiers in their names, and those identifiers are authoritative
 * over any file-level default.
 */
const FILE_MAP = Object.freeze({
  'fields.test.js': { areas: ['NT'] },
  'jcs.test.js': { areas: ['GC'] },
  'vin.test.js': { areas: ['VC'] },
  'resolve.test.js': { areas: ['VC'] },
  'revocation.test.js': { areas: ['RV'] },
  'clocks.test.js': { areas: ['DA'] },
  'hooks.test.js': { areas: ['CH'] },
  'protocol-vectors.test.js': {
    areas: ['NT', 'DD', 'RV', 'VC', 'GC'],
    route: routeProtocolAssertion,
  },
  'grant.test.js': { areas: ['NT', 'DD', 'GC', 'VC'], route: routeGrantAssertion },
})

/**
 * Attribute one `grant.test.js` assertion. A published NF-5 identifier in the name wins
 * outright. Otherwise: the Refusal-1 assertions (the raw VIN never inside the signed bytes,
 * no VIN-shaped grant key) are the VIN-to-credential property and belong to VC; everything
 * else — shape, canonical bytes, signature, tamper detection, commitment, counterparty
 * binding, expiry — is grant core, GC.
 */
/**
 * Attribute one PROTOCOL-profile assertion. Names are prefixed with the group id they
 * evidence (`GC [protocol]: ...`), so the mapping is read off the name rather than guessed.
 *
 * A corpus-level control (`[control] the vector corpus is non-empty ...`) guards every group
 * in the file at once: if the corpus were empty, every per-group assertion would iterate
 * nothing and pass. Attributing those controls to ALL of the file's groups is therefore
 * accurate rather than generous — one control genuinely does establish non-vacuity for each.
 */
function routeProtocolAssertion(name) {
  const id = /^([A-Z]{2}) \[protocol\]/.exec(name)
  if (id) return [id[1]]
  if (/\[control\]/.test(name)) return ['NT', 'DD', 'RV', 'VC', 'GC']
  return ['GC']
}

function routeGrantAssertion(name) {
  const id = /NF5-([A-Z]{2})-\d{3}/.exec(name)
  if (id) return [id[1]]
  if (/REFUSAL 1/.test(name)) return ['VC']
  return ['GC']
}

// ---------------------------------------------------------------------------------
// Preflight (NF-5 §4.3)
// ---------------------------------------------------------------------------------

/**
 * §4.3: Ed25519 MUST be obtained by feature-detecting `{ name: 'Ed25519' }` and falling back to
 * the legacy Workers name `NODE-ED25519`. A run that resolves neither MUST report INCONCLUSIVE
 * for every signature-dependent assertion — and §4.6 makes INCONCLUSIVE count as FAIL. The
 * probe is here, before anything runs, so that a signature-blind runtime produces one honest
 * line at the top rather than a hundred confusing assertion failures.
 */
async function probeEd25519() {
  for (const algorithm of ['Ed25519', 'NODE-ED25519']) {
    try {
      const pair = await crypto.subtle.generateKey({ name: algorithm }, true, ['sign', 'verify'])
      if (pair?.privateKey) return { available: true, algorithm }
    } catch {
      // Try the next name. A throw here is the feature detection working.
    }
  }
  return { available: false, algorithm: null }
}

/** Areas whose assertions cannot be evaluated without a working Ed25519 implementation. */
const SIGNATURE_DEPENDENT = Object.freeze(['NT', 'DD', 'RV', 'VC', 'GC'])

// ---------------------------------------------------------------------------------
// Static properties of the test files (profile, determinism)
// ---------------------------------------------------------------------------------

/**
 * §4.2: a MODULE-profile assertion imports from `broker/src/` and calls its exports directly;
 * a PROTOCOL-profile assertion speaks only to artifacts and observable interfaces. The
 * distinction is decidable from the import list, so it is decided from the import list rather
 * than from a claim in a header comment.
 *
 * Import specifiers are read from the RAW source, not from the lexed source, because a
 * specifier IS a string literal and the lexer blanks string contents by design.
 */
function profileOf(source) {
  const specifiers = [...source.matchAll(/from\s*['"]([^'"]+)['"]/g)].map((m) => m[1])
  // Any relative import into an implementation source tree is a MODULE-profile binding, not
  // just `broker/src`: a file that reaches into `m3-drop-compliance/src` is calling the IUT's
  // exports directly and is bound to this implementation exactly as tightly.
  const touchesModules = specifiers.some(
    (s) => s.startsWith('.') && /(^|\/)(broker|m0-vin-yield|m3-drop-compliance)\/src\//.test(s),
  )
  return touchesModules ? 'M' : 'P'
}

/**
 * §4.4(2)-(3): no wall clock and no unseeded randomness in an assertion's decision path.
 *
 * This is reported as an ADVISORY and never gates the verdict, and the reason is worth stating
 * plainly rather than burying: distinguishing `Date.now()` in a decision path from `Date.now`
 * captured and deliberately broken to prove a module never reads the ambient clock requires a
 * dataflow analysis this harness does not have. `clocks.test.js` does exactly the latter. A
 * gate here would fail a file for holding the line harder than the rule requires, so the
 * runner names the occurrences and leaves the judgement to a reader.
 */
function determinismAdvisory(source) {
  const { code } = stripNonCode(source)
  const count = (re) => (code.match(re) ?? []).length
  return {
    dateNow: count(/\bDate\s*\.\s*now\b/g),
    mathRandom: count(/\bMath\s*\.\s*random\b/g),
    randomUUID: count(/\brandomUUID\b/g),
    getRandomValues: count(/\bgetRandomValues\b/g),
  }
}

// ---------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------

function emptyArea(area) {
  return {
    ...area,
    files: [],
    profiles: new Set(),
    assertions: [],
    pass: 0,
    fail: 0,
    inconclusive: 0,
    controls: 0,
    controlsFailed: 0,
    failures: [],
  }
}

/**
 * Drive `node:test` over the declared files and fold every assertion into its area(s).
 *
 * Suites are skipped (`details.type === 'suite'`) so that a `describe` block is not counted as
 * an assertion alongside the assertions inside it. Skipped and TODO assertions are counted as
 * INCONCLUSIVE, per §4.6: a test that did not run is a check that could not be evaluated, and
 * treating it as "no finding" would make every mandatory assertion optional for anyone able to
 * add `{ skip: true }`.
 */
async function executeTests(files, areas) {
  const unattributed = []
  const stream = run({ files: files.map((f) => f.abs), concurrency: true })

  // `data.file` is the path Node resolved, which is not necessarily the path handed to
  // `run()` — a symlinked checkout reports the realpath, and an exact-path lookup then
  // attributes every assertion to no area at all. That failure is silent in the worst
  // possible way: the totals still look plausible while every group reads UNEVIDENCED. Match
  // on the absolute path first and fall back to the basename, which is unique because the
  // FILE_MAP keys are.
  const byAbs = new Map(files.map((f) => [f.abs, f]))
  const byBase = new Map(files.map((f) => [f.name, f]))
  const basename = (p) => String(p ?? '').split(/[\\/]/).pop()

  const record = (data, outcome, error) => {
    if (data?.details?.type === 'suite') return
    const file = byAbs.get(data.file) ?? byBase.get(basename(data.file))
    if (!file) {
      unattributed.push({ name: data?.name, file: data?.file, outcome })
      return
    }
    const name = String(data.name ?? '')
    const targets = file.route ? file.route(name) : file.areas
    const isControl = /\[control\]/.test(name)
    for (const id of targets) {
      const area = areas.get(id)
      if (!area) {
        unattributed.push({ name, file: data.file, outcome, reason: `unknown area ${id}` })
        continue
      }
      area.assertions.push({ name, outcome, file: file.name })
      area[outcome] += 1
      if (isControl) {
        area.controls += 1
        if (outcome !== 'pass') area.controlsFailed += 1
      }
      if (outcome !== 'pass') {
        area.failures.push({ file: file.name, name, error: error ?? null, outcome })
      }
    }
  }

  for await (const event of stream) {
    if (event.type === 'test:pass') {
      const skipped = event.data?.skip === true || event.data?.todo === true
      record(event.data, skipped ? 'inconclusive' : 'pass')
    } else if (event.type === 'test:fail') {
      const err = event.data?.details?.error
      record(event.data, 'fail', String(err?.message ?? err ?? 'unknown failure').split('\n')[0])
    }
  }

  return { unattributed }
}

// ---------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------

/**
 * Area verdict. The order of the tests is the order of §4.6 and §4.7:
 *
 *  - zero assertions  -> UNEVIDENCED. An area with no tests must never read as conformant.
 *  - any INCONCLUSIVE -> INCONCLUSIVE (counts as FAIL, §4.6).
 *  - any FAIL         -> FAIL.
 *  - no positive control -> NO-CONTROL. §4.7: a group whose verdict rests entirely on refusals
 *    is satisfied by an implementation that refuses everything, including one that is not
 *    running. A group without a passing control has not been shown to do anything.
 *  - otherwise        -> PASS.
 */
function areaVerdict(area) {
  const total = area.pass + area.fail + area.inconclusive
  if (total === 0) return 'UNEVIDENCED'
  if (area.inconclusive > 0) return 'INCONCLUSIVE'
  if (area.fail > 0) return 'FAIL'
  if (area.controls === 0 || area.controlsFailed > 0) return 'NO-CONTROL'
  return 'PASS'
}

const PASSING = new Set(['PASS'])

function buildGates(areas, staticResult, ed25519, unattributed, undeclared, missing) {
  const groups = [...areas.values()].filter((a) => a.kind === 'nf5-group')
  const gates = []

  gates.push({
    id: '§4.3',
    title: 'Ed25519 resolves; signature-dependent areas are evaluable',
    ok: ed25519.available,
    detail: ed25519.available
      ? `resolved as { name: '${ed25519.algorithm}' }`
      : `unresolvable — ${SIGNATURE_DEPENDENT.join(', ')} are INCONCLUSIVE, which §4.6 counts as FAIL`,
  })

  gates.push({
    id: 'harness',
    title: 'Every test file is declared, and every declared file exists',
    ok: undeclared.length === 0 && missing.length === 0 && unattributed.length === 0,
    detail:
      undeclared.length === 0 && missing.length === 0 && unattributed.length === 0
        ? `${[...areas.values()].reduce((n, a) => n + a.files.length, 0)} file-to-area bindings, no orphans`
        : [
            undeclared.length ? `undeclared in tests/: ${undeclared.join(', ')}` : '',
            missing.length ? `declared but absent: ${missing.join(', ')}` : '',
            unattributed.length ? `${unattributed.length} assertion(s) attributed to no area` : '',
          ]
            .filter(Boolean)
            .join(' · '),
  })

  const unevidenced = groups.filter((a) => areaVerdict(a) === 'UNEVIDENCED')
  gates.push({
    id: '§4.9',
    title: 'Every declared NF-5 group has at least one passing assertion',
    ok: unevidenced.length === 0,
    detail: unevidenced.length === 0
      ? `${groups.length}/${groups.length} groups evidenced`
      : `UNEVIDENCED: ${unevidenced.map((a) => a.id).join(', ')} — no assertion in the suite maps here`,
  })

  const noControl = groups.filter((a) => a.controls === 0 || a.controlsFailed > 0)
  gates.push({
    id: '§4.7',
    title: 'Every group carries a passing positive control (vacuity)',
    ok: noControl.length === 0,
    detail: noControl.length === 0
      ? `${groups.reduce((n, a) => n + a.controls, 0)} controls, all passing`
      : `no passing [control] in: ${noControl.map((a) => a.id).join(', ')}`,
  })

  const failing = groups.filter((a) => a.fail > 0 || a.inconclusive > 0)
  gates.push({
    id: '§4.6',
    title: 'Every mandatory assertion is PASS (INCONCLUSIVE counts as FAIL)',
    ok: failing.length === 0,
    detail: failing.length === 0
      ? `${groups.reduce((n, a) => n + a.pass, 0)} assertions passing in NF-5 groups, 0 failing, 0 inconclusive`
      : failing.map((a) => `${a.id}: ${a.fail} fail / ${a.inconclusive} inconclusive`).join(' · '),
  })

  const noProtocol = groups.filter((a) => !a.profiles.has('P'))
  gates.push({
    id: '§4.2',
    title: 'Every group has PROTOCOL-profile evidence (MODULE alone is never the gate)',
    ok: noProtocol.length === 0,
    detail: noProtocol.length === 0
      ? 'every group is evidenced over artifacts and observable interfaces'
      : `MODULE profile only: ${noProtocol.map((a) => a.id).join(', ')} — §4.2 requires the Prime ` +
        'tier to be attainable through the PROTOCOL profile alone, so an implementation reusing ' +
        'none of broker/src/ cannot currently be assessed by this suite',
  })

  gates.push({
    id: 'VC/static',
    title: 'Group VC static scan (evidence, not proof — see README limitations)',
    ok: staticResult.ok,
    detail: staticResult.ok
      ? `${staticResult.checks.length} checks clean over ${staticResult.files.length} files; ` +
        `${staticResult.controls.filter((c) => c.ok).length}/${staticResult.controls.length} scanner self-controls pass`
      : `${staticResult.findings.length} finding(s); ` +
        `${staticResult.checks.filter((c) => c.verdict !== 'PASS').map((c) => `${c.id}=${c.verdict}`).join(', ')}`,
  })

  return gates
}

// ---------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------

const pad = (s, n) => String(s).padEnd(n)
const num = (s, n) => String(s).padStart(n)

function formatReport(r) {
  const L = []
  L.push('════════════════════════════════════════════════════════════════════════════════')
  L.push(' NIMBUS FOUNDATION — NF-5 CONFORMANCE RUN')
  L.push(` suite ${r.suite} · ${r.startedAt} · node ${r.node}`)
  L.push('════════════════════════════════════════════════════════════════════════════════')
  L.push('')
  L.push('PREFLIGHT')
  L.push(`  Ed25519 (WebCrypto)      ${r.ed25519.available ? `available as { name: '${r.ed25519.algorithm}' }` : 'UNRESOLVABLE'}`)
  L.push(`  test files declared      ${r.files.length}`)
  L.push(`  test files discovered    ${r.discovered.length}`)
  L.push(`  undeclared / missing     ${r.undeclared.length} / ${r.missing.length}`)
  L.push('')
  L.push('FILE → AREA MAP')
  L.push(`  ${pad('FILE', 22)}${pad('PROFILE', 9)}${pad('AREAS', 16)}ASSERTIONS`)
  for (const f of r.files) {
    L.push(`  ${pad(f.name, 22)}${pad(f.profile === 'M' ? 'MODULE' : 'PROTOCOL', 9)}${pad(f.areas.join(','), 16)}${f.count}`)
  }
  L.push('')
  L.push('AREA ROLLUP (NF-5 §4.9)')
  L.push(
    `  ${pad('ID', 4)}${pad('AREA', 44)}${num('PASS', 5)}${num('FAIL', 5)}${num('INC', 4)}${num('CTRL', 5)}  ${pad('PROF', 5)}VERDICT`,
  )
  for (const a of r.areas) {
    const id = a.kind === 'nf5-group' ? a.id : `${a.id}*`
    L.push(
      `  ${pad(id, 4)}${pad(a.title.slice(0, 43), 44)}${num(a.pass, 5)}${num(a.fail, 5)}${num(a.inconclusive, 4)}${num(a.controls, 5)}  ${pad([...a.profiles].sort().join('') || '—', 5)}${a.verdict}`,
    )
  }
  L.push('')
  L.push('  Legend  PASS = every assertion passed and a positive control passed.')
  L.push('          UNEVIDENCED = no assertion in this suite maps to this area. Counts as FAIL.')
  L.push('          NO-CONTROL = only refusals were asserted (§4.7 vacuity). Counts as FAIL.')
  L.push('          INCONCLUSIVE = could not be evaluated. §4.6 counts it as FAIL.')
  L.push('          PROF: M = MODULE profile, P = PROTOCOL profile (§4.2).')
  L.push('          *   = supplementary area. Reported, never gated: NF-5 §1.1 disclaims any')
  L.push('                certification of legal compliance, so these assertions inform a reader')
  L.push('                and contribute nothing to the tier.')
  L.push('')

  const specGap = r.areas.filter((a) => a.kind === 'nf5-group' && !a.assertionsPublished)
  if (specGap.length) {
    L.push('SPECIFICATION COVERAGE')
    L.push('  NF-5 as published in specs/ ends after §6. These groups are declared in the §4.9')
    L.push('  table but carry no numbered assertion text, so their evidence is mapped by file')
    L.push('  rather than matched to a published assertion id:')
    for (const a of specGap) L.push(`    ${a.id}  ${a.spec}`)
    L.push('  Two implementers can therefore disagree about what these areas require. That is a')
    L.push('  defect in the specification, not in the implementation, and it is reported rather')
    L.push('  than papered over.')
    L.push('')
  }

  L.push('DETERMINISM ADVISORY (NF-5 §4.4 — reported, never gated)')
  const flagged = r.files.filter((f) => Object.values(f.determinism).some((v) => v > 0))
  if (flagged.length === 0) {
    L.push('  no ambient-clock or unseeded-randomness call sites in any test file')
  } else {
    for (const f of flagged) {
      const parts = Object.entries(f.determinism)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => `${k}×${v}`)
      L.push(`  ${pad(f.name, 22)}${parts.join('  ')}`)
    }
    L.push('  These are call sites in code, not in comments. The harness cannot tell a decision-')
    L.push('  path read from a deliberately broken clock used to prove a module never reads one,')
    L.push('  so it names them and gates nothing.')
  }
  L.push('')

  L.push('GATES')
  for (const g of r.gates) {
    L.push(`  ${pad(g.id, 10)}${g.ok ? 'PASS' : 'FAIL'}  ${g.title}`)
    for (const line of wrap(g.detail, 74)) L.push(`              ${line}`)
  }
  L.push('')

  if (r.failures.length) {
    L.push(`FAILING ASSERTIONS (${r.failures.length})`)
    for (const f of r.failures.slice(0, 40)) {
      L.push(`  [${f.area}] ${f.file}`)
      L.push(`      ${f.name}`)
      if (f.error) L.push(`      → ${f.error}`)
    }
    if (r.failures.length > 40) L.push(`  … ${r.failures.length - 40} more`)
    L.push('')
  }

  L.push('STATIC-SCAN CAVEAT (group VC)')
  L.push('  The VC static scan is EVIDENCE, NOT PROOF. It is a syntactic argument over names,')
  L.push('  parameter lists and returned object literals, with no dataflow and no call graph.')
  L.push('  A real VIN-to-credential path survives it if it is split across two functions, named')
  L.push('  innocuously, assembled with computed keys, or returned through a header, a cache or')
  L.push('  a database row. Run `node conformance/static-scan.js` for the full enumeration; the')
  L.push('  first three defeats are:')
  for (const lim of LIMITATIONS.slice(0, 3)) {
    for (const line of wrap(lim, 74)) L.push(`    ${line}`)
  }
  L.push('')

  L.push('════════════════════════════════════════════════════════════════════════════════')
  L.push(' VERDICT')
  L.push('════════════════════════════════════════════════════════════════════════════════')
  L.push(`  assertions executed   ${r.totals.pass + r.totals.fail + r.totals.inconclusive}`)
  L.push(`  passed / failed / inc ${r.totals.pass} / ${r.totals.fail} / ${r.totals.inconclusive}`)
  L.push(`  NF-5 groups PASS      ${r.totals.groupsPassing}/${r.totals.groups}`)
  L.push(`  gates PASS            ${r.gates.filter((g) => g.ok).length}/${r.gates.length}`)
  L.push('')
  L.push(`  NF-5 PRIME-IMPLEMENTER TIER: ${r.verdict}`)
  if (r.verdict !== 'PASS') {
    L.push('')
    L.push('  Blocking:')
    for (const b of r.blocking) {
      const lines = wrap(b, 70)
      L.push(`    - ${lines[0]}`)
      for (const line of lines.slice(1)) L.push(`      ${line}`)
    }
  }
  L.push('')
  return L.join('\n')
}

function wrap(text, width) {
  const out = []
  let line = ''
  for (const word of String(text).split(/\s+/)) {
    if (line && `${line} ${word}`.length > width) {
      out.push(line)
      line = word
    } else {
      line = line ? `${line} ${word}` : word
    }
  }
  if (line) out.push(line)
  return out
}

// ---------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------

async function main(argv) {
  const asJson = argv.includes('--json')
  const startedAt = new Date().toISOString()

  const discovered = readdirSync(TESTS_DIR)
    .filter((n) => n.endsWith('.test.js'))
    .sort()
  const declared = Object.keys(FILE_MAP).sort()
  const undeclared = discovered.filter((n) => !declared.includes(n))
  const missing = declared.filter((n) => !discovered.includes(n))

  const files = declared
    .filter((n) => discovered.includes(n))
    .map((name) => {
      const abs = join(TESTS_DIR, name)
      const source = readFileSync(abs, 'utf8')
      return {
        name,
        abs,
        areas: FILE_MAP[name].areas,
        route: FILE_MAP[name].route,
        profile: profileOf(source),
        determinism: determinismAdvisory(source),
        count: 0,
      }
    })

  const areas = new Map(AREAS.map((a) => [a.id, emptyArea(a)]))
  for (const f of files) {
    for (const id of f.areas) {
      const area = areas.get(id)
      if (area) {
        area.files.push(f.name)
        area.profiles.add(f.profile)
      }
    }
  }

  const ed25519 = await probeEd25519()
  const { unattributed } = await executeTests(files, areas)
  const staticResult = await scan()

  for (const f of files) {
    f.count = [...areas.values()]
      .flatMap((a) => a.assertions)
      .filter((x) => x.file === f.name).length
  }
  // An assertion counted in two areas is one assertion; de-duplicate per file.
  for (const f of files) {
    const seen = new Set()
    for (const a of areas.values()) {
      for (const x of a.assertions) if (x.file === f.name) seen.add(x.name)
    }
    f.count = seen.size
  }

  const areaRows = [...areas.values()].map((a) => ({
    id: a.id,
    title: a.title,
    spec: a.spec,
    kind: a.kind,
    assertionsPublished: a.assertionsPublished,
    files: a.files,
    profiles: a.profiles,
    pass: a.pass,
    fail: a.fail,
    inconclusive: a.inconclusive,
    controls: a.controls,
    controlsFailed: a.controlsFailed,
    verdict: areaVerdict(a),
  }))

  const gates = buildGates(areas, staticResult, ed25519, unattributed, undeclared, missing)
  const groups = areaRows.filter((a) => a.kind === 'nf5-group')

  const failures = [...areas.values()].flatMap((a) => a.failures.map((f) => ({ area: a.id, ...f })))
  const blocking = []
  for (const g of gates) if (!g.ok) blocking.push(`${g.id} — ${g.title}: ${g.detail}`)

  const totals = {
    pass: [...areas.values()].reduce((n, a) => n + a.pass, 0),
    fail: [...areas.values()].reduce((n, a) => n + a.fail, 0),
    inconclusive: [...areas.values()].reduce((n, a) => n + a.inconclusive, 0),
    groups: groups.length,
    groupsPassing: groups.filter((a) => PASSING.has(a.verdict)).length,
  }

  // The Prime verdict is the conjunction of every gate. There is no other input, and no way
  // to supply one (§4.1: no criterion may be added except by a versioned amendment).
  const verdict = gates.every((g) => g.ok) ? 'PASS' : 'FAIL'
  // The suite result is broader than the tier: a supplementary area that fails is still a
  // failing test run, and a run that failed must not exit 0.
  const suiteClean = totals.fail === 0 && totals.inconclusive === 0 && staticResult.ok

  const report = {
    suite: SUITE_VERSION,
    startedAt,
    node: process.version,
    ed25519,
    discovered,
    undeclared,
    missing,
    unattributed,
    files: files.map((f) => ({
      name: f.name,
      areas: f.areas,
      profile: f.profile,
      determinism: f.determinism,
      count: f.count,
    })),
    areas: areaRows,
    gates,
    failures,
    totals,
    static: staticResult,
    blocking,
    verdict,
    suiteClean,
  }

  process.stdout.write(asJson ? `${JSON.stringify(report, null, 2)}\n` : `${formatReport(report)}\n`)
  return verdict === 'PASS' && suiteClean ? 0 : 1
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
  },
  (err) => {
    process.stderr.write(`run.js: harness error: ${err?.stack ?? err}\n`)
    process.exitCode = 2
  },
)
