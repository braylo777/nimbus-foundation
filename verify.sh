#!/usr/bin/env bash
#
# Nimbus Foundation IoV — full verification.
#
#   ./verify.sh
#
# One command, one exit code. Runs every check that can run without a deployment or a network:
# the conformance suite, the NF-5 tier verdict, the static VIN-to-credential scan, a parse check
# over every module, the three D1 schemas, and the binding no-npm/no-build-step stack constraint.
#
# Exit 0 means every gate passed. Anything else means do not ship.
#
# Requires: node >= 20 (uses node:test). sqlite3 is optional — schema checks are skipped with a
# visible notice if it is absent, never silently.

set -uo pipefail
cd "$(dirname "$0")"

FAILURES=0
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '   \033[31mFAIL\033[0m  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
skip() { printf '   \033[33mSKIP\033[0m  %s\n' "$1"; }

step "1/6  Conformance suite (node:test)"
if node --test conformance/tests/*.test.js >/tmp/nf-suite.log 2>&1; then
  ok "$(awk '/ pass [0-9]+/ {print $NF; exit}' /tmp/nf-suite.log) assertions passed, $(awk '/ fail [0-9]+/ {print $NF; exit}' /tmp/nf-suite.log) failed"
else
  bad "test failures — see /tmp/nf-suite.log"
  grep -E '^✖|not ok' /tmp/nf-suite.log | head -20
fi

step "2/6  NF-5 tier verdict"
if node conformance/run.js >/tmp/nf-tier.log 2>&1; then
  ok "$(grep 'TIER:' /tmp/nf-tier.log | sed 's/^ *//')"
else
  bad "NF-5 tier FAIL — see /tmp/nf-tier.log"
  sed -n '/Blocking:/,$p' /tmp/nf-tier.log | head -20
fi

step "3/6  Static VIN-to-credential scan (evidence, not proof — see conformance/README.md)"
if node conformance/static-scan.js >/tmp/nf-scan.log 2>&1; then
  ok "no credential-minting shape found on the declared surface"
else
  bad "static scan flagged a candidate path — see /tmp/nf-scan.log"
fi

step "4/6  Every module parses"
PARSE_FAIL=0
while IFS= read -r f; do
  node --check "$f" 2>/dev/null || { bad "parse error: $f"; PARSE_FAIL=1; }
done < <(find broker m0-vin-yield m3-drop-compliance conformance -name '*.js')
[ "$PARSE_FAIL" -eq 0 ] && ok "$(find broker m0-vin-yield m3-drop-compliance conformance -name '*.js' | wc -l | tr -d ' ') JavaScript files"

step "5/6  D1 schemas apply"
if command -v sqlite3 >/dev/null 2>&1; then
  for s in broker/schema.sql m0-vin-yield/schema.sql m3-drop-compliance/schema.sql; do
    if sqlite3 :memory: ".read $s" 2>/tmp/nf-sql.log; then ok "$s"; else bad "$s — $(head -2 /tmp/nf-sql.log)"; fi
  done
else
  skip "sqlite3 not installed; schema syntax unverified"
fi

step "6/6  Binding stack constraint (NF-WP-1 §14: no npm, no build step)"
# The conformance suite may use node:test/node:assert/node:fs/node:crypto — Node built-ins that
# require no install. Everything else must be Web-standard. A package.json, a node_modules, or a
# TypeScript file in a V1 directory means the constraint has been broken.
VIOLATIONS=$(find broker m0-vin-yield m3-drop-compliance conformance specs \
  \( -name 'package.json' -o -name 'node_modules' -o -name '*.ts' -o -name '*.tsx' \
     -o -name 'tsconfig.json' -o -name '*.config.js' \) 2>/dev/null)
if [ -z "$VIOLATIONS" ]; then
  ok "no package.json, node_modules, TypeScript or bundler config in V1"
else
  bad "stack constraint violated:"; echo "$VIOLATIONS" | sed 's/^/         /'
fi

printf '\n════════════════════════════════════════════════════════════\n'
if [ "$FAILURES" -eq 0 ]; then
  printf ' \033[32mALL GATES PASS\033[0m\n'
  printf '\n Not covered here — these need a deployment or a network:\n'
  printf '   · M0 has never run against live vPIC. Until it does, the load-bearing\n'
  printf '     data assumption is UNTESTED (NF-WP-1 §13.1) and M1 is not cleared.\n'
  printf '   · The DROP adapter is a declared stub. The real CPPA interface is not\n'
  printf '     published in NF-WP-1 and must be confirmed before August 1, 2026.\n'
  printf '   · No end-to-end route tests run against a deployed broker.\n'
  exit 0
fi
printf ' \033[31m%s GATE(S) FAILED\033[0m — do not ship\n' "$FAILURES"
exit 1
