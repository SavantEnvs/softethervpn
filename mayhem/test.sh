#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for SoftEther VPN: the dynamically linked KAT probe (known inputs ->
# known outputs through mayaqua/cedar) plus upstream's own `vpncmd /tools check` self-test.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ORACLE_DIR="$SRC/build/oracle"
[ -x "$ORACLE_DIR/kat" ] && [ -x "$ORACLE_DIR/vpncmd" ] || {
  echo "oracle binaries missing under $ORACLE_DIR (mayhem/build.sh should have built them)" >&2
  emit_ctrf "softether-oracle" 0 1 0
  exit 1
}

passed=0
failed=0

# 1) Known-answer probe: digests, PACK/config/JSON/packet round-trips with fixed expected values.
kat_out="$("$ORACLE_DIR/kat" 2>&1)" || true
printf '%s\n' "$kat_out" | grep -E '^KAT_' || true
kat_ok=$(printf '%s\n' "$kat_out" | grep -c '^KAT_OK ' || true)
kat_fail=$(printf '%s\n' "$kat_out" | grep -c '^KAT_FAIL ' || true)
if ! printf '%s\n' "$kat_out" | grep -qE '^KAT_SUMMARY total=[0-9]+ failed=0$' || [ "$kat_ok" -lt 31 ]; then
  failed=$((failed + 1 + kat_fail))
  echo "FAIL: KAT probe did not report a complete, clean summary (ok=$kat_ok fail=$kat_fail)" >&2
else
  passed=$((passed + kat_ok))
fi

# 2) Upstream's own environment self-test: each of its six subsystem checks must print Pass.
check_out="$(cd "$ORACLE_DIR" && ./vpncmd /tools /cmd check 2>&1)" || true
for sub in 'Kernel System' 'Memory Operation System' 'ANSI / Unicode string processing system' \
           'File system' 'Thread processing system' 'Network system'; do
  if printf '%s\n' "$check_out" | grep -A1 -F "Checking '$sub'" | grep -q 'Pass'; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: vpncmd check: '$sub' did not pass" >&2
  fi
done
if printf '%s\n' "$check_out" | grep -q 'All checks passed'; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: vpncmd check: no 'All checks passed' line" >&2
fi

emit_ctrf "softether-kat+vpncmd-check" "$passed" "$failed" 0
