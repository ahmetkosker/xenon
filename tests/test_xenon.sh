#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" ]]; then
  echo "usage: $0 <xenon_binary>" >&2
  exit 1
fi

CLEAN_OUT="$(mktemp)"
ISSUES_OUT="$(mktemp)"
OVERFLOW_OUT="$(mktemp)"
LONG_PTR_OUT="$(mktemp)"
MALFORMED_OUT="$(mktemp)"
JSON_OUT="$(mktemp)"
trap 'rm -f "$CLEAN_OUT" "$ISSUES_OUT" "$OVERFLOW_OUT" "$LONG_PTR_OUT" "$MALFORMED_OUT" "$JSON_OUT"' EXIT

"$BIN" analyze examples/clean.trace > "$CLEAN_OUT"
if ! grep -q 'leaks: 0' "$CLEAN_OUT"; then
  echo "expected zero leaks for clean trace" >&2
  cat "$CLEAN_OUT" >&2
  exit 1
fi

set +e
"$BIN" analyze examples/with_issues.trace > "$ISSUES_OUT"
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "expected exit code 2 for issue trace, got $code" >&2
  cat "$ISSUES_OUT" >&2
  exit 1
fi

for expected in 'double_free: 1' 'invalid_free: 1' 'use_after_free: 1' 'out_of_bounds: 1' 'invalid_access: 1' 'malformed_line: 0' 'invalid_number: 0' 'unknown_operation: 0' 'leaks: 1'; do
  if ! grep -q "$expected" "$ISSUES_OUT"; then
    echo "missing expected summary line: $expected" >&2
    cat "$ISSUES_OUT" >&2
    exit 1
  fi
done

set +e
"$BIN" analyze examples/overflow.trace > "$OVERFLOW_OUT"
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "expected exit code 2 for overflow trace, got $code" >&2
  cat "$OVERFLOW_OUT" >&2
  exit 1
fi

if ! grep -q 'out_of_bounds: 1' "$OVERFLOW_OUT"; then
  echo "expected out_of_bounds: 1 for overflow trace" >&2
  cat "$OVERFLOW_OUT" >&2
  exit 1
fi

"$BIN" analyze examples/long_pointer.trace > "$LONG_PTR_OUT"
for expected in 'double_free: 0' 'invalid_free: 0' 'use_after_free: 0' 'out_of_bounds: 0' 'invalid_access: 0' 'leaks: 0'; do
  if ! grep -q "$expected" "$LONG_PTR_OUT"; then
    echo "unexpected issue for long pointer trace: $expected" >&2
    cat "$LONG_PTR_OUT" >&2
    exit 1
  fi
done

set +e
"$BIN" analyze examples/malformed.trace > "$MALFORMED_OUT"
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "expected exit code 2 for malformed trace, got $code" >&2
  cat "$MALFORMED_OUT" >&2
  exit 1
fi

for expected in 'malformed_line: 1' 'invalid_number: 2' 'unknown_operation: 1'; do
  if ! grep -q "$expected" "$MALFORMED_OUT"; then
    echo "missing expected malformed summary line: $expected" >&2
    cat "$MALFORMED_OUT" >&2
    exit 1
  fi
done

set +e
"$BIN" analyze --format json examples/with_issues.trace > "$JSON_OUT"
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "expected exit code 2 for json issue trace, got $code" >&2
  cat "$JSON_OUT" >&2
  exit 1
fi

for expected in '"double_free": 1' '"invalid_free": 1' '"use_after_free": 1' '"out_of_bounds": 1' '"invalid_access": 1' '"leaks": 1' '"leaked_blocks"'; do
  if ! grep -q "$expected" "$JSON_OUT"; then
    echo "missing expected json field: $expected" >&2
    cat "$JSON_OUT" >&2
    exit 1
  fi
done

echo "xenon tests passed"
