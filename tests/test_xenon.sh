#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" ]]; then
  echo "usage: $0 <xenon_binary>" >&2
  exit 1
fi

"$BIN" analyze examples/clean.trace > /tmp/xenon_clean.out
if ! grep -q 'leaks: 0' /tmp/xenon_clean.out; then
  echo "expected zero leaks for clean trace" >&2
  cat /tmp/xenon_clean.out >&2
  exit 1
fi

set +e
"$BIN" analyze examples/with_issues.trace > /tmp/xenon_issues.out
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "expected exit code 2 for issue trace, got $code" >&2
  cat /tmp/xenon_issues.out >&2
  exit 1
fi

for expected in 'double_free: 1' 'invalid_free: 1' 'use_after_free: 1' 'out_of_bounds: 1' 'invalid_access: 1' 'leaks: 1'; do
  if ! grep -q "$expected" /tmp/xenon_issues.out; then
    echo "missing expected summary line: $expected" >&2
    cat /tmp/xenon_issues.out >&2
    exit 1
  fi
done

echo "xenon tests passed"
