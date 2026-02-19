# xenon

`xenon` is a lightweight Memory Poison/Leak Visualizer for C libraries.

It consumes a simple trace file (alloc/free/read/write events) and reports:

- memory leaks
- double free
- invalid free
- use-after-free (poison violations)
- out-of-bounds reads/writes
- invalid accesses on unknown pointers

## Why this project exists

Low-level libraries often have event logs but no quick way to summarize memory safety issues.
`xenon` turns raw traces into a concise report you can run in CI.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Run

```bash
./build/xenon analyze examples/clean.trace
./build/xenon analyze examples/with_issues.trace
```

## Trace format

```text
# comments are allowed
alloc <ptr> <size>
free <ptr>
write <ptr> <offset> <len>
read  <ptr> <offset> <len>
```

Example:

```text
alloc 0x1000 32
write 0x1000 0 16
read  0x1000 8 8
free  0x1000
```

## Exit codes

- `0`: no findings
- `2`: one or more findings detected
- `1`: usage/input/runtime error

## Tests

```bash
ctest --test-dir build --output-on-failure
```
