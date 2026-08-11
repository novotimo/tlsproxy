# Testing

```sh
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig     # libcyaml is source-built
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DUNIT_TESTING=y
cmake --build build
ctest --test-dir build --output-on-failure
```

`-DCMAKE_BUILD_TYPE=Debug` alongside `-DUNIT_TESTING=y` is not optional.
`UNIT_TESTING` forces `-O0`, and `_FORTIFY_SOURCE` at `-O0` makes glibc emit a
warning that `-Werror` turns into a build failure.

`ctest` runs the cmocka binaries and the integration scripts under
`test/integration/`, which drive the built program rather than linking against
it. `app/main.c` is linked into the executable only, so nothing in it is
reachable from a cmocka binary and the scripts are the only cover it has.

## How the suites are written

The mocks interpose at the libc and OpenSSL boundary with `-Wl,--wrap`, and they
record the arguments they were called with rather than only faking a return
value. That distinction is the reason the suite was rewritten: it reached 100%
line coverage in December 2025 and still missed ten defects, because the mocks
discarded their arguments, so a leaked descriptor or a NULL passed to the logger
could not be expressed as a test at all.

Tests are named after the claim they make, so a failure of
`handle_accept_closes_fd_when_ssl_new_fails` is already the bug report. Each
test makes one claim and takes a fresh fixture through
`cmocka_unit_test_setup(..., reset_recorders)`.

Coverage is measured but is not a target. The floor in CI exists to stop the
suite rotting back to where it was, not as a number to chase.

## What CI runs

Every push to every branch, five jobs:

| Job | Purpose |
| --- | --- |
| Unit tests (Debug) | The suites at `-O0`, with asserts live |
| Release (`-Werror` at `-O2`) | Warnings that only appear with optimization, and the only build compiled with `NDEBUG` |
| ASAN + UBSAN | Gates on sanitizer diagnostics rather than exit code, since UBSAN reports and continues |
| Valgrind memcheck | Uninitialized reads, which ASAN does not see |
| Coverage | Line coverage over `src/`, with a floor enforced |

Both workflows trigger on push rather than on `pull_request`, so opening a PR
starts no run of its own and CI tests the branch tip rather than the tip merged
into `main`. Rebase before merging rather than trusting a green PR.

## Benchmarks and profiles

Separate from the test suite and documented in `benchmark/README.md`.
`benchmark/bench.sh` measures against nginx and haproxy, `benchmark/report.py`
renders a run against the committed baseline, and `benchmark/profile.sh` takes
CPU profiles of all three subjects.
