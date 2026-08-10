# Changelog

# Version 1.1.0

Mostly repair work. A review of the 1.0.0 tree turned up six issues worth of
defects, and this release is those fixes together with the test suite and the
CI that would have caught them. The two worst were a logger that wedged every
worker permanently once its ring buffer filled, and a configuration reload that
killed the master process on any error in the new file.

## Startup (#19)

- `tlsproxy -v` prints the version and exits, and the startup banner carries it
  as well. Both come from `PROJECT_VERSION` in `CMakeLists.txt` by way of a
  generated `inc/version.h`, so there is one place to bump.
- A config file that cannot be parsed is reported with its name, which is what
  you want when the name is a typo or the argument was meant to be a flag.
- stdout is asked for line buffering explicitly, since it is fully buffered
  when it isn't a terminal, and the startup messages otherwise sat in every
  worker's inherited buffer and were printed again by each of them on the way
  out. It also keeps them in order against stderr, which is unbuffered.

## Connection shutdown (#38)

Teardown is now a state machine, working through `PS_SERVER_DISCONNECTED`,
`PS_CLIENT_FLUSHED` and `PS_CLOSE_NOTIFY_SENT` whichever side closes first.

- The tail of the backend's response is no longer truncated. A response
  followed by EOF usually arrives in a single epoll event, and we acted on the
  EOF before the data it arrived with.
- Once we are finished with a connection we keep reading from the client and
  discarding what it sends, so `close()` emits a FIN rather than a RST; nginx
  calls this `lingering_close`. Two new per-listener keys bound it,
  `shutdown-timeout` for the whole teardown and `shutdown-interval` for the gap
  between client messages, defaulting to 30 and 5 seconds.
- A reset from the backend is propagated to the client instead of being turned
  into a clean close.
- `proxy_close()` no longer waits for the peer's `close_notify` before it
  completes, since a peer that never answers would otherwise hold the context,
  both descriptors and the worker's slot in `nproxies` for as long as it liked.
  It no longer returns `TPX_AGAIN`.
- TCP keepalive is set on both legs, configured by the new `tcp-keepidle`,
  `tcp-keepintvl` and `tcp-keepcnt` keys, defaulting to 60, 10 and 3. All three
  are optional, and the client leg is configured once on the listening socket,
  since Linux copies those options on to every descriptor `accept()` returns.
  There is still no idle timeout, so keepalive is the only thing bounding a
  peer that dies without sending FIN.

## Client half-close (#53)

A client that finished its handshake and then disconnected against a backend
that had not closed put the worker on a full core indefinitely. Once the last
of the client's data had gone to the backend, `PS_CLIENT_DISCONNECTED` reissued
`shutdown(SHUT_WR)` on a descriptor it had already shut down, read `EAGAIN` and
went back to `epoll_wait()`, which reported the same writability again at once,
since a socket we will never write to again stays writable forever. Nothing
consumed the readiness and nothing deregistered the descriptor, so the proxy
was never released either, which is what made the shutdown hang in #41
permanent once it happened.

The flush and the read are separate states now. `PS_CLIENT_DISCONNECTED` ends
when the queue to the backend empties, at which point the backend leg is
re-registered for `EPOLLIN` alone and the proxy moves to `PS_SERVER_FLUSHED`,
which reads the backend until it EOFs. No assert was involved, so Debug and
Release behaved identically.

## Connect timeout (#57)

`proxy_handle_connect()` arms the connect timeout, and the branch where a later
`connect()` completes is the only place that disarms it. A client event that
arrives while the backend connect is still outstanding never goes through that
function, since the connecting states return early for the backend leg alone
and fall through to the ready path for the client, so a client that closed
there moved to `PS_CLIENT_DISCONNECTED` with its node still on the timer tree.
Once the backend closed as well, `handle_server_disconnected()` wrote a new key
into that node and inserted it a second time, which tripped its
`assert(!timer_set)` in Debug and, with the assert compiled out, either faulted
inside the insert's rebalance or left the node linked at two positions for the
single `ngx_rbtree_delete()` in `proxy_close()`. The tree holds every armed
timer the worker has, so the damage was to every connection on that worker
rather than to the one that triggered it. A backend slow enough to still be
connecting when the client hangs up is ordinary, and so is a backend at its
connection limit closing as soon as it answers.

The connect timer is dropped now when the client goes away while the connect is
outstanding. Nothing is armed in its place, so a proxy that still has data
queued for a backend whose connect never completes waits out the kernel's SYN
retries instead of `connect-timeout`, which is around 127 seconds at the
default `tcp_syn_retries` of 6.

## Logging (#27)

- `_write_linebuf()` returned still holding the write lock when the ring buffer
  was full. The mutex is `PTHREAD_PROCESS_SHARED` and lives in the shared
  mapping, so the first worker to fill the ring wedged itself on its next log
  call and then every other worker on theirs, and killing the holder did not
  release it. Since `log_proxy()` sits on the connection path, that was the
  whole proxy.
- The lock is robust now, so a worker that dies holding it leaves the next
  taker with `EOWNERDEAD` and a `pthread_mutex_consistent()` call rather than a
  hang. "Ring buffer full" is reported once per episode instead of once per
  dropped line.
- `_ringbuf_fits()` asked for room for the line but not for the NUL terminator
  written after it, so a message that exactly filled the ring left
  `write_idx == read_idx`, which is the encoding for empty, and the next writer
  overwrote unread data.
- `write_logs()` retries a short write and only advances the read index onto a
  length prefix, rather than treating any non-negative `write()` return as
  complete and landing the index mid-message. A write that takes nothing
  rewinds over the prefix it consumed, and the remaining event count is
  re-emitted on the eventfd instead of being discarded, which is what
  previously turned a transient logfile error into bytes stranded in the ring
  forever.
- `_linebuf_append()` bounds-checks the unsanitized path, `write_logs()`
  accepts the longest line the builder can produce, and `errno` is cleared
  before the calls whose result is read out of it. The re-emit passed the event
  count itself where `write()` wanted its address, so the one path that was
  meant to recover from a failed log write read from a wild pointer.

## Partly written log lines (#58)

- A `write()` that took part of a line and then refused the rest, which is what
  a filesystem filling up mid-line does to the regular file `init_logger()`
  opens, left the read index where it started. The next drain read the original
  length and sent the line from the beginning, so the file was left holding the
  first fragment twice. The rollback commits the cursor it rewound now, and the
  next drain owes the file the remainder rather than the whole line.
- The four bytes that rollback writes are the length prefix framing the
  remainder, and they now land over body the kernel has already taken rather
  than in the middle of a line that is about to be sent again. They go into the
  ring after `_sanitize_c()` has run and they routinely contain NULs, so a
  reader parsing logfmt previously found an embedded NUL in the middle of a
  field.
- The read cursor no longer carries the invariant that it sits one byte past a
  terminator, since a re-framed remainder begins in the middle of what was one
  message. The write cursor still carries it, because a worker publishes a
  whole line or nothing, and the framed length check covers the read side.

## Audit records (#28)

- The sanitizer escaped neither `"` nor `\`, since both cases sat in the `else`
  of an `isprint()` test and C99 makes `isprint` true for every printing
  character. A value containing a quote closed its own field, so everything
  after it parsed as further `key="value"` pairs. Nothing that reaches the
  sanitizer today is remote-controlled, so this was a log integrity defect
  rather than a remote injection vulnerability, but it would have become one
  with the first feature that logs SNI or a peer certificate.
- The listener startup record printed `target_ip` under the `listen_ip` key,
  the `argv` field in the startup record lost its opening quote, and listener
  messages claimed to come from the master process.
- Workers that die are recorded as dead rather than as whatever they were last
  seen as.
- The master's own schemas honour `logging: 0`, which they previously ignored
  because they tested the log descriptor rather than the enabled flag.
- `X509_NAME_oneline()` allocates, and the certificate logging paths now free
  what it returns.

## Configuration validation (#46)

- `nworkers` is checked rather than taken on trust. Zero gave a master with no
  workers, which parses cleanly and then proxies nothing, and since the field is
  a uint anything up to 2^32-1 parsed and went straight into the fork loop. It
  is rejected below 1 and above 128 now.
- `connect-timeout` defaults to 60 seconds, following nginx's
  `proxy_connect_timeout`. It is optional to the schema, so leaving it out read
  as zero, and a deadline of `gettime() + 0` has already passed by the next turn
  of the event loop, which dropped every backend connection that didn't complete
  immediately. It was also the one per-listener timeout measured in
  milliseconds, while `shutdown-timeout` and `shutdown-interval` were in
  seconds, so it is seconds throughout now and the example configs lost three
  zeroes.
- Both ports have to be between 1 and 65535. Zero parses either way, and it
  fails differently on each side: `connect()` to port 0 returns ECONNREFUSED on
  Linux, so a `target-port` of 0 brought the listener up and then refused every
  connection for a reason the error didn't name, while `bind()` reads a
  `listen-port` of 0 as a request for whatever ephemeral port is spare, which
  puts the listener somewhere nothing was told to connect to.
- The three `tcp-keep*` values are bounded by what the kernel takes, 32767 for
  `tcp-keepidle` and `tcp-keepintvl` and 127 for `tcp-keepcnt`, rather than by
  `INT_MAX`. Everything between the two used to validate cleanly and then fail
  `setsockopt()` with EINVAL in `bind_listen_sock()`, which runs in the worker
  after the master has forked, so it was reported to nobody and killed the
  worker. All four keepalive `setsockopt()` calls on the listening socket are
  warnings now, `SO_KEEPALIVE` along with the three `TCP_KEEP*` ones, since a
  listener with degraded keepalive still serves traffic and a worker that exits
  does not, and a value that would provoke a refusal no longer gets past
  startup anyway.
- A private key that group or other can read, write or execute is warned about
  at startup and on every reload. It stays a warning rather than a refusal,
  since the mode that is wrong for a key in one deployment is deliberate in
  another, and it goes to stderr as well as the log, because a master with no
  `logfile` has its logger disabled and would otherwise be told nothing. A key
  that can't be `stat()`ed is left alone for OpenSSL to fail on, which it does
  a moment later with more to say about the reason.
- Reload validates the new configuration with the same code as startup.
  `handle_reload()` carried a hand-copied subset of the listener checks under a
  comment asking that the two be kept in step, and they had already drifted,
  since the copy checked neither `nworkers` nor the `tcp-keep*` bounds and so
  accepted configurations startup would have refused. `tpx_validate_conf()`
  takes a log descriptor to decide where its complaints go, the master's log on
  reload and stderr at startup, so there is one set of rules with two
  destinations.

## Configuration reload (#26)

- A failed reload no longer terminates the proxy.
- `cyaml_free()` was called with the address of the config pointer rather than
  the pointer itself, and the `(cyaml_data_t **)` cast hid it, so libcyaml
  walked the stack address of a local and freed it. Every error path in
  `handle_reload()` reached that call, which is to say every failed reload was
  a SIGSEGV in the master.
- The new configuration's certificates and keys are built into a complete
  `SSL_CTX` per listener before anything is swapped in, and then freed, so a
  certificate that does not load leaves the running configuration alone. A
  configuration with no listeners, a listener with neither `cert-chain` nor
  `cacerts`, and a `BIO_new_file()` returning NULL are all reported rather than
  assumed away, and the X509 store is freed on the error paths.
- Worker pids are allocated before the old configuration is freed, so the old
  one can still be restored if that allocation fails.
- Workers set `PR_SET_PDEATHSIG`, so they exit with the master rather than
  outliving it holding the listening sockets.

## Rejected reloads (#75)

- `handle_reload()` opens the new configuration's log file before it has
  decided whether to accept it, since the probe contexts need somewhere to
  report their failures, and the paths that reject the configuration after that
  left the descriptor open. Only the master ever reloads and the master is the
  process that never restarts, so a supervisor holding a broken configuration
  and hanging up on a schedule walked it to `EMFILE` with nothing bounding it.

## The logger's write lock (#74)

- `init_logger()` ends by initializing `write_lock`, which is right at startup,
  when `init_shmem()` has just mapped the region and no worker exists yet, and
  wrong on a reload, when workers are taking that lock in `_write_linebuf()`
  for every line they emit. Re-initializing a held mutex is undefined by POSIX
  and in practice returns it to the unlocked state, so a second worker could
  enter the critical section while the first was still in it. A
  `lock_initialized` flag in the shared region, which `init_shmem()`'s
  `MAP_ANONYMOUS` zeroes for us, now holds the initialization to the once it
  belongs at.

## Proxy lifecycle (#29)

- `create_proxy()` freed the proxy, NULLed the pointer and then fell into
  `log_proxy()` with it. That returned early at INFO and segfaulted at DEBUG,
  which is what `example/default.yml` ships, on any backend that refused the
  connection synchronously.
- `nproxies++` ran even when creation failed, and only successful proxies ever
  reach the matching decrement. Since `child_loop()` exits at `nproxies == 0`,
  a single failed backend connection meant the worker never exited on SIGHUP,
  which broke both graceful shutdown and hot reload.
- `client_addr` was never written, and `proxy_t` was `malloc`'d rather than
  zeroed, so the audit log formatted uninitialized heap as the client address
  and had never recorded who connected.
- The accepted descriptor leaked on five paths out of `handle_accept()` and the
  connect socket leaked on both `fcntl()` failures in `create_connect()`. The
  accepted descriptor belongs to `handle_accept()` until a proxy exists, so
  `create_proxy()` closes only the socket it opened itself.
- `proxy_handle_connect()` treats `EALREADY` as retryable, which is what its
  documented contract in `inc/proxy.h` always said.

## Signals (#50)

`epoll_wait()` returns `-1` with `EINTR` when the process is stopped and
continued, and `SIGSTOP` cannot be blocked, so the `sigprocmask()` in
`block_signals()` does not prevent it. Both loops then walked their event array
with `nfds == -1` converted to `size_t`, which is a bound of `SIZE_MAX` over a
100-element automatic array. No assert is involved, so Debug and Release
behaved the same way.

- `parent_loop()` treated `_fatal()` as though it terminated. It does during
  startup, but `in_startup` is cleared before the loop and after that it logs
  and returns, which is what keeps a failed reload from killing the master. It
  goes back to `epoll_wait()` now.
- `child_loop()` recognized `EINTR` already, though its `break` left the
  `switch` rather than the loop and it fell into the same walk. The master
  logged the worker as killed by signal 11 and respawned it, so that half cost
  the connections the worker held rather than the service.

## Debug builds (#30)

Three asserts that a normal connection tripped, each of which aborted a worker
in Debug and was inert in Release.

- `proxy_handle_read()` asserted `buflen > 0` on entry where `buflen` is
  unconditionally 0, so a Debug build could not move a byte in either
  direction.
- `proxy_handle_write()` asserted `write_idx > 0` and so aborted on a freshly
  rotated chunk, which any transfer whose read burst is an exact multiple of
  `TPX_NET_BUFSIZE` produces.
- `TPX_EMPTY` from `queue_peek()` fell into the `default:` arm shared with
  `TPX_SUCCESS`, leaving `wbuf` NULL. That one was latent, since
  `outbuf_empty()` rejects an empty queue on entry, and the case is now
  reported as queue corruption.

## Queue and logging invariants (#56)

`bufq_t`'s `read_idx` and `write_idx` were `int` with `-1` for empty and were
compared against a `size_t buflen` on the hot path, which put
`SSL_write(ssl, NULL, SIZE_MAX)` one deleted assert away. They are `size_t` now
with `queue_empty()` carrying the empty case, so the type holds the invariant
rather than a check that `NDEBUG` removes from the shipped image. A
`_Static_assert` pins `TPX_NET_BUFSIZE` below `INT_MAX`, since it is passed to
`SSL_read()` and `SSL_write()` as an `int`.

- The asserts in `write_logs()` that a corrupt ring could trip are runtime
  checks that log and return, and the ones left are programming-error
  invariants that a valid input cannot reach.
- Allocation failures in `enqueue()` and in the read path are checked and
  reported rather than dereferenced.
- The queue's diagnostics go to the log instead of `stderr` and `perror()`, so
  a worker's complaint about a corrupt queue reaches the same place everything
  else does.

## Hardening (#14)

- Our own code and the tests compile under `-Wall -Wextra -Wshadow
  -Wsign-conversion -Wpointer-arith -Wstrict-prototypes -Wwrite-strings
  -Wimplicit-fallthrough=5 -Werror` with nothing left over. Vendored headers in
  `external/` are included as system headers and excluded from that.
- Hardening flags go on through GCC's `-fhardened` where it exists and are
  spelled out individually where it does not:
  `-fstack-protector-strong`, `-fstack-clash-protection`,
  `-fcf-protection=full`, `-ftrivial-auto-var-init=zero`, PIE, and full RELRO
  with `BIND_NOW`. `_FORTIFY_SOURCE=3` applies to every configuration except
  Debug, since there is no optimization at `-O0` to fold the size checks into.
  `-fno-strict-aliasing` is set because the epoll data pointers are tagged.
- The example `compose.yml` drops all capabilities with nothing added back, and
  adds `read_only: true`, `no-new-privileges`, a pids limit, a memory limit and
  an explicit nofile ulimit. The proxy listens on 8443 in the container and
  lets Docker publish 443, so it does not need `NET_BIND_SERVICE`. Logs move to
  a named volume so the root filesystem can stay read-only.

There is deliberately no privilege dropping or chroot: the container starts as
a non-root user, so there is no privilege to drop and no window in which we
hold one.

## Tests and CI (#4)

- The proxy, listener and event suites were rewritten and a logging suite
  added, giving 153 tests across six binaries. The mocks record the arguments
  they were called with rather than only faking a return value, which is the
  point of the rewrite: the old suite reached 100% line coverage in December
  2025 and still missed the ten defects above, because a leaked descriptor or a
  NULL passed to the logger could not be expressed as a test at all.
- `__assert_fail` is interposed and routed into `mock_assert()`, since cmocka
  handles SIGFPE, SIGILL, SIGSEGV, SIGBUS and SIGSYS but not SIGABRT, so a
  tripped assert in `src/` previously killed the binary with no report and left
  every later test unrun.
- `test/integration/signals.sh` starts the built binary, stops and continues
  the master and then the workers, and checks that nothing died and that the
  listener still accepts. `app/main.c` is linked into the executable and not
  into the library the cmocka binaries use, so neither event loop is reachable
  from them.
- CI runs unit tests, a Release build at `-O2` under `-Werror`, ASAN with
  UBSAN, Valgrind memcheck and coverage with a floor. The sanitizer job gates
  on diagnostics rather than exit code, since UBSAN reports and carries on.
- Both workflows triggered on push and on pull request, so a branch with an
  open PR ran the whole matrix twice. They trigger on push only now.

# Version 1.0.0

This is the initial version of TLS Proxy, with the main selling points being:
- Accept thousands of concurrent connections.
- Listen on multiple ports.
- Basic TLS configurability (configuring certs and keys).
- Multi-process.
