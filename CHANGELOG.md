# Changelog

## Unreleased

- `SSL_MODE_RELEASE_BUFFERS`: a held connection costs 43 KB rather than 74 (#72).
- `TCP_NODELAY` on both legs, so small messages stop waiting out a delayed ACK.
  A 30 Hz tick went from a p99 of 42 ms to 1.1 ms (#91).
- `accept4()`, `SOCK_NONBLOCK` and epoll deregistration left to `close()`: six
  fewer syscalls per connection (#94).
- A benchmark suite against nginx and haproxy, a baseline, and a profiler (#6,
  #70).

## 1.1.0

Repair work, with the tests and CI that would have caught it.

- The logger no longer wedges a worker when its ring fills, drops the queue on a
  partly written line, or misreads a framed length (#27, #58, #61, #74). Audit
  records are logfmt and escaped (#28).
- A failed reload leaves the running configuration alone instead of killing the
  master (#26, #75), and the same checks run at startup (#46).
- Teardown is a state machine, so a truncated response, a client half-close and
  a backend reset all behave (#38, #53, #29).
- Connect timeouts are enforced by the timer tree (#57), signals go through
  `signalfd` (#50), self-signed leaves load (#68), OpenSSL failures report their
  reason (#80), and workers survive a master with PID 1 (#69).
- Hardening flags, sanitizer and valgrind jobs, and mocks that record their
  arguments rather than only faking returns (#14, #30, #56, #4, #19).

## 1.0.0

First release: TLS termination for any TCP protocol, several listeners in one
process, configurable certificates and keys, master/worker processes.
