#!/usr/bin/env bash
#
# Integration test for #68: a listener whose cert-chain holds a leaf with no
# issuer above it must start, since that is what
# SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR was asked for.
#
# Usage: selfsigned.sh <path to tlsproxy> <path to the example directory>
#
# init_openssl() lives in app/main.c, which is linked into the executable and
# not into the library the cmocka binaries use, so the only way to see what it
# does with a chain of one is to run the program.
#
# The fixture is the example leaf on its own rather than a generated
# self-signed certificate, which keeps the openssl(1) binary out of the
# dependencies. Both take the same path: X509_verify_cert() fails, the flag
# turns that into a success, and the chain left over the leaf is empty, so
# SSL_CTX_build_cert_chain() returns 2 rather than 1. A chain that does carry
# an intermediate returns 1 even when errors were ignored, since the security
# level loop in ssl_build_cert_chain() overwrites the 2.

set -u

BIN=$1
CERTS=$2

RUN=$(mktemp -d)
LOG=$RUN/tlsproxy.log
MASTER=

fail() {
    echo "FAIL: $*"
    [ -n "$MASTER" ] && kill -KILL "$MASTER" 2>/dev/null
    [ -f "$LOG" ] && { echo "--- log ---"; cat "$LOG"; }
    [ -f "$RUN/stderr.txt" ] \
        && { echo "--- stderr ---"; cat "$RUN/stderr.txt"; }
    exit 1
}

# $1 is the listen port. The schema rejects listen-port 0, so we cannot ask
# the kernel for a free one; start on a port derived from the pid and walk
# upwards, which keeps concurrent runs off each other.
write_config() {
    cat > "$RUN/tlsproxy.yml" <<EOF
nworkers: 1
logfile: $LOG
loglevel: DEBUG

listeners:
  - name: selfsigned
    target-ip: 127.0.0.1
    target-port: 9
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cert-chain: $CERTS/servcert.pem
    servkey: $CERTS/servkey.pem
EOF
}

for try in 0 1 2 3 4 5 6 7 8 9; do
    PORT=$(( 20000 + ($$ + try * 89) % 20000 ))
    rm -f "$LOG"
    write_config "$PORT"
    ( cd "$RUN" && exec "$BIN" tlsproxy.yml ) \
        >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
    MASTER=$!
    # The listen event is logged by a worker, so seeing it in the file means
    # the master got past init_openssl() and into parent_loop() draining the
    # ring. Before #68 was fixed the master died in init_openssl() instead and
    # this loop ran out with the process gone.
    started=
    for _ in $(seq 50); do
        grep -q 'event=listen' "$LOG" 2>/dev/null && { started=1; break; }
        kill -0 "$MASTER" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$started" ] && break
    kill -KILL "$MASTER" 2>/dev/null
    wait "$MASTER" 2>/dev/null
    MASTER=
done
[ -n "$MASTER" ] || fail "the proxy would not start on any candidate port"
echo "master $MASTER on port $PORT"

grep -q 'Failed to build cert chain' "$LOG" \
    && fail "a chain of one was treated as a failure"

# The 2 is worth a line of its own, since the chain we are about to offer is
# shorter than the file the operator named implied. The message is matched
# rather than the level, since the example key's mode draws a WARN of its own
# here and either one would satisfy a check on the level alone.
grep -q 'level=WARN.*error_msg="Building cert chain"' "$LOG" \
    || fail "nothing warned that the chain was built with errors ignored"

# Logging the listener and accepting on it are different things, and only the
# second one is what the operator asked for.
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null \
    || fail "listener on port $PORT is not accepting"
exec 3>&-

kill -TERM "$MASTER" 2>/dev/null
for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
kill -KILL "$MASTER" 2>/dev/null
wait "$MASTER" 2>/dev/null

rm -rf "$RUN"
echo "PASS"
