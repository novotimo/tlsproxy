#!/usr/bin/env bash
#
# Integration test for #79: a reload the master rejects must be reported, and
# must go on being reported when the new configuration has no logfile key.
#
# Usage: reload_reports.sh <path to tlsproxy> <path to the example directory>
#
# handle_reload() lives in app/main.c, which is linked into the executable and
# not into the library the cmocka binaries use, so the only way to see what a
# rejected reload writes is to run the program and read the log back.

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

# $1 is the listen port, $2 the server key and $3 the logfile, which is left
# out of the file altogether when it is empty. The schema rejects listen-port
# 0, so we cannot ask the kernel for a free one; start on a port derived from
# the pid and walk upwards, which keeps concurrent runs off each other.
write_config() {
    { [ -n "$3" ] && echo "logfile: $3"; cat <<EOF
nworkers: 1
loglevel: DEBUG

listeners:
  - name: reporttest
    target-ip: 127.0.0.1
    target-port: 9
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cacerts:
      - $CERTS/intcert.pem
    servcert: $CERTS/servcert.pem
    servkey: $2
EOF
    } > "$RUN/tlsproxy.yml"
}

start_proxy() {
    for try in 0 1 2 3 4 5 6 7 8 9; do
        PORT=$(( 20000 + ($$ + try * 89) % 20000 ))
        rm -f "$LOG"
        write_config "$PORT" "$CERTS/servkey.pem" "$LOG"
        ( cd "$RUN" && exec "$BIN" tlsproxy.yml ) \
            >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
        MASTER=$!
        # The listen event is logged by a worker, so seeing it in the file
        # means the master is in parent_loop() draining the ring as well.
        for _ in $(seq 50); do
            grep -q 'event=listen' "$LOG" 2>/dev/null && return 0
            kill -0 "$MASTER" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$MASTER" 2>/dev/null
        wait "$MASTER" 2>/dev/null
        MASTER=
    done
    return 1
}

# A reload is asynchronous, so wait for the count of whatever it should have
# written to reach $2 rather than sleeping a fixed time.
wait_for_lines() {
    for _ in $(seq 50); do
        [ "$(grep -c "$1" "$LOG")" -ge "$2" ] && return 0
        kill -0 "$MASTER" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

start_proxy || fail "could not start the proxy on any candidate port"
echo "master $MASTER on port $PORT"

# clntkey.pem is a well formed key that is not the one in servcert.pem, so
# SSL_CTX_use_PrivateKey() fails in load_servkey() and the probe context
# init_openssl() builds for the new config comes back NULL. Leaving the
# logfile key out of that same edit is the case #79 is about: the master has
# a perfectly good descriptor and used to turn itself off in front of it.
write_config "$PORT" "$CERTS/clntkey.pem" ""
kill -HUP "$MASTER" || fail "could not signal the master"

# Both halves of the report are checked, since they take different routes out:
# the probe's own failure goes through the descriptor handle_reload() passes
# down to init_openssl(), and this one through the caller's own logfd.
wait_for_lines 'Failed to load server key into ctx' 1 \
    || fail "the probe context's own failure was not logged"
wait_for_lines 'Couldn.t reload config' 1 \
    || fail "the rejection was not logged"

# The same rejection again, with nothing accepted in between. A rejection path
# that leaves the shared logger worse than it found it reports the first one
# and then goes quiet, and an accepted reload in between would hide that by
# setting enabled and loglevel afresh.
kill -HUP "$MASTER"
wait_for_lines 'Couldn.t reload config' 2 \
    || fail "the second rejection in a row was not logged"

# The logger is shared, so a master that has turned itself off has turned the
# workers off with it, and neither the count above nor the master's own
# records would show it.
before_worker=$(grep -c 'process_type=worker' "$LOG")
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null \
    || fail "listener on port $PORT stopped accepting"
for _ in $(seq 50); do
    [ "$(grep -c 'process_type=worker' "$LOG")" -gt "$before_worker" ] && break
    sleep 0.1
done
[ "$(grep -c 'process_type=worker' "$LOG")" -gt "$before_worker" ] \
    || fail "no worker logged after the rejected reloads"

# The old configuration keeps serving, so the master is still logging under
# it, and a reload the master accepts is the cheapest thing to make it say so.
write_config "$PORT" "$CERTS/servkey.pem" "$LOG"
kill -HUP "$MASTER"
wait_for_lines 'event=listen' 2 \
    || fail "the master stopped logging after the rejected reload"

# A logfile the master cannot open is the other way init_logger() fails, and
# it is refused after the probe loop rather than before it. The rejection has
# to reach the descriptor the master is keeping, not the one it is refusing.
write_config "$PORT" "$CERTS/servkey.pem" "$RUN/nosuchdir/tlsproxy.log"
kill -HUP "$MASTER"
wait_for_lines 'Couldn.t update logfile' 1 \
    || fail "an unopenable logfile was refused without saying so"

# Same as above: the refused configuration was never adopted, so the master is
# still logging to the file named by the one it kept.
write_config "$PORT" "$CERTS/servkey.pem" "$LOG"
kill -HUP "$MASTER"
wait_for_lines 'event=listen' 3 \
    || fail "the master stopped logging after refusing the new logfile"

# All of the above still passes if the proxy is alive but no longer serving.
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null \
    || fail "listener on port $PORT stopped accepting"

kill -TERM "$MASTER" 2>/dev/null
for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
kill -KILL "$MASTER" 2>/dev/null
wait "$MASTER" 2>/dev/null

# The cmocka binaries the CI sanitizer job runs do not link app/main.c, so a
# sanitized build only ever reaches handle_reload() through a script like this
# one. LeakSanitizer reports at exit, which is why this waits for the master
# to go rather than killing it. Nothing matches in an unsanitized build, so
# the check costs nothing there.
#
# The misaligned load in write_logs() is #61, already filed, and every run of
# the master trips it. test/ubsan.supp does not cover it here: measured on the
# tlsproxy binary, the same suppressions file that the cmocka job passes has no
# effect on the diagnostic, so the known finding is dropped by name instead.
# Once #61 is fixed this line matches nothing and can go.
diag=$(grep -hE 'runtime error|ERROR: AddressSanitizer|ERROR: LeakSanitizer' \
            "$RUN/stderr.txt" 2>/dev/null \
       | grep -v 'src/logging.c.*misaligned address' | sort -u)
[ -z "$diag" ] || fail "the master reported sanitizer diagnostics:
$diag"

rm -rf "$RUN"
echo "PASS"
