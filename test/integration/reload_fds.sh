#!/usr/bin/env bash
#
# Integration test for #75: a reload the master rejects must not leak the log
# file descriptor init_logger() opened for the new config.
#
# Usage: reload_fds.sh <path to tlsproxy> <path to the example directory>
#
# handle_reload() lives in app/main.c, which is linked into the executable and
# not into the library the cmocka binaries use, so the only way to count the
# master's descriptors is to run the program and read /proc.

set -u

BIN=$1
CERTS=$2

RELOADS=20

RUN=$(mktemp -d)
LOG=$RUN/tlsproxy.log
MASTER=

fail() {
    echo "FAIL: $*"
    [ -n "$MASTER" ] && kill -KILL "$MASTER" 2>/dev/null
    [ -f "$LOG" ] && { echo "--- log ---"; cat "$LOG"; }
    [ -f "$RUN/stderr.txt" ] && { echo "--- stderr ---"; cat "$RUN/stderr.txt"; }
    exit 1
}

# $1 is the listen port and $2 the server key. The schema rejects listen-port
# 0, so we cannot ask the kernel for a free one; start on a port derived from
# the pid and walk upwards, which keeps concurrent runs off each other.
write_config() {
    cat > "$RUN/tlsproxy.yml" <<EOF
nworkers: 1
logfile: $LOG
loglevel: DEBUG

listeners:
  - name: reloadtest
    target-ip: 127.0.0.1
    target-port: 9
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cacerts:
      - $CERTS/cacert.pem
      - $CERTS/intcert.pem
    servcert: $CERTS/servcert.pem
    servkey: $2
EOF
}

nfds() {
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

start_proxy() {
    for try in 0 1 2 3 4 5 6 7 8 9; do
        PORT=$(( 20000 + ($$ + try * 97) % 20000 ))
        rm -f "$LOG"
        write_config "$PORT" "$CERTS/servkey.pem"
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
# written to the log to reach $2 rather than sleeping a fixed time.
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

before=$(nfds)
[ "$before" -gt 0 ] || fail "could not read /proc/$MASTER/fd"

# clntkey.pem is a well formed key that is not the one in servcert.pem, so
# SSL_CTX_use_PrivateKey() fails in load_servkey() and the probe context
# init_openssl() builds for the new config comes back NULL. The reload is
# rejected after init_logger() has already opened the new log file.
write_config "$PORT" "$CERTS/clntkey.pem"
for _ in $(seq "$RELOADS"); do
    kill -HUP "$MASTER" || fail "could not signal the master"
    sleep 0.05
done

wait_for_lines 'Failed to load server key into ctx' "$RELOADS" \
    || fail "only $(grep -c 'Failed to load server key into ctx' "$LOG") of \
$RELOADS reloads reached the probe context, so the test proved nothing"

after=$(nfds)
[ "$after" -le "$before" ] \
    || fail "master held $before descriptors, then $after after $RELOADS \
rejected reloads"

onlog=$(ls -l "/proc/$MASTER/fd" | grep -c "$LOG")
[ "$onlog" -eq 1 ] || fail "$onlog descriptors open on the log file, want 1"

# Closing the wrong descriptor would leave the count right and the logging
# broken, so make the master write one more record through the one it kept.
# "Couldn't reload config" is the record that goes through the caller's logfd;
# the probe's own failures above went through the new one.
kill -HUP "$MASTER"
wait_for_lines 'Couldn.t reload config' $((RELOADS + 1)) \
    || fail "the master stopped logging after the rejected reloads"

# The accepted path closes the old descriptor and keeps the new one, so its
# count should not move either. Workers are replaced on an accepted reload, so
# a second listen event is what says the swap went through.
write_config "$PORT" "$CERTS/servkey.pem"
kill -HUP "$MASTER"
wait_for_lines 'event=listen' 2 || fail "the good config was not reloaded"
accepted=$(nfds)
[ "$accepted" -le "$before" ] \
    || fail "master held $before descriptors, then $accepted after an \
accepted reload"

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
rm -rf "$RUN"
echo "PASS"
