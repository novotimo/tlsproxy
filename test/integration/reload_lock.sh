#!/usr/bin/env bash
#
# Integration test for #74: a reload must not re-initialize the logger's write
# lock, which workers hold in _write_linebuf() on every line they emit.
#
# Usage: reload_lock.sh <path to tlsproxy> <path to the example directory>
#                       <path to mutex_probe.so>
#
# init_logger() is in app/main.c and so out of reach of the cmocka binaries,
# and a re-initialized mutex looks exactly like a fresh one from the outside,
# so the count comes from interposing pthread_mutex_init() instead.

set -u

BIN=$1
CERTS=$2
PROBE=$3

RELOADS=5

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

# $1 is the listen port and $2 the server key. Two workers, so the reload has
# something live holding the lock rather than only the master.
write_config() {
    cat > "$RUN/tlsproxy.yml" <<EOF
nworkers: 2
logfile: $LOG
loglevel: DEBUG

listeners:
  - name: locktest
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

inits() {
    grep -c "shared_mutex_init pid=$MASTER " "$RUN/stderr.txt"
}

start_proxy() {
    for try in 0 1 2 3 4 5 6 7 8 9; do
        PORT=$(( 20000 + ($$ + try * 97) % 20000 ))
        rm -f "$LOG"
        write_config "$PORT" "$CERTS/servkey.pem"
        ( cd "$RUN" && LD_PRELOAD=$PROBE exec "$BIN" tlsproxy.yml ) \
            >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
        MASTER=$!
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

before=$(inits)
[ "$before" -eq 1 ] \
    || fail "$before shared mutexes initialized at startup, want 1; the probe \
is not seeing what it is meant to"

# Workers are replaced on an accepted reload, so counting listen events is how
# we know each SIGHUP was taken rather than coalesced.
for i in $(seq "$RELOADS"); do
    kill -HUP "$MASTER" || fail "could not signal the master"
    wait_for_lines 'event=listen' $(( (i + 1) * 2 )) \
        || fail "reload $i did not cycle the workers"
done

after=$(inits)
[ "$after" -eq "$before" ] \
    || fail "the write lock was initialized $before time(s), then $after after \
$RELOADS reloads, so a reload re-initialized it under the workers"

# A rejected reload runs init_logger() too, and returns without cycling
# anything, so it needs checking separately. clntkey.pem is a well formed key
# that does not match servcert.pem.
write_config "$PORT" "$CERTS/clntkey.pem"
kill -HUP "$MASTER"
wait_for_lines 'Couldn.t reload config' 1 || fail "the reload was not rejected"

rejected=$(inits)
[ "$rejected" -eq "$before" ] \
    || fail "a rejected reload initialized the write lock again ($rejected \
against $before)"

# The workers have to still be able to log through that lock afterwards.
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null \
    || fail "listener on port $PORT stopped accepting"
wait_for_lines 'event=proxy' 1 || fail "no worker logged after the reloads"

kill -TERM "$MASTER" 2>/dev/null
for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
kill -KILL "$MASTER" 2>/dev/null
wait "$MASTER" 2>/dev/null
rm -rf "$RUN"
echo "PASS"
