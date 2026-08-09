#!/usr/bin/env bash
#
# Integration test for #50: a stopped and continued process must survive the
# EINTR that epoll_wait() returns on the way back.
#
# Usage: signals.sh <path to tlsproxy> <path to the example directory>
#
# app/main.c is not linked into any of the cmocka binaries, so parent_loop()
# and child_loop() can only be exercised by running the program.

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
    [ -f "$RUN/stderr.txt" ] && { echo "--- stderr ---"; cat "$RUN/stderr.txt"; }
    exit 1
}

# The config schema rejects listen-port 0, so we cannot ask the kernel for a
# free one. Start on a port derived from the pid and walk upwards until one
# binds, which keeps concurrent runs off each other's ports.
write_config() {
    cat > "$RUN/tlsproxy.yml" <<EOF
nworkers: 2
logfile: $LOG
loglevel: DEBUG

listeners:
  - name: sigtest
    target-ip: 127.0.0.1
    target-port: 9
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cacerts:
      - $CERTS/cacert.pem
      - $CERTS/intcert.pem
    servcert: $CERTS/servcert.pem
    servkey: $CERTS/servkey.pem
EOF
}

start_proxy() {
    for try in 0 1 2 3 4 5 6 7 8 9; do
        port=$(( 20000 + ($$ + try * 97) % 20000 ))
        rm -f "$LOG"
        write_config "$port"
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

start_proxy || fail "could not start the proxy on any candidate port"
WORKERS=$(pgrep -P "$MASTER" | tr '\n' ' ')
[ -n "$WORKERS" ] || fail "master $MASTER started no workers"
echo "master $MASTER, workers $WORKERS"

# The master. Before the fix _fatal() logged and returned, and the event loop
# then ran to nfds == -1 cast to size_t.
kill -STOP "$MASTER" || fail "could not stop the master"
kill -CONT "$MASTER" || fail "could not continue the master"
sleep 1
if ! kill -0 "$MASTER" 2>/dev/null; then
    wait "$MASTER"; rc=$?
    fail "master died after SIGSTOP/SIGCONT, wait status $rc"
fi
grep -q 'error_desc="Interrupted system call"' "$LOG" \
    || fail "master did not log the EINTR, so the test proved nothing"

# The workers. A worker that dies here is respawned, so the evidence is in the
# log rather than in whether anything is still running.
for w in $WORKERS; do kill -STOP "$w" || fail "could not stop worker $w"; done
for w in $WORKERS; do kill -CONT "$w" || fail "could not continue worker $w"; done
sleep 1
deaths=$(grep -c 'worker_state="dead"' "$LOG")
[ "$deaths" -eq 0 ] || fail "$deaths worker(s) died after SIGSTOP/SIGCONT"
after=$(pgrep -P "$MASTER" | tr '\n' ' ')
[ "$WORKERS" = "$after" ] || fail "workers changed: [$WORKERS] then [$after]"

# Everything above still passes if the proxy is alive but no longer serving,
# so check that the listener is still accepting after the round trip.
port=$(grep -o 'listen-port: [0-9]*' "$RUN/tlsproxy.yml" | grep -o '[0-9]*')
(exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null \
    || fail "listener on port $port stopped accepting"

kill -TERM "$MASTER" 2>/dev/null
for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
kill -KILL "$MASTER" 2>/dev/null
wait "$MASTER" 2>/dev/null
rm -rf "$RUN"
echo "PASS"
