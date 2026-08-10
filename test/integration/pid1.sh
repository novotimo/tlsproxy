#!/usr/bin/env bash
#
# Integration test for #69: the master must serve when it is PID 1, and the
# branch that gives up on respawning must say so on stderr.
#
# Usage: pid1.sh <path to tlsproxy> <path to the example directory>
#
# Both faults live in app/main.c, which is linked into the executable and not
# into the library the cmocka binaries use, so the only way to see either one
# is to run the program.
#
# The first half needs a PID namespace, which an unprivileged user namespace
# provides where the kernel allows it. Where it does not, that half is skipped
# and the second half still runs.

set -u

BIN=$1
CERTS=$2

RUN=$(mktemp -d)
MASTER=

fail() {
    echo "FAIL: $*"
    [ -n "$MASTER" ] && kill -KILL "$MASTER" 2>/dev/null
    for f in "$RUN"/stderr.txt "$RUN"/stdout.txt; do
        [ -s "$f" ] && { echo "--- $(basename "$f") ---"; cat "$f"; }
    done
    exit 1
}

# $1 is the listen port and $2 the logfile, left out of the file altogether
# when it is empty, which is the case that used to produce no output at all.
# The schema rejects listen-port 0, so we cannot ask the kernel for a free
# one; start on a port derived from the pid and walk upwards, which keeps
# concurrent runs off each other.
write_config() {
    { [ -n "$2" ] && echo "logfile: $2"; cat <<EOF
nworkers: 2
loglevel: DEBUG

listeners:
  - name: pid1test
    target-ip: 127.0.0.1
    target-port: 9
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cert-chain: $CERTS/chain.pem
    servkey: $CERTS/servkey.pem
EOF
    } > "$RUN/tlsproxy.yml"
}

port_for() { echo $(( 20000 + ($$ + $1 * 89) % 20000 )); }

# ---------------------------------------------------------------- as PID 1

if unshare -rpf --mount-proc true 2>/dev/null; then
    started=
    for try in 0 1 2 3 4 5 6 7 8 9; do
        PORT=$(port_for "$try")
        write_config "$PORT" ""
        ( cd "$RUN" && exec unshare -rpf --mount-proc "$BIN" tlsproxy.yml ) \
            >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
        MASTER=$!
        # Before the fix every worker read getppid() == 1 as "the master is
        # gone", exited, and the master gave up on respawning them inside a
        # second. Waiting for the port to accept covers both the exit and a
        # master that is alive without serving.
        for _ in $(seq 30); do
            if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
                exec 3>&-
                started=1
                break
            fi
            kill -0 "$MASTER" 2>/dev/null || break
            sleep 0.1
        done
        [ -n "$started" ] && break
        kill -KILL "$MASTER" 2>/dev/null
        wait "$MASTER" 2>/dev/null
        MASTER=
    done
    [ -n "$started" ] || fail "nothing accepted on any port with the master as PID 1"
    echo "served on port $PORT with the master as PID 1"

    # unshare(1) forks the master and waits for it without forwarding
    # anything, so the signal has to go to the master itself. It arrives
    # despite the master being the namespace's init, since the kernel exempts
    # blocked signals from the SIGNAL_UNKILLABLE check in sig_ignored() and
    # every signal we care about is blocked for the signalfd.
    for p in $(pgrep -P "$MASTER" 2>/dev/null); do
        kill -TERM "$p" 2>/dev/null
    done
    for _ in $(seq 50); do
        kill -0 "$MASTER" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$MASTER" 2>/dev/null
    wait "$MASTER" 2>/dev/null
    MASTER=
else
    echo "SKIP: unprivileged PID namespaces are unavailable, PID 1 half skipped"
fi

# ------------------------------------------------- giving up out loud

# No logfile, so the logger is disabled and stderr is the only way this can
# be reported at all.
started=
for try in 10 11 12 13 14 15 16 17 18 19; do
    PORT=$(port_for "$try")
    write_config "$PORT" ""
    ( cd "$RUN" && exec "$BIN" tlsproxy.yml ) \
        >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
    MASTER=$!
    for _ in $(seq 30); do
        [ -n "$(pgrep -P "$MASTER" 2>/dev/null)" ] && { started=1; break; }
        kill -0 "$MASTER" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$started" ] && break
    kill -KILL "$MASTER" 2>/dev/null
    wait "$MASTER" 2>/dev/null
    MASTER=
done
[ -n "$started" ] || fail "the proxy would not start on any candidate port"
echo "master $MASTER on port $PORT"

# TPX_RESTART_MAX * nworkers restarts inside TPX_RESTART_WINDOW seconds is the
# threshold, so 2 workers killed 6 times over is past it with room to spare.
# The pids are re-read each round rather than remembered, since a respawned
# worker is a different process.
for _ in $(seq 6); do
    for w in $(pgrep -P "$MASTER" 2>/dev/null); do
        kill -KILL "$w" 2>/dev/null
    done
    sleep 0.2
done

for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$MASTER" 2>/dev/null; then
    kill -KILL "$MASTER" 2>/dev/null
    fail "the master outlived $((6 * 2)) worker kills without giving up"
fi
wait "$MASTER" 2>/dev/null
rc=$?
MASTER=

[ "$rc" -eq 77 ] || fail "master exited $rc, expected 77"
grep -q 'Workers dying faster than they can be replaced' "$RUN/stderr.txt" \
    || fail "the master gave up without saying so on stderr"

rm -rf "$RUN"
echo "PASS"
