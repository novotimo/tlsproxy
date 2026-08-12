#!/usr/bin/env bash
#
# A listener whose cert-chain holds one self-signed certificate starts,
# accepts, and sends that certificate and nothing else. Nothing verifies what
# the operator named, so a leaf with no issuer above it is not an error here;
# what a client makes of it is the client's business, and openssl(1) reports
# 18, self-signed certificate, unless it has been handed the same file.
#
# Usage: selfsigned.sh <path to tlsproxy>
#
# init_openssl() lives in app/main.c, which is linked into the executable and
# not into the library the cmocka binaries use, so running the program is the
# only way to see what it does with a chain of one.
#
# openssl(1) does three jobs here: it makes the certificate, since example/
# has no self-signed leaf with a key beside it; it holds the backend port
# open, since the proxy defers the client handshake until its own connect to
# the backend has finished, so a refused backend leaves nothing to read; and
# it reads back what came over the wire. Without it the test exits 77 and
# CTest records a skip.

set -u

BIN=$1

command -v openssl >/dev/null 2>&1 || {
    echo "SKIP: openssl(1) is not on PATH"
    exit 77
}

RUN=$(mktemp -d)
LOG=$RUN/tlsproxy.log
MASTER=
BACKEND=

cleanup() {
    [ -n "$MASTER" ] && kill -KILL "$MASTER" 2>/dev/null
    [ -n "$BACKEND" ] && kill -KILL "$BACKEND" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$RUN"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    [ -f "$LOG" ] && { echo "--- log ---"; cat "$LOG"; }
    [ -f "$RUN/stderr.txt" ] \
        && { echo "--- stderr ---"; cat "$RUN/stderr.txt"; }
    exit 1
}

# An EC key so that generating one costs nothing worth measuring, and a day of
# validity so the fixture cannot be the reason a later run fails
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$RUN/servkey.pem" -out "$RUN/servcert.pem" -days 1 \
        -subj "/CN=selfsigned.test" >/dev/null 2>&1 \
    || fail "openssl could not generate the fixture certificate"
chmod 600 "$RUN/servkey.pem"

# $1 is the listen port and $2 the backend's. The schema rejects listen-port 0,
# so we cannot ask the kernel for a free one; start on a port derived from the
# pid and walk upwards, which keeps concurrent runs off each other.
write_config() {
    cat > "$RUN/tlsproxy.yml" <<EOF
nworkers: 1
logfile: $LOG
loglevel: DEBUG

listeners:
  - name: selfsigned
    target-ip: 127.0.0.1
    target-port: $2
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: $1
    cert-chain: $RUN/servcert.pem
    servkey: $RUN/servkey.pem
EOF
}

for try in 0 1 2 3 4 5 6 7 8 9; do
    PORT=$(( 20000 + ($$ + try * 89) % 20000 ))
    BACK=$(( PORT + 1 ))
    rm -f "$LOG"
    write_config "$PORT" "$BACK"

    # s_server never gets to speak TLS, since the client sends nothing after
    # its handshake and we tear the connection down; it is here to make the
    # proxy's connect() succeed and for no other reason
    openssl s_server -accept "127.0.0.1:$BACK" -cert "$RUN/servcert.pem" \
            -key "$RUN/servkey.pem" -quiet >/dev/null 2>&1 &
    BACKEND=$!

    ( cd "$RUN" && exec "$BIN" tlsproxy.yml ) \
        >"$RUN/stdout.txt" 2>"$RUN/stderr.txt" &
    MASTER=$!
    # The listen event is logged by a worker, so seeing it in the file means
    # the master got past init_openssl() and into parent_loop() draining the
    # ring. A master that refused the certificate dies in init_openssl()
    # instead and this loop runs out with the process gone.
    started=
    for _ in $(seq 50); do
        grep -q 'event=listen' "$LOG" 2>/dev/null && { started=1; break; }
        kill -0 "$MASTER" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$started" ] && break

    kill -KILL "$MASTER" 2>/dev/null
    kill -KILL "$BACKEND" 2>/dev/null
    wait "$MASTER" "$BACKEND" 2>/dev/null
    MASTER=
    BACKEND=
done
[ -n "$MASTER" ] || fail "the proxy would not start on any candidate port"
echo "master $MASTER on port $PORT, backend on $BACK"

# Logging the listener and accepting on it are different things, and only the
# second one is what the operator asked for.
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null \
    || fail "listener on port $PORT is not accepting"
exec 3>&-

WIRE=$(timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -showcerts \
       </dev/null 2>/dev/null)
NCERTS=$(printf '%s' "$WIRE" | grep -c 'BEGIN CERTIFICATE')
[ "$NCERTS" = 1 ] \
    || fail "expected the one certificate the file holds, got $NCERTS"

# With one certificate in the reply the range covers exactly that certificate
printf '%s' "$WIRE" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
    > "$RUN/wire.pem"
SENT=$(openssl x509 -in "$RUN/wire.pem" -noout -fingerprint -sha256)
NAMED=$(openssl x509 -in "$RUN/servcert.pem" -noout -fingerprint -sha256)
[ "$SENT" = "$NAMED" ] \
    || fail "the certificate sent is not the one named: $SENT vs $NAMED"

# A chain of one is a configuration we accept rather than one we tolerate, so
# it should have produced nothing to report at all.
grep -q 'level=ERROR\|level=FATAL' "$LOG" \
    && fail "a self-signed leaf was reported as an error"

kill -TERM "$MASTER" 2>/dev/null
for _ in $(seq 50); do
    kill -0 "$MASTER" 2>/dev/null || break
    sleep 0.1
done
kill -KILL "$MASTER" 2>/dev/null
kill -KILL "$BACKEND" 2>/dev/null
wait "$MASTER" "$BACKEND" 2>/dev/null
MASTER=
BACKEND=

echo "PASS"
