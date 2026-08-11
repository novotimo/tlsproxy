#!/bin/sh
# Profiles one or all three subjects under identical handshake load and writes
# perf output, a flamegraph and syscall counts per subject into
# profile-results/<run>. Everything runs as the invoking user, so no privilege
# is needed; the container path would need root to profile another uid.
#
#   profile.sh                    all three
#   profile.sh tlsproxy           just ours
#   BUILD=1 profile.sh            rebuild the comparators first
#
# Needs dev-util/perf and dev-util/FlameGraph, and
# kernel.perf_event_paranoid at 1 or lower.
#
# This is deliberately not bench.sh. bench.sh measures the shipped image in a
# cgroup against the generator host, and its numbers are the ones that go in a
# report; this runs everything on one machine as one user so that perf can
# attach, and its numbers are only comparable to other runs of itself.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

OPENSSL=${OPENSSL:-$HOME/prog/openssl}
HAPROXY_SRC=${HAPROXY_SRC:-$HOME/prog/haproxy}
NGINX_SRC=${NGINX_SRC:-$HOME/prog/nginx}
# Four physical cores and their siblings for the subject, two for the backend,
# the rest for the generator. Matches compose.yml's cpuset for the subject.
SUBJ_CPUS=${SUBJ_CPUS:-0-3,8-11}
SINK_CPUS=${SINK_CPUS:-4,12}
GEN_CPUS=${GEN_CPUS:-5-7,13-15}
WORKERS=${WORKERS:-8}            # one per logical CPU in SUBJ_CPUS
CONC=${CONC:-256}
GEN_THREADS=${GEN_THREADS:-6}
DUR=${DUR:-12}
# strace costs two traps per call, so the syscall pass runs at a concurrency
# that cannot pile connections up against the 4096 descriptor limit.
SC_CONC=${SC_CONC:-16}

subjects=${*:-tlsproxy haproxy nginx}
run=$(date -u +%Y%m%dT%H%M%SZ)
out="profile-results/$run"
# Builds are cached across runs, since haproxy and nginx take a couple of
# minutes each and neither changes between profiles of our tree.
work="profile-results/.build"
mkdir -p "$out" "$work"
certs="$here/certs/ecdsa"
[ -r "$certs/leaf.key" ] || { echo "certs/ecdsa is missing, run certs/mkcerts.sh" >&2; exit 1; }

for t in perf stackcollapse-perf.pl flamegraph.pl; do
    command -v "$t" >/dev/null || { echo "$t not found" >&2; exit 1; }
done
[ "$(cat /proc/sys/kernel/perf_event_paranoid)" -le 1 ] \
    || { echo "set kernel.perf_event_paranoid to 1 or lower" >&2; exit 1; }

# ---------------------------------------------------------------- builds

build_tlsproxy() {
    # RelWithDebInfo rather than Release: Release has no symbols, and without
    # frame pointers a call graph comes back as hex. -U_FORTIFY_SOURCE because
    # GCC on this host predefines it and -fhardened redefines it, which -Werror
    # turns into a build failure for anything that optimizes.
    cmake -B "$work/build" -S .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
          -DCMAKE_C_FLAGS="-U_FORTIFY_SOURCE -fno-omit-frame-pointer" \
          > "$work/tlsproxy-build.log" 2>&1
    cmake --build "$work/build" -j >> "$work/tlsproxy-build.log" 2>&1
}

build_comparators() {
    # Both against the same OpenSSL tlsproxy uses, so the proxy is the only
    # variable. A worktree each, so neither source tree is touched.
    rm -rf "$work/hap" "$work/ngx"
    git -C "$HAPROXY_SRC" worktree add -q --detach "$PWD/$work/hap" HEAD
    ( cd "$work/hap" && make -j"$(nproc)" TARGET=linux-glibc USE_OPENSSL=1 \
        USE_PCRE= USE_ZLIB= SSL_INC="$OPENSSL/include" SSL_LIB="$OPENSSL" \
        DEBUG_CFLAGS="-g -fno-omit-frame-pointer" ) > "$work/hap-build.log" 2>&1
    git -C "$NGINX_SRC" worktree add -q --detach "$PWD/$work/ngx" HEAD
    ( cd "$work/ngx" && auto/configure --prefix="$PWD/root" --with-stream \
        --with-stream_ssl_module --without-http \
        --with-cc-opt="-O2 -g -fno-omit-frame-pointer -I$OPENSSL/include" \
        --with-ld-opt="-L$OPENSSL -Wl,-rpath,$OPENSSL" \
      && make -j"$(nproc)" ) > "$work/ngx-build.log" 2>&1
    mkdir -p "$work/ngx/root/logs"
}

# ---------------------------------------------------------------- configs

write_configs() {
    cat > "$work/tlsproxy.yml" <<EOF
nworkers: $WORKERS
listeners:
  - name: prof
    target-ip: 127.0.0.1
    target-port: 9099
    connect-timeout: 5
    listen-ip: 127.0.0.1
    listen-port: 9443
    cert-chain: $certs/chain.crt
    servkey: $certs/leaf.key
EOF
    # Mirrors subjects/haproxy/tcp/haproxy.cfg, with maxconn brought under the
    # 4096 descriptor limit a normal user has, since haproxy raises RLIMIT_NOFILE
    # to match maxconn and refuses to start if it cannot.
    cat > "$work/haproxy.cfg" <<EOF
global
    nbthread $WORKERS
    maxconn  1200
    tune.ssl.cachesize 0
    ssl-default-bind-options no-tls-tickets

defaults
    mode    tcp
    timeout connect 5s
    timeout client  60s
    timeout server  60s

frontend bench
    bind 127.0.0.1:9443 ssl crt $certs/leaf.pem
    default_backend origin

backend origin
    server s 127.0.0.1:9099
EOF
    cat > "$work/nginx.conf" <<EOF
daemon               off;
worker_processes     $WORKERS;
error_log            stderr warn;
pid                  $PWD/$work/ngx/root/nginx.pid;

events {
    worker_connections 1024;
    multi_accept       on;
}

stream {
    server {
        listen     127.0.0.1:9443 ssl backlog=65535 reuseport;
        proxy_pass 127.0.0.1:9099;
        proxy_connect_timeout 5s;

        ssl_certificate     $certs/chain.crt;
        ssl_certificate_key $certs/leaf.key;
        ssl_session_cache   off;
        ssl_session_tickets off;
    }
}
EOF
}

# ---------------------------------------------------------------- run

stop_all() {
    for pat in '[t]lsproxy: ' '[h]aproxy -f' '[n]ginx:' '[s]ink -p 9099'; do
        for p in $(pgrep -u "$(id -u)" -f "$pat" 2>/dev/null); do
            kill "$p" 2>/dev/null || true
        done
    done
    sleep 1
}

start_sink() {
    setsid taskset -c "$SINK_CPUS" "$work/sink" -p 9099 -w 2 >/dev/null 2>&1 &
    sleep 1
}

# $1 = subject, $2 = optional wrapper (strace ...)
start_subject() {
    _w=${2:-}
    case $1 in
    tlsproxy) ( cd "$work" && LD_LIBRARY_PATH=$OPENSSL setsid taskset \
        -c "$SUBJ_CPUS" $_w ./build/tlsproxy tlsproxy.yml >/dev/null 2>&1 & ) ;;
    haproxy)  LD_LIBRARY_PATH=$OPENSSL setsid taskset -c "$SUBJ_CPUS" $_w \
        "$work/hap/haproxy" -f "$work/haproxy.cfg" >/dev/null 2>&1 & ;;
    nginx)    setsid taskset -c "$SUBJ_CPUS" $_w "$work/ngx/objs/nginx" \
        -c "$PWD/$work/nginx.conf" -p "$PWD/$work/ngx/root" >/dev/null 2>&1 & ;;
    esac
    sleep 3
}

# haproxy is one process with nbthread threads, so perf -p covers it whole.
subject_pids() {
    case $1 in
    tlsproxy) pgrep -u "$(id -u)" -f '[t]lsproxy: worker' ;;
    haproxy)  pgrep -u "$(id -u)" -f '[h]aproxy -f' ;;
    nginx)    pgrep -u "$(id -u)" -f '[n]ginx: worker' ;;
    esac | tr '\n' ',' | sed 's/,$//'
}

load() {        # $1 = duration, $2 = concurrency, $3 = output file
    taskset -c "$GEN_CPUS" generators/build/tlsload -m handshake -c "$2" \
        -d "$1" -t "$GEN_THREADS" -V 1.3 -G X25519 \
        -k TLS_AES_256_GCM_SHA384 127.0.0.1 9443 > "$3" 2>&1
}

profile_one() {
    s=$1
    stop_all; start_sink; start_subject "$s"
    p=$(subject_pids "$s")
    [ -n "$p" ] || { echo "$s: did not start, see $work" >&2; return 1; }

    load $((DUR + 4)) "$CONC" "$out/$s-load-stat.txt" & lp=$!
    sleep 2
    perf stat -e task-clock,cycles,instructions,branch-misses,cache-misses,context-switches \
        -p "$p" -o "$out/$s-stat.txt" -- sleep "$DUR"
    wait "$lp" 2>/dev/null || true

    load $((DUR + 4)) "$CONC" "$out/$s-load-rec.txt" & lp=$!
    sleep 2
    # LBR rather than DWARF: the kernel is built without frame pointers, so fp
    # mode truncates at the first library frame, and DWARF costs four times the
    # data and truncates deep stacks instead.
    perf record -F 999 --call-graph lbr -p "$p" -o "$out/$s.data" \
        -- sleep "$DUR" >/dev/null 2>&1
    wait "$lp" 2>/dev/null || true
    stop_all

    perf report -i "$out/$s.data" --stdio --no-children -g none \
        --percent-limit 0.05 > "$out/$s-flat.txt" 2>/dev/null
    perf report -i "$out/$s.data" --stdio --sort=dso -g none \
        > "$out/$s-dso.txt" 2>/dev/null
    perf report -i "$out/$s.data" --stdio --children -g graph,0.5,caller \
        --percent-limit 0.5 > "$out/$s-callgraph.txt" 2>/dev/null
    perf script -i "$out/$s.data" 2>/dev/null | stackcollapse-perf.pl \
        > "$out/$s.folded"
    flamegraph.pl --title "$s, $WORKERS workers, -m handshake -c $CONC" \
        "$out/$s.folded" > "$out/$s-flame.svg"

    # Syscalls, from a separate run: strace rather than perf trace, which needs
    # /sys/kernel/tracing, and launched rather than attached, which yama
    # ptrace_scope=1 refuses.
    stop_all; start_sink
    start_subject "$s" "strace -f -c -o $PWD/$out/$s-syscalls.txt"
    load 10 "$SC_CONC" "$out/$s-sc-load.txt"
    stop_all
}

# ---------------------------------------------------------------- provenance

{
    echo "run          $run"
    echo "sha          $(git -C .. -c safe.directory='*' rev-parse --short HEAD)"
    echo "dirty        $(git -C .. status --porcelain -- src inc app | wc -l) file(s) in src inc app"
    echo "subjects     $subjects"
    echo "workers      $WORKERS"
    echo "concurrency  $CONC"
    echo "duration     $DUR"
    echo "subject cpus $SUBJ_CPUS"
    echo "sink cpus    $SINK_CPUS"
    echo "gen cpus     $GEN_CPUS"
    echo "openssl      $("$OPENSSL/apps/openssl" version 2>/dev/null || echo "$OPENSSL")"
    echo "perf         $(perf --version)"
    echo "paranoid     $(cat /proc/sys/kernel/perf_event_paranoid)"
    echo "governor     $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
    echo "no_turbo     $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)"
    echo "mitigations  $(grep -h . /sys/devices/system/cpu/vulnerabilities/spectre_v2)"
} > "$out/provenance.txt"

cc -O2 -o "$work/sink" backend/sink/sink.c
build_tlsproxy
case " $subjects " in *haproxy*|*nginx*) [ -x "$work/hap/haproxy" ] || BUILD=1 ;; esac
[ "${BUILD:-0}" = 1 ] && build_comparators
write_configs

for s in $subjects; do
    printf '%-9s ' "$s"
    profile_one "$s" || continue
    awk '/msec task-clock/{gsub(",","",$1); tc=$1}
         END{printf "task-clock %.0f ms  ", tc}' "$out/$s-stat.txt"
    awk -F'[= ]' '/^completed/{printf "%s hs/s  errors=%s\n", $4, $6}' \
        "$out/$s-load-stat.txt"
done

stop_all
echo
echo "results:  $out"
echo "flame:    $out/<subject>-flame.svg"
