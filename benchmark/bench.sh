#!/bin/sh
# Drives one benchmark mode across subjects and writes CSV, raw generator
# output and provenance into results/<run>. All five modes share one CSV
# schema and one set of validity checks.
#
#   bench.sh -m handshake -x "64 256 1024 4096"     closed loop, axis = concurrency
#   bench.sh -m rate      -x "2000 4000 6000 8000"  open loop,   axis = offered rate
#   bench.sh -m idle      -x "1000 5000 20000"      held open,   axis = connections
#   bench.sh -m bulk      -x "64 1024 65536"        echo,        axis = payload bytes
#   bench.sh -m message   -x "1000 5000 20000"      echo,        axis = connections
#
# message holds its connections and sends one small message per connection every
# -i milliseconds, so its latency columns are msg_* and describe a round trip
# rather than a handshake. The hs_* columns still describe the handshakes that
# set the connections up.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

GEN=${GEN:-root@10.99.0.2}
SUBJECT_IP=${SUBJECT_IP:-10.99.0.1}
SUBJECT_IFACE=${SUBJECT_IFACE:-enp0s31f6}
GEN_IFACE=${GEN_IFACE:-enp4s0}
DOCKER=${DOCKER:-docker}
SSH=${SSH:-ssh}
# GEN=local runs the generator on this host instead, pinned off the subject's
# cpuset. The bulk test needs it: a gigabit link caps the data path far below
# what the subjects can do, so across the wire it would measure the NIC.
GEN_CPUS=${GEN_CPUS:-6,7,14,15}
GROUP=${GROUP:-X25519}
CIPHER=${CIPHER:-TLS_AES_256_GCM_SHA384}
TLSVER=${TLSVER:-1.3}
PORT=${PORT:-8443}

mode=handshake
subjects="tlsproxy nginx-stream haproxy-tcp"
certs="ecdsa"
axis="64 256 1024 4096"
conc=1024
rate=0
payload=1024
reqs=1
reps=6
dur=10
threads=0                       # 0 = one per generator CPU, see below
resume=0
interval=1000
lockstep=0
backend=""

while getopts "m:s:e:x:c:r:b:n:R:d:t:B:i:LK" o; do
    case $o in
    m) mode=$OPTARG ;;      s) subjects=$OPTARG ;;
    e) certs=$OPTARG ;;     x) axis=$OPTARG ;;
    c) conc=$OPTARG ;;      r) rate=$OPTARG ;;
    b) payload=$OPTARG ;;   n) reqs=$OPTARG ;;
    R) reps=$OPTARG ;;      d) dur=$OPTARG ;;
    t) threads=$OPTARG ;;   B) backend=$OPTARG ;;
    i) interval=$OPTARG ;;  L) lockstep=1 ;;
    K) resume=1 ;;
    *) echo "usage: $0 -m handshake|rate|idle|bulk|message [-x values]" \
            "[-s subjects]" >&2
       exit 2 ;;
    esac
done

case $mode in
handshake|rate|idle|bulk|message) : ;;
*) echo "mode must be handshake, rate, idle, bulk or message" >&2; exit 2 ;;
esac

# bulk and message need the sink echoing; the rest only need it to hold and to
# close.
if [ -z "$backend" ]; then
    backend=backend-sink
    case $mode in bulk|message) backend=backend-echo ;; esac
fi

run=$(date -u +%Y%m%dT%H%M%SZ)
out="results/$run"
mkdir -p "$out"
csv="$out/$mode.csv"
sha=$(git -C .. -c safe.directory='*' rev-parse --short HEAD)

cid()      { $DOCKER compose --profile "$1" ps -q "$1" 2>/dev/null | head -1; }
cpu_usec() { awk '/usage_usec/{print $2}' "$1/cpu.stat" 2>/dev/null || echo 0; }
procs()    { sort -n "$1/cgroup.procs" 2>/dev/null | tr '\n' ' '; }
throttle() { cat /sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count \
                 2>/dev/null || echo 0; }
mem_max()  { awk '/^max /{print $2}' "$1/memory.events" 2>/dev/null || echo 0; }

# The generator's own utilization, sampled around each rep. A subject that is
# not saturated while the generator is says the number belongs to the
# generator: measured on 2026-08-11, the 20,000 connection point of -m message
# had a p99 of 158 ms with four generator threads and 18.9 ms with twelve,
# against the same subject, because the generator could not service its own
# connections fast enough to time them accurately.
gen_stat() {
    [ "$GEN" = local ] && return 0
    $SSH -n "$GEN" 'head -1 /proc/stat' 2>/dev/null || true
}
gen_busy() {   # $1 = before, $2 = after
    [ -n "$1" ] && [ -n "$2" ] || return 0
    printf '%s\n%s\n' "$1" "$2" | awk '
        NR==1 { for (i=2;i<=NF;i++) { b[i]=$i; bt+=$i } bi=$5+$6 }
        NR==2 { for (i=2;i<=NF;i++) { at+=$i } ai=$5+$6
                d=at-bt; if (d>0) printf "%.1f", 100*(d-(ai-bi))/d }'
}

# One generator thread per CPU it has. The generator host runs nothing else, so
# there is no reason to leave any of it idle; a thread-starved generator shows
# up as subject latency and is very hard to tell apart from the real thing.
if [ "$threads" -eq 0 ]; then
    if [ "$GEN" = local ]; then
        threads=$(echo "$GEN_CPUS" | tr ',' '\n' | awk -F- \
                  '{ if (NF==2) n+=$2-$1+1; else n+=1 } END { print n }')
    else
        threads=$($SSH -n "$GEN" nproc 2>/dev/null || echo 4)
    fi
fi

sample_mem() {
    _cg=$1; _out=$2; _done=$3
    peak=0; pa=0; pf=0; ps=0
    while [ ! -f "$_done" ]; do
        cur=$(cat "$_cg/memory.current" 2>/dev/null || echo 0)
        set -- $(awk '/^anon /{a=$2} /^file /{f=$2} /^inactive_file /{i=$2}
                      /^slab /{s=$2}
                      END{printf "%d %d %d %d", a+0, f+0, i+0, s+0}' \
                 "$_cg/memory.stat" 2>/dev/null || echo 0 0 0 0)
        w=$((cur - $3))
        if [ "$w" -gt "$peak" ]; then peak=$w; pa=$1; pf=$2; ps=$4; fi
        sleep 1
    done
    echo "$peak $pa $pf $ps" > "$_out"
}

wait_port() {
    i=0
    while [ "$i" -lt 30 ]; do
        python3 -c "import socket;socket.create_connection(('127.0.0.1',$1),1).close()" \
            2>/dev/null && return 0
        i=$((i + 1)); sleep 1
    done
    echo "$2 never answered on port $1" >&2
    return 1
}

wait_ready() {
    i=0
    while [ "$i" -lt 60 ]; do
        if echo | openssl s_client -connect "127.0.0.1:$PORT" -brief \
             >/dev/null 2>&1; then return 0; fi
        i=$((i + 1)); sleep 1
    done
    echo "$1 never answered on $PORT" >&2
    return 1
}

{
    echo "run              $run"
    echo "tlsproxy_sha     $sha"
    echo "mode             $mode"
    echo "axis             $axis"
    echo "backend          $backend"
    echo "subject_ip       $SUBJECT_IP"
    echo "generator        $GEN"
    [ "$GEN" = local ] && echo "generator_cpus   $GEN_CPUS"
    echo "group            $GROUP"
    echo "cipher           $CIPHER"
    echo "tls_version      $TLSVER"
    echo "resumption       $resume"
    [ "$mode" = message ] && echo "msg_interval_ms  $interval"
    [ "$mode" = message ] && echo "msg_lockstep     $lockstep"
    echo "duration_s       $dur"
    echo "reps             $reps"
    echo "threads          $threads"
    echo "--- subject host ---"
    IFACE=$SUBJECT_IFACE sh ./tune.sh subject --show
    echo "--- generator host ---"
    $SSH -n "$GEN" "IFACE=$GEN_IFACE sh /root/tune.sh generator --show" || true
    echo "--- generators ---"
    cat generators/build/PROVENANCE
    echo "--- subject worker counts ---"
    grep -h "^nworkers:" subjects/tlsproxy/tlsproxy.yml
    grep -h "worker_processes" subjects/nginx/stream/nginx.conf
    grep -h "nbthread" subjects/haproxy/tcp/haproxy.cfg
    echo "--- subject images ---"
    for i in nginx:bench haproxy:3.2.22 tlsproxy:bench-deb; do
        printf '%-22s ' "$i"
        $DOCKER run --rm --entrypoint sh "$i" -c \
            '. /etc/os-release; printf "%s %s libssl3=%s\n" "$ID" "$VERSION_ID" \
             "$(dpkg -l | awk "/ libssl3/{print \$3}" | head -1)"' 2>/dev/null \
            || echo "?"
    done
} > "$out/provenance.txt" 2>&1

echo "run,sha,mode,model,subject,cert,resume,axis,concurrency,offered_rate,payload,reqs,threads,duration,rep,completed,rate,errors,shed,hs_p50,hs_p95,hs_p99,hs_p999,hs_max,msg_p50,msg_p95,msg_p99,msg_p999,msg_max,mb_per_sec,cpu_cores,gen_busy_pct,ws_peak_bytes,anon_bytes,file_bytes,slab_bytes,mem_max_delta,throttle_delta,workers_stable,run_ok" > "$csv"

bport=8080
case $backend in backend-sink) bport=8081 ;; backend-echo) bport=8082 ;; esac
for b in backend backend-sink backend-echo; do
    [ "$b" = "$backend" ] \
        || $DOCKER compose --profile sink rm -sf "$b" >/dev/null 2>&1 || true
done
$DOCKER compose --profile sink up -d "$backend" >/dev/null
wait_port "$bport" "$backend"

for cert in $certs; do
    echo "CERT=$cert" > .env
    for subj in $subjects; do
        $DOCKER compose --profile "$subj" rm -sf "$subj" >/dev/null 2>&1 || true
        $DOCKER compose --profile "$subj" up -d "$subj" >/dev/null
        wait_ready "$subj"
        cg="/sys/fs/cgroup/docker/$(cid "$subj")"

        for x in $axis; do
            a_conc=$conc; a_rate=$rate; a_pay=$payload
            case $mode in
            handshake|idle|message) a_conc=$x ;;
            rate)                   a_rate=$x ;;
            bulk)                   a_pay=$x ;;
            esac

            case $mode in
            handshake) margs="-m handshake -c $a_conc" ;;
            idle)      margs="-m hold -c $a_conc -H 0" ;;
            rate)      margs="-m handshake -r $a_rate -M 400000" ;;
            bulk)      margs="-m request -c $a_conc -b $a_pay -n $reqs" ;;
            message)   margs="-m message -c $a_conc -b $a_pay -I $interval" ;;
            esac
            [ "$mode" = message ] && [ "$lockstep" = 1 ] && margs="$margs -L"
            [ "$resume" = 1 ] && margs="$margs -R"

            for rep in $(seq 1 "$reps"); do
                raw="$out/$mode-$subj-$cert-x$x-r$rep.txt"
                pre_procs=$(procs "$cg"); pre_cpu=$(cpu_usec "$cg")
                pre_thr=$(throttle);      pre_mm=$(mem_max "$cg")
                pre_gen=$(gen_stat)

                rm -f "$out/.done" "$out/.mem"
                sample_mem "$cg" "$out/.mem" "$out/.done" &
                sampler=$!

                if [ "$GEN" = local ]; then
                    taskset -c "$GEN_CPUS" sh -c "ulimit -n 1048576; \
                        generators/build/tlsload $margs -d $dur -t $threads \
                        -V $TLSVER -G $GROUP -k $CIPHER 127.0.0.1 $PORT" \
                        > "$raw" 2>&1 || true
                else
                    $SSH -n "$GEN" "ulimit -n 1048576; ./build/tlsload $margs \
                        -d $dur -t $threads -V $TLSVER -G $GROUP -k $CIPHER \
                        $SUBJECT_IP $PORT" > "$raw" 2>&1 || true
                fi

                touch "$out/.done"; wait "$sampler" 2>/dev/null || true
                post_gen=$(gen_stat)
                gbusy=$(gen_busy "$pre_gen" "$post_gen")
                post_cpu=$(cpu_usec "$cg"); post_procs=$(procs "$cg")
                post_thr=$(throttle);       post_mm=$(mem_max "$cg")
                set -- $(cat "$out/.mem" 2>/dev/null || echo 0 0 0 0)
                ws=$1; anon=$2; file=$3; slab=$4

                stats=$(awk '
                    /^completed=/ { ok=1
                        for (i=1;i<=NF;i++) { split($i,kv,"=")
                            if (kv[1]=="completed") comp=kv[2]
                            if (kv[1]=="rate")      rt=kv[2]
                            if (kv[1]=="errors")    er=kv[2]
                            if (kv[1]=="shed")      sh=kv[2] } }
                    /^handshakes=/ {
                        for (i=1;i<=NF;i++) { split($i,kv,"=")
                            if (kv[1]=="hs_ms_p50") p50=kv[2]
                            if (kv[1]=="p95")  p95=kv[2]
                            if (kv[1]=="p99")  p99=kv[2]
                            if (kv[1]=="p999") p999=kv[2]
                            if (kv[1]=="max")  mx=kv[2] } }
                    # Left empty rather than zeroed for the modes that send no
                    # messages, so a median never averages in a column that was
                    # never measured.
                    /^messages=/ {
                        for (i=1;i<=NF;i++) { split($i,kv,"=")
                            if (kv[1]=="msg_ms_p50") m50=kv[2]
                            if (kv[1]=="p95")  m95=kv[2]
                            if (kv[1]=="p99")  m99=kv[2]
                            if (kv[1]=="p999") m999=kv[2]
                            if (kv[1]=="max")  mmx=kv[2] } }
                    /^bytes_up=/ {
                        for (i=1;i<=NF;i++) { split($i,kv,"=")
                            if (kv[1]=="mbytes_per_sec") mb=kv[2] } }
                    END { printf "%d,%d,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d",
                          comp+0, rt+0, er+0, sh+0, p50+0, p95+0, p99+0,
                          p999+0, mx+0, m50, m95, m99, m999, mmx, mb+0, ok+0 }
                ' "$raw")
                ok=${stats##*,}; stats=${stats%,*}

                cores=$(awk -v a="$pre_cpu" -v b="$post_cpu" -v d="$dur" \
                            'BEGIN{printf "%.3f",(b-a)/1000000/d}')
                stable=0; [ "$pre_procs" = "$post_procs" ] && stable=1
                tdelta=$((post_thr - pre_thr)); mmdelta=$((post_mm - pre_mm))
                # message is open per message rather than per connection: the
                # send grid is fixed in advance, so a subject that cannot keep
                # up misses slots instead of being offered less.
                model=closed
                case $mode in rate|message) model=open ;; esac

                echo "$run,$sha,$mode,$model,$subj,$cert,$resume,$x,$a_conc,$a_rate,$a_pay,$reqs,$threads,$dur,$rep,$stats,$cores,$gbusy,$ws,$anon,$file,$slab,$mmdelta,$tdelta,$stable,$ok" >> "$csv"

                comp=${stats%%,*};  rest=${stats#*,}
                rt=${rest%%,*};     rest=${rest#*,}
                er=${rest%%,*};     rest=${rest#*,}
                sh=${rest%%,*}
                printf '%-9s %-13s x=%-6s r=%s %7s/s %5s cores %6sMB err=%s shed=%s%s%s%s%s%s\n' \
                    "$mode" "$subj" "$x" "$rep" "$rt" "$cores" \
                    "$((ws / 1048576))" "$er" "$sh" \
                    "$([ "$stable" = 1 ] || echo '  WORKERS-CHANGED')" \
                    "$([ "$tdelta" = 0 ] || echo '  THROTTLED')" \
                    "$([ "$mmdelta" = 0 ] || echo '  MEM-PRESSURE')" \
                    "$([ "$ok" = 1 ] || echo '  RUN-FAILED')" \
                    "$(awk -v g="$gbusy" 'BEGIN{if (g+0 >= 70) print "  GEN-BUSY " int(g) "%"}')"
            done
        done
        $DOCKER compose --profile "$subj" rm -sf "$subj" >/dev/null 2>&1 || true
    done
done

rm -f "$out/.done" "$out/.mem"
echo
echo "csv:        $csv"
echo "provenance: $out/provenance.txt"
