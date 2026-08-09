#!/bin/sh
# Per-second memory and socket-state time series for one subject under load.
# SVC=<service> LVL=<concurrency> DUR=<seconds> diag/memory-timeseries.sh
# Distinguishes memory that tracks live connections from memory that tracks
# connections completed.

BENCH=${BENCH:-$HOME/prog/tlsproxy/benchmark}
GEN=${GEN:-root@10.99.0.2}
SUBJECT_IP=${SUBJECT_IP:-10.99.0.1}
LVL=${LVL:-1024}
DUR=${DUR:-30}
SVC=${SVC:-nginx-stream}

cd "$BENCH"
echo "CERT=ecdsa" > .env
docker compose --profile "$SVC" rm -sf "$SVC" >/dev/null 2>&1 || true
docker compose --profile "$SVC" up -d "$SVC" >/dev/null
sleep 3
cid=$(docker compose --profile "$SVC" ps -q "$SVC")
cg=/sys/fs/cgroup/docker/$cid

per=$((LVL / 4))
ssh -n "$GEN" "ulimit -n 1048576; ./build/tls-perf -t 4 -l $per -T $DUR \
    --tls 1.3 --tickets off -c TLS_AES_256_GCM_SHA384 -C X25519 \
    $SUBJECT_IP 8443" > /tmp/nginx-diag-load.txt 2>&1 &
load=$!

echo "$SVC, c=$LVL, ${DUR}s.  client = sockets on :8443, backend = sockets to :80"
printf '%4s %8s %8s %6s  %s\n' t cur_MB anon_MB procs "socket states"

i=0
while [ "$i" -lt $((DUR + 5)) ]; do
    cur=$(( $(cat "$cg/memory.current" 2>/dev/null || echo 0) / 1048576 ))
    anon=$(( $(awk '/^anon /{print $2}' "$cg/memory.stat" 2>/dev/null || echo 0) / 1048576 ))
    np=$(wc -l < "$cg/cgroup.procs" 2>/dev/null || echo 0)
    s=$(docker exec "$cid" cat /proc/net/tcp 2>/dev/null | awk '
        function nm(s) {
            return s=="01"?"ESTAB" : s=="02"?"SYNSENT": s=="03"?"SYNRECV":
                   s=="04"?"FINW1" : s=="05"?"FINW2"  : s=="06"?"TIMEW"  :
                   s=="07"?"CLOSE" : s=="08"?"CLOSEW" : s=="09"?"LASTACK":
                   s=="0A"?"LISTEN": s }
        NR>1 { split($2,l,":"); split($3,r,":")
               if (l[2]=="20FB")      c[$4]++
               else if (r[2]=="0050") b[$4]++ }
        END { printf "client["; for (k in c) printf "%s=%d ", nm(k), c[k]
              printf "] backend["; for (k in b) printf "%s=%d ", nm(k), b[k]
              printf "]" }')
    printf '%4d %8s %8s %6s  %s\n' "$i" "$cur" "$anon" "$np" "$s"
    i=$((i + 1))
    sleep 1
done

wait "$load" 2>/dev/null || true
echo "--- generator said ---"
tail -4 /tmp/nginx-diag-load.txt
echo "--- 10s after the load stopped ---"
sleep 10
printf 'cur=%sMB anon=%sMB\n' \
    "$(( $(cat "$cg/memory.current") / 1048576 ))" \
    "$(( $(awk '/^anon /{print $2}' "$cg/memory.stat") / 1048576 ))"
docker compose --profile "$SVC" stop "$SVC" >/dev/null
