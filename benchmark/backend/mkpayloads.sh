#!/bin/sh
# Writes the fixed-size response bodies the backend serves.
set -eu

out=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/payload
mkdir -p "$out"

for spec in 64:64 1k:1024 8k:8192 64k:65536 1m:1048576; do
    name=${spec%%:*}
    size=${spec##*:}
    [ -s "$out/$name" ] && [ "$(wc -c < "$out/$name")" = "$size" ] && continue
    tr '\0' 'x' < /dev/zero | head -c "$size" > "$out/$name"
done

ls -l "$out" | awk 'NR>1 {printf "%-6s %s\n", $9, $5}'
