#!/bin/sh
# Builds the load generators for the generator host and records what they are.
# Run on the subject host; copy build/ across.
set -eu

MARCH="${MARCH:-x86-64-v2}"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src="$here/src"
out="$here/build"
mkdir -p "$src" "$out"

fetch() {
    if [ -d "$src/$1/.git" ]; then
        git -C "$src/$1" fetch -q --depth 1 origin HEAD
        git -C "$src/$1" reset -q --hard FETCH_HEAD
    else
        git clone -q --depth 1 "$2" "$src/$1"
    fi
    git -C "$src/$1" rev-parse HEAD
}

tls_perf_sha=$(fetch tls-perf https://github.com/tempesta-tech/tls-perf)
wrk2_sha=$(fetch wrk2 https://github.com/giltene/wrk2)

# tls-perf's Makefile hardcodes -march=native and the build host is not the
# generator host.
#
# libstdc++ and libgcc stay dynamic on purpose. Their static archives come from
# the build host's own toolchain, which on Gentoo is compiled to that host's
# -march, so linking them statically carries the build host's instruction set
# past -march=$MARCH and the binary dies of SIGILL on the generator.
g++ -O2 -march="$MARCH" -Wall -DL1DSZ=64 \
    -c "$src/tls-perf/main.cc" -o "$out/tls-perf.o"
g++ -o "$out/tls-perf" "$out/tls-perf.o" -lpthread -lssl -lcrypto
rm -f "$out/tls-perf.o"

# wrk2's Makefile has no -march, so it is baseline x86-64 already.
#
# It vendors LuaJIT 2.0.3, whose -b ELF object writer emits a section header
# string table that binutils 2.46 rejects. The link still succeeds, so the
# failure surfaces at run time as "PANIC: unprotected error in call to Lua API
# (attempt to index a nil value)" on the first request. LuaJIT can emit the
# bytecode as C instead, which avoids that writer, so build libluajit first,
# put a good bytecode.o in place, and let make find it already up to date.
make -C "$src/wrk2" -j"$(nproc)" deps/luajit/src/libluajit.a >/dev/null
mkdir -p "$src/wrk2/obj"
( cd "$src/wrk2/deps/luajit/src" \
  && ./luajit -b -t c "$src/wrk2/src/wrk.lua" "$src/wrk2/obj/bytecode.c" )
cc -std=c99 -O2 -c -o "$src/wrk2/obj/bytecode.o" "$src/wrk2/obj/bytecode.c"
make -C "$src/wrk2" -j"$(nproc)" >/dev/null
cp "$src/wrk2/wrk" "$out/wrk"

# A wrk that cannot load its embedded script exits 0 on the panic, so check.
"$out/wrk" -t1 -c1 -d1s -R 10 http://127.0.0.1:1 2>&1 \
    | grep -q PANIC && { echo "wrk: embedded script did not load" >&2; exit 1; }

# tlsload lives in this repo, so it is built from the tree rather than fetched.
gcc -O2 -march="$MARCH" -Wall -Wextra -D_GNU_SOURCE \
    -o "$out/tlsload" "$here/tlsload/tlsload.c" \
    -lssl -lcrypto -lpthread -lm

# The generator host has no AVX-512. Anything that reaches it dies of SIGILL
# there, and ssh reports a signal death only as exit 255 with no message.
for b in "$out/tls-perf" "$out/wrk" "$out/tlsload"; do
    n=$(objdump -d "$b" | grep -cE '%zmm|%k[1-7]\}' || true)
    [ "$n" -eq 0 ] || { echo "$b: $n AVX-512 instructions" >&2; exit 1; }
done

minglibc() {
    objdump -T "$1" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -uV | tail -1
}
sonames() {
    objdump -p "$1" | awk '/NEEDED/ {printf "%s ", $2}'
}

{
    echo "tls-perf   $tls_perf_sha"
    echo "wrk2       $wrk2_sha"
    echo "tlsload    $(git -C "$here/.." -c safe.directory='*' rev-parse --short HEAD 2>/dev/null || echo local)"
    echo "march      $MARCH"
    echo "build-host $(uname -srm), $(g++ --version | head -1)"
    echo "tls-perf   min $(minglibc "$out/tls-perf"), needs $(sonames "$out/tls-perf")"
    echo "wrk        min $(minglibc "$out/wrk"), needs $(sonames "$out/wrk")"
    echo "tlsload    min $(minglibc "$out/tlsload"), needs $(sonames "$out/tlsload")"
} | tee "$out/PROVENANCE"
