#!/bin/sh
# Applies and records the host tuning a run depends on.
# Usage: tune.sh <subject|generator> [--show]
# --show records without changing anything. Settings are not persistent.
set -eu

role="${1:?usage: tune.sh <subject|generator> [--show]}"
mode="${2:-apply}"
iface="${IFACE:-}"

set_sysctl() {
    [ "$mode" = "--show" ] && return 0
    sysctl -qw "$1=$2"
}

# For keys that only exist once a module is loaded.
set_sysctl_opt() {
    [ "$mode" = "--show" ] && return 0
    [ -e "/proc/sys/$(echo "$1" | tr . /)" ] || return 0
    sysctl -qw "$1=$2"
}

case "$role" in
generator)
    # 4-tuple space and TIME_WAIT recycling: the client closes first in every
    # churn test, so this is what caps new connections per second.
    set_sysctl net.ipv4.ip_local_port_range "1024 65535"
    set_sysctl net.ipv4.tcp_tw_reuse 1
    set_sysctl net.ipv4.tcp_max_tw_buckets 2000000
    ;;
subject)
    set_sysctl net.core.somaxconn 65535
    set_sysctl net.ipv4.tcp_max_syn_backlog 65535
    # Published ports are DNAT, so every connection takes a conntrack entry.
    # Needs the docker daemon up first, since that is what loads the module.
    set_sysctl_opt net.netfilter.nf_conntrack_max 1048576
    set_sysctl_opt net.netfilter.nf_conntrack_tcp_timeout_time_wait 30
    # Base clock on every core. Gives up peak throughput for runs that can be
    # compared to each other.
    if [ "$mode" != "--show" ]; then
        for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [ -w "$g" ] && echo performance > "$g"
        done || true
        if [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
        fi
    fi
    ;;
*)
    echo "role must be subject or generator" >&2
    exit 2
    ;;
esac
set_sysctl net.core.rmem_max 16777216
set_sysctl net.core.wmem_max 16777216
set_sysctl net.core.netdev_max_backlog 16384

show() { printf '%-32s %s\n' "$1" "$(cat "$2" 2>/dev/null || echo MISSING)"; }

echo "role                             $role"
echo "host                             $(uname -srm)"
for k in net.ipv4.ip_local_port_range net.ipv4.tcp_tw_reuse \
         net.ipv4.tcp_max_tw_buckets net.core.somaxconn \
         net.ipv4.tcp_max_syn_backlog net.core.rmem_max net.core.wmem_max \
         net.core.netdev_max_backlog; do
    printf '%-32s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null | tr '\t' ' ')"
done
for k in net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_count \
         net.netfilter.nf_conntrack_tcp_timeout_time_wait; do
    printf '%-32s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo MISSING)"
done
printf '%-32s %s\n' "nofile soft/hard" "$(ulimit -Sn)/$(ulimit -Hn)"
printf '%-32s %s\n' "fs.nr_open" "$(sysctl -n fs.nr_open)"

if [ -n "$iface" ]; then
    printf '%-32s %s\n' "iface" "$iface"
    show "iface.speed" "/sys/class/net/$iface/speed"
    show "iface.duplex" "/sys/class/net/$iface/duplex"
    show "iface.mtu" "/sys/class/net/$iface/mtu"
    if command -v ethtool >/dev/null 2>&1; then
        printf '%-32s %s\n' "iface.offloads" \
            "$(ethtool -k "$iface" 2>/dev/null \
               | awk '/^(rx|tx)-checksumming|^(tcp-segmentation|generic-)/ \
                      {printf "%s%s ", $1, $2}')"
        printf '%-32s %s\n' "iface.coalesce" \
            "$(ethtool -c "$iface" 2>/dev/null \
               | awk '/^(rx|tx)-usecs:/ {printf "%s%s ", $1, $2}')"
        printf '%-32s %s\n' "iface.ring" \
            "$(ethtool -g "$iface" 2>/dev/null | awk '/^(RX|TX):/ {print $2}' \
               | paste -sd/ -)"
    fi
fi

if [ "$role" = subject ] && [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    show "cpu.governor" /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
    show "cpu.no_turbo" /sys/devices/system/cpu/intel_pstate/no_turbo
    show "cpu.throttle_count" \
        /sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count
fi
