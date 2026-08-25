# hitch for the benchmark only. Debian ships 1.8.0, which is upstream's latest
# release, so the package is taken as-is and libssl3 is brought to the same
# patch level the other subjects carry.
#
# The image runs as root so that hitch can bind and then drop to the hitch user
# itself, which is what its own init script does; verify_privileges() in
# src/hitch.c refuses to run workers as root unless both user and group are
# set to root explicitly.
FROM debian:13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends hitch \
    && apt-get install -y --only-upgrade libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && (getent group hitch  >/dev/null || groupadd -r hitch) \
    && (getent passwd hitch >/dev/null \
        || useradd -r -g hitch -M -s /usr/sbin/nologin hitch)

CMD ["hitch", "--config=/etc/hitch/hitch.conf"]
