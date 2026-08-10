# tlsproxy for the benchmark only. The shipped image builds on alpine:edge,
# which pins nothing and gives a different libc and OpenSSL from the images
# nginx and haproxy publish. Here all three subjects run Debian 13 with the
# same glibc and the same libssl3, so the comparison is between the proxies
# rather than between their crypto libraries.
FROM debian:13 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config libssl-dev libcyaml-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY app app
COPY CMakeLists.txt CMakeLists.txt
COPY cmake cmake
COPY inc inc
COPY external external
COPY src src

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

FROM debian:13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libcyaml1 \
    && apt-get install -y --only-upgrade libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 2001 tlsproxy \
    && useradd -u 2001 -g 2001 -M -s /usr/sbin/nologin tlsproxy \
    && mkdir /etc/tlsproxy /var/log/tlsproxy \
    && chown tlsproxy:tlsproxy /etc/tlsproxy /var/log/tlsproxy

COPY --from=build /src/build/tlsproxy /usr/bin/tlsproxy

USER 2001:2001
CMD ["tlsproxy"]
