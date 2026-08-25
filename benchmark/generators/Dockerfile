# tlsload as a container, for runs where subject and generator share one
# machine. It is built here rather than copied from build/ so that the
# generator links the same Debian libssl3 the subjects do, and so that its own
# crypto is not the one variable nobody controlled.
#
# -march matches build.sh rather than the host, so a containerized run and a
# cross-host run are comparing generators built the same way.
FROM debian:13 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY tlsload/tlsload.c /src/tlsload.c
RUN gcc -O2 -march=x86-64-v2 -Wall -Wextra -D_GNU_SOURCE \
        -o /tlsload /src/tlsload.c -lssl -lcrypto -lpthread -lm

FROM debian:13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3t64 \
    && apt-get install -y --only-upgrade libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /tlsload /usr/bin/tlsload
ENTRYPOINT ["tlsload"]
