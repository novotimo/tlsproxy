# nginx for the benchmark only. Identical to the official image except that
# libssl3 is brought to the same patch level the other two subjects carry, so
# that no part of the comparison is a difference in OpenSSL.
FROM nginx:1.29.4
RUN apt-get update \
    && apt-get install -y --only-upgrade libssl3 \
    && rm -rf /var/lib/apt/lists/*
