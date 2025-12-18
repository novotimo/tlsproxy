# syntax=docker/dockerfile:1

FROM alpine:edge AS build

RUN apk add --no-cache build-base cmake pkgconfig openssl-dev \
    && apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing libcyaml-dev

WORKDIR /src

COPY app app
COPY CMakeLists.txt CMakeLists.txt
COPY cmake cmake
COPY inc inc
COPY external external
COPY src src

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

FROM alpine:edge

LABEL maintainer="Timothy Copeland <tacopeland@proton.me>"

RUN set -x \
    && addgroup -g 2001 -S tlsproxy \
    && adduser -S -D -H -u 2001 -h / -s /sbin/nologin -G tlsproxy -g tlsproxy tlsproxy \
    && apk add --no-cache --virtual openssl \
    && apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing libcyaml \
    && mkdir /etc/tlsproxy && chown tlsproxy:tlsproxy /etc/tlsproxy \
    && mkdir /var/log/tlsproxy && chown tlsproxy:tlsproxy /var/log/tlsproxy

COPY --from=build /src/build/tlsproxy /usr/bin
RUN chown tlsproxy:tlsproxy /usr/bin/tlsproxy && chmod u+x /usr/bin/tlsproxy


USER 2001:2001

CMD ["tlsproxy", "/etc/tlsproxy/default.yml"]
