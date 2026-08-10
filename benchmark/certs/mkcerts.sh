#!/bin/sh
# Generates the certificates every subject shares: a CA per algorithm and a
# leaf signed by it. All three subjects serve the same two-certificate chain,
# so the handshake carries the same bytes whichever one is under test.
#
# A lone self-signed leaf is not usable here: SSL_CTX_build_cert_chain()
# returns 2 for one, and app/main.c:init_openssl() treats anything but 1 as
# fatal, so tlsproxy will not start with one in cert-chain.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
san="subjectAltName=DNS:bench,IP:10.99.0.1,IP:127.0.0.1"

gen() {
    name=$1
    shift
    d="$here/$name"
    mkdir -p "$d"

    openssl req -x509 -nodes -days 3650 -subj "/CN=bench-ca-$name" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        "$@" -keyout "$d/ca.key" -out "$d/ca.crt" 2>/dev/null

    openssl req -new -nodes -subj "/CN=bench" \
        "$@" -keyout "$d/leaf.key" -out "$d/leaf.csr" 2>/dev/null
    openssl x509 -req -in "$d/leaf.csr" -days 3650 \
        -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial \
        -extfile /dev/stdin -out "$d/leaf.crt" 2>/dev/null <<EOF
$san
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    rm -f "$d/leaf.csr" "$d/ca.srl"

    # chain.crt for tlsproxy's cert-chain and nginx's ssl_certificate;
    # leaf.pem is the single file haproxy's crt wants.
    cat "$d/leaf.crt" "$d/ca.crt" > "$d/chain.crt"
    cat "$d/chain.crt" "$d/leaf.key" > "$d/leaf.pem"
    # 644 so the tlsproxy image's uid 2001 can read them. tlsproxy warns about
    # that at startup on stderr and carries on.
    chmod 644 "$d/leaf.key" "$d/leaf.pem" "$d/ca.key"

    printf '%-6s leaf=%s issuer=%s\n' "$name" \
        "$(openssl x509 -in "$d/leaf.crt" -noout -subject | sed 's/.*CN *= *//')" \
        "$(openssl x509 -in "$d/leaf.crt" -noout -issuer  | sed 's/.*CN *= *//')"
}

gen ecdsa -newkey ec -pkeyopt ec_paramgen_curve:P-256
gen rsa   -newkey rsa:2048
