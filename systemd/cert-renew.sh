#!/bin/bash
# ACME DNS-01 renewal for dns.example.com; atomic publish into /var/lib/private-doh-tls
# lego 5.4.1: "run" = get or renew; --renew-days 30 = renew when <30d left (no-op otherwise)
set -euo pipefail
DOM=dns.example.com
ACME=/var/lib/private-doh-acme
TLS=/var/lib/private-doh-tls
LEGO=/opt/private-doh/bin/lego
mkdir -p "$ACME"

# ACME account email: injected via EnvironmentFile, absent = fail closed
if [ -z "${ACME_EMAIL:-}" ]; then
  echo "ACME_EMAIL not set (check /etc/private-doh/acme.env)" >&2
  exit 1
fi

CRT="$ACME/certificates/${DOM}.crt"
KEY="$ACME/certificates/${DOM}.key"

"$LEGO" run --path "$ACME" \
  -d "$DOM" -m "$ACME_EMAIL" -a --dns cloudflare --renew-days 30 || exit 1

# verify key/cert pair before publishing
[ -s "$CRT" ] && [ -s "$KEY" ] || { echo "missing cert files"; exit 1; }
CERT_PUB=$(openssl x509 -in "$CRT" -noout -pubkey | openssl sha256)
KEY_PUB=$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl sha256)
[ "$CERT_PUB" = "$KEY_PUB" ] || { echo "key mismatch"; exit 1; }

# publish atomically only if content changed
TS=$(date -u +%Y%m%dT%H%M%SZ)
NEW_HASH=$(cat "$CRT" "$KEY" | sha256sum | cut -d' ' -f1)
CUR_TARGET=$(readlink "$TLS/current" 2>/dev/null || echo none)
CUR_HASH=""
if [ "$CUR_TARGET" != "none" ] && [ -f "$TLS/$CUR_TARGET/fullchain.pem" ]; then
  CUR_HASH=$(cat "$TLS/$CUR_TARGET/fullchain.pem" "$TLS/$CUR_TARGET/privkey.pem" | sha256sum | cut -d' ' -f1)
fi
if [ "$NEW_HASH" = "$CUR_HASH" ]; then
  echo "certificate unchanged; nothing to publish"
  exit 0
fi

DEST="$TLS/versions/$TS"
mkdir -p "$DEST"
cat "$CRT" > "$DEST/fullchain.pem"
cat "$KEY" > "$DEST/privkey.pem"
chown private-doh-acme:private-doh "$DEST/fullchain.pem" "$DEST/privkey.pem"
chmod 644 "$DEST/fullchain.pem"; chmod 640 "$DEST/privkey.pem"; chmod 755 "$DEST"
ln -sfn "versions/$TS" "$TLS/current.tmp" && mv -T "$TLS/current.tmp" "$TLS/current"
echo "published $TS"
