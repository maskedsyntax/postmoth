#!/usr/bin/env bash
# Local GreenMail test server with a throwaway CA, for integration and
# end-to-end tests. Plain SMTP (for injecting test mail) + IMAPS.
#
#   scripts/greenmail.sh start    # generate certs, start container
#   scripts/greenmail.sh test     # start + run the ignored IMAP tests
#   scripts/greenmail.sh stop
#   scripts/greenmail.sh env      # print the POSTMOTH_TEST_* variables
#
# The CA lives in target/greenmail/ and is trusted only by Postmoth when
# passed explicitly (--extra-ca / POSTMOTH_TEST_IMAP_CA).
set -euo pipefail

IMAGE=greenmail/standalone:2.1.14
NAME=postmoth-greenmail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR="$ROOT/target/greenmail"
SMTP_PORT=${GREENMAIL_SMTP_PORT:-3025}
IMAPS_PORT=${GREENMAIL_IMAPS_PORT:-3993}
USER_LOGIN=me@example.org
USER_PASS=greenmail-test-password
STOREPASS=changeit

certs() {
  [ -f "$DIR/server.p12" ] && return
  mkdir -p "$DIR"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Postmoth Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$DIR/ca.key" -out "$DIR/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$DIR/server.key" -out "$DIR/server.csr" 2>/dev/null
  printf '%s\n' "subjectAltName=DNS:localhost,IP:127.0.0.1" "extendedKeyUsage=serverAuth" \
    "basicConstraints=critical,CA:FALSE" > "$DIR/server.ext"
  openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 30 -extfile "$DIR/server.ext" -out "$DIR/server.pem" 2>/dev/null
  openssl pkcs12 -export -in "$DIR/server.pem" -inkey "$DIR/server.key" -certfile "$DIR/ca.pem" \
    -name greenmail -passout "pass:$STOREPASS" -out "$DIR/server.p12"
  chmod 0644 "$DIR/server.p12"   # read by the container user
}

start() {
  certs
  if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then return; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" \
    -p "127.0.0.1:$SMTP_PORT:3025" -p "127.0.0.1:$IMAPS_PORT:3993" \
    -v "$DIR:/certs:ro" \
    -e GREENMAIL_OPTS="-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imaps \
      -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.auth.disabled=false \
      -Dgreenmail.users=$USER_LOGIN:$USER_PASS \
      -Dgreenmail.users.login=email \
      -Dgreenmail.tls.keystore.file=/certs/server.p12 \
      -Dgreenmail.tls.keystore.password=$STOREPASS" \
    "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$SMTP_PORT") 2>/dev/null; then
      sleep 1; echo "greenmail ready (smtp :$SMTP_PORT, imaps :$IMAPS_PORT)"; return
    fi
    sleep 0.5
  done
  docker logs "$NAME" >&2; echo "greenmail did not start" >&2; exit 1
}

print_env() {
  cat <<VARS
export POSTMOTH_TEST_IMAP_HOST=localhost
export POSTMOTH_TEST_IMAP_PORT=$IMAPS_PORT
export POSTMOTH_TEST_IMAP_USER=$USER_LOGIN
export POSTMOTH_TEST_IMAP_PASS=$USER_PASS
export POSTMOTH_TEST_IMAP_CA=$DIR/ca.pem
export POSTMOTH_TEST_SMTP_PORT=$SMTP_PORT
VARS
}

case "${1:-}" in
  start) start ;;
  stop) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "stopped" ;;
  env) print_env ;;
  test)
    start
    eval "$(print_env)"
    cargo test -p postmoth-mail --test greenmail -- --ignored
    ;;
  *) echo "usage: $0 start|stop|env|test" >&2; exit 64 ;;
esac
