#!/usr/bin/env bash
# Update this server's i6.shark to origin/main, keeping the settings each
# server sets for itself in src/consts.go, then rebuild, restart and check it.
# Anything failing puts the previous code and binary back.
# Run by .github/workflows/deploy.yml as: update.sh <checkout dir> <systemd unit>
# Optional env: I6_SHARED_SECRET (written to /etc/i6shark.env for the service).
set -euo pipefail
DIR=$1
UNIT=$2
cd "$DIR"

GO=$(command -v go || true)
[ -n "$GO" ] || GO=/usr/local/go/bin/go
[ -x "$GO" ] || { echo "Go toolchain not found"; exit 1; }
BIN=$(systemctl show "$UNIT" -p ExecStart --value | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
[ -n "$BIN" ] || BIN="$DIR/i6shark"

OLD=$(git rev-parse HEAD)
SERVER_CONSTS=$(mktemp)
cp src/consts.go "$SERVER_CONSTS"
cp "$BIN" "$BIN.prev"
rollback() {
  echo "check failed: rolling back to $(git rev-parse --short "$OLD")"
  git reset -q --hard "$OLD"
  cp "$SERVER_CONSTS" src/consts.go
  cp "$BIN.prev" "$BIN"
  rm -f "/etc/systemd/system/$UNIT.d/secret.conf"
  systemctl daemon-reload
  systemctl restart "$UNIT"
}

git fetch -q origin main
git reset -q --hard origin/main

# Carry over this server's own values; everything else comes from the repo.
for name in SharedSecret IPv6Prefix IPv6Subnet Interface ListenPort ListenHost Debug; do
  line=$(grep -E "^[[:space:]]*$name[[:space:]]*=" "$SERVER_CONSTS" | head -1 || true)
  [ -n "$line" ] || continue
  value=$(printf '%s' "$line" | sed -E "s/^[[:space:]]*$name[[:space:]]*=[[:space:]]*//; s/[[:space:]]*\/\/.*$//")
  awk -v n="$name" -v v="$value" '
    !done && $0 ~ ("^[[:space:]]*" n "[[:space:]]*=") {
      c = ""; i = index($0, "//"); if (i > 0) c = substr($0, i)
      match($0, "^[[:space:]]*" n "[[:space:]]*=[[:space:]]*")
      $0 = substr($0, 1, RLENGTH) v (c != "" ? " " c : ""); done = 1
    }
    { print }' src/consts.go > src/consts.go.tmp
  mv src/consts.go.tmp src/consts.go
done

if [ -n "${I6_SHARED_SECRET:-}" ]; then
  install -m 600 /dev/null /etc/i6shark.env
  printf 'I6_SHARED_SECRET=%s\n' "$I6_SHARED_SECRET" > /etc/i6shark.env
  mkdir -p "/etc/systemd/system/$UNIT.d"
  printf '[Service]\nEnvironmentFile=/etc/i6shark.env\n' > "/etc/systemd/system/$UNIT.d/secret.conf"
  systemctl daemon-reload
fi

if ! "$GO" build -o "$BIN.new" ./src; then rollback; exit 1; fi
mv "$BIN.new" "$BIN"
systemctl restart "$UNIT"
sleep 3

# An authorised fetch must work and an internal address must be refused.
SECRET=${I6_SHARED_SECRET:-$(sed -nE 's/^[[:space:]]*SharedSecret[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' src/consts.go | head -1)}
PORT=$(sed -nE 's/^[[:space:]]*ListenPort[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' src/consts.go | head -1)
UA="i6shark-deploy-check"
TOKEN=$(printf '%s' "$SECRET" | openssl dgst -sha256 -hmac "$UA" | awk '{print $NF}')
fetch=$(curl -s -o /dev/null -w '%{http_code}' -m 20 -A "$UA" -H "API-Token: $TOKEN" "http://127.0.0.1:$PORT/?url=https://www.cloudflare.com/cdn-cgi/trace" || true)
internal=$(curl -s -o /dev/null -w '%{http_code}' -m 20 -A "$UA" -H "API-Token: $TOKEN" "http://127.0.0.1:$PORT/?url=http://127.0.0.1:22/" || true)
echo "check: authorised fetch=$fetch, internal address=$internal (want 200, 403)"
if [ "$fetch" != 200 ] || [ "$internal" != 403 ]; then rollback; exit 1; fi
rm -f "$BIN.prev" "$SERVER_CONSTS"
echo "deployed $(git rev-parse --short HEAD)"
