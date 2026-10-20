#!/usr/bin/env bash
# Starts a throwaway sshd for the kereru integration tests.
#
#   dev/sshd.sh            # start on 127.0.0.1:2222
#   dev/sshd.sh stop       # stop it
#
# Then run the tests with:
#   KERERU_TEST_SSH=127.0.0.1:2222 \
#   KERERU_TEST_AUTHORIZED_KEYS="$DIR/authorized_keys" \
#     cargo test -p kereru --test connect
#
# The tests install their own key in authorized_keys; the server only needs to
# trust that file.
set -euo pipefail

DIR="${DIR:-/tmp/pigeons-web-sshd}"
PORT="${PORT:-2222}"

if [ "${1:-start}" = "stop" ]; then
  [ -f "$DIR/sshd.pid" ] && kill "$(cat "$DIR/sshd.pid")" 2>/dev/null || true
  exit 0
fi

mkdir -p "$DIR"
[ -f "$DIR/host_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$DIR/host_ed25519"
: > "$DIR/authorized_keys"

cat > "$DIR/sshd_config" <<CONFIG
Port $PORT
ListenAddress 127.0.0.1
HostKey $DIR/host_ed25519
AuthorizedKeysFile $DIR/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile $DIR/sshd.pid
LogLevel DEBUG1
CONFIG

sshd -f "$DIR/sshd_config" -E "$DIR/sshd.log"
sleep 1
echo "sshd on 127.0.0.1:$PORT"
echo "  authorized_keys: $DIR/authorized_keys"
echo "  log:             $DIR/sshd.log"
