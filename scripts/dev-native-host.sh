#!/usr/bin/env bash
# Install or remove the development native messaging host for the current
# user in Chrome, Chromium and Brave.
#
#   scripts/dev-native-host.sh install   # builds the debug host
#   scripts/dev-native-host.sh uninstall
set -euo pipefail

NAME=dev.postmoth.native_host
DEV_ID=nnbgdhodaoggiiakpcmnlkgalgkoecbk
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=${XDG_CONFIG_HOME:-$HOME/.config}
DIRS=(
  "$CONFIG/google-chrome/NativeMessagingHosts"
  "$CONFIG/chromium/NativeMessagingHosts"
  "$CONFIG/BraveSoftware/Brave-Browser/NativeMessagingHosts"
)

case "${1:-}" in
  install)
    cargo build --quiet -p postmoth-native-host --manifest-path "$ROOT/Cargo.toml"
    host="$ROOT/target/debug/postmoth-native-host"
    for d in "${DIRS[@]}"; do
      # Only for browsers that have a profile directory.
      [ -d "$(dirname "$d")" ] || continue
      mkdir -p "$d"
      sed -e "s|@HOST_PATH@|$host|" \
          -e "s|@ALLOWED_ORIGINS@|\"chrome-extension://$DEV_ID/\"|" \
          "$ROOT/packaging/native-messaging/$NAME.json.in" > "$d/$NAME.json"
      chmod 0644 "$d/$NAME.json"
      echo "installed $d/$NAME.json"
    done
    ;;
  uninstall)
    for d in "${DIRS[@]}"; do
      if [ -f "$d/$NAME.json" ]; then
        rm -f "$d/$NAME.json"
        echo "removed $d/$NAME.json"
      fi
    done
    ;;
  *)
    echo "usage: $0 install|uninstall" >&2
    exit 64
    ;;
esac
