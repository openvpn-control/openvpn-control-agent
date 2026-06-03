#!/bin/sh
set -e

case "${1:-}" in
  remove|upgrade|0|1)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop openvpn-control-agent.service || true
    fi
    ;;
esac

exit 0
