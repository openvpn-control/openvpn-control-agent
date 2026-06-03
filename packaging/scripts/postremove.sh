#!/bin/sh
set -e

case "${1:-}" in
  remove|purge|0)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable openvpn-control-agent.service || true
      systemctl daemon-reload || true
    fi
    ;;
esac

exit 0
