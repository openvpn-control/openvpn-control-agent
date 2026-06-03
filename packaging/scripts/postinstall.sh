#!/bin/sh
set -e

case "${1:-}" in
  configure|1|2)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl enable openvpn-control-agent.service || true
      systemctl try-restart openvpn-control-agent.service \
        || systemctl restart openvpn-control-agent.service \
        || systemctl start openvpn-control-agent.service \
        || true
    fi
    ;;
esac

exit 0
