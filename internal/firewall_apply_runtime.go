package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// teardownPanelIptables снимает цепочки панели (iptables-save), в т.ч. OVPN_*.
func teardownPanelIptables(ifName, cidr string) []byte {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		ifName = "tun0"
	}
	cidr = strings.TrimSpace(cidr)
	sh := `
set +e
# все переходы из FORWARD в цепочки панели (в т.ч. /32 → OVPN_* и без списка VIP)
while iptables -t filter -S FORWARD 2>/dev/null | grep -qE -- '-j OVPN_| -j OPENVPN_PANEL_'; do
  SPEC=$(iptables -t filter -S FORWARD 2>/dev/null | grep -E -- '-j OVPN_| -j OPENVPN_PANEL_' | head -n1 | sed 's/^-A FORWARD //')
  [ -z "$SPEC" ] && break
  iptables -t filter -D FORWARD $SPEC 2>/dev/null || break
done
for c in $(iptables -t filter -L 2>/dev/null | sed -n 's/^Chain \(OVPN_[^ ]*\) .*/\1/p'); do
  iptables -t filter -F "$c" 2>/dev/null
  iptables -t filter -X "$c" 2>/dev/null
done
iptables -t filter -F OPENVPN_PANEL_FWD 2>/dev/null
iptables -t filter -X OPENVPN_PANEL_FWD 2>/dev/null
iptables -t filter -F OPENVPN_PANEL_BASE 2>/dev/null
iptables -t filter -X OPENVPN_PANEL_BASE 2>/dev/null
while [ -n "$SN" ] && iptables -t nat -C POSTROUTING -s "$SN" -j OPENVPN_PANEL_NAT 2>/dev/null; do
  iptables -t nat -D POSTROUTING -s "$SN" -j OPENVPN_PANEL_NAT
done
while iptables -t nat -C POSTROUTING -j OPENVPN_PANEL_NAT 2>/dev/null; do
  iptables -t nat -D POSTROUTING -j OPENVPN_PANEL_NAT
done
iptables -t nat -F OPENVPN_PANEL_NAT 2>/dev/null
iptables -t nat -X OPENVPN_PANEL_NAT 2>/dev/null
# старые nft-таблицы панели (если остались после обновления)
nft delete table inet ovpn_panel_fw 2>/dev/null
nft delete table ip ovpn_panel_nat 2>/dev/null
set -e
true
`
	cmd := exec.Command("sh", "-c", sh)
	out, _ := cmd.CombinedOutput()
	return out
}

// firewallApplyRuntime выполняет bash-скрипт с iptables (stdin) или только снимает правила при пустом script.
func (s *AgentServer) firewallApplyRuntime(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Script            string `json:"script"`
			TunnelInterface   string `json:"tunnelInterface"`
			VpnSubnetCidr     string `json:"vpnSubnetCidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		script := strings.TrimSpace(body.Script)
		if script == "" {
			out := teardownPanelIptables(body.TunnelInterface, body.VpnSubnetCidr)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"message": "runtime firewall cleared (iptables)",
				"output":  string(out),
			})
			return
		}

		cmd := exec.Command("sh", "-e", "-c", script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     false,
				"error":  fmt.Sprintf("%v", err),
				"output": string(out),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"output": string(out),
		})
	})(w, r)
}
