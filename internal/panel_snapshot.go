package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"os/exec"
)

type panelSnapshotTunnelCtx struct {
	TunnelInterface string `json:"tunnelInterface"`
	VpnSubnet       string `json:"vpnSubnet"`
	VpnSubnetCidr   string `json:"vpnSubnetCidr"`
}

type panelSnapshotTunnelFw struct {
	DefaultPolicy string    `json:"defaultPolicy"`
	Rules         []fwRule  `json:"rules"`
	NatRules      []natRule `json:"natRules"`
}

type panelSnapshotUser struct {
	VpnUserID      *string  `json:"vpnUserId"`
	FirewallMode   string   `json:"firewallMode"`
	FirewallRules  []fwRule `json:"firewallRules"`
	FirewallNatRules []natRule `json:"firewallNatRules"`
	CcdText        string   `json:"ccdText"`
}

// PanelSnapshot — локальная копия данных панели на агенте.
type PanelSnapshot struct {
	SchemaVersion  int                           `json:"schemaVersion"`
	AgentNodeID    string                        `json:"agentNodeId"`
	NodeName       string                        `json:"nodeName"`
	Revision       string                        `json:"revision"`
	UpdatedAt      string                        `json:"updatedAt"`
	TunnelContext  panelSnapshotTunnelCtx        `json:"tunnelContext"`
	TunnelFirewall panelSnapshotTunnelFw       `json:"tunnelFirewall"`
	UsersByCn      map[string]panelSnapshotUser  `json:"usersByCn"`
}

func panelCacheDir(serverConfPath string) string {
	return filepath.Join(filepath.Dir(serverConfPath), "panel-cache")
}

// SnapshotJSONPath путь к файлу снимка рядом с каталогом server.conf.
func SnapshotJSONPath(serverConfPath string) string {
	return filepath.Join(panelCacheDir(serverConfPath), "snapshot.json")
}

// WritePanelSnapshotAtomic записывает snapshot.json атомарно.
func WritePanelSnapshotAtomic(serverConfPath string, raw []byte) error {
	d := panelCacheDir(serverConfPath)
	if err := os.MkdirAll(d, 0755); err != nil {
		return err
	}
	tmp := filepath.Join(d, ".snapshot.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, SnapshotJSONPath(serverConfPath))
}

// LoadPanelSnapshot читает снимок с диска (если нет файла — ошибка).
func LoadPanelSnapshot(serverConfPath string) (*PanelSnapshot, error) {
	b, err := os.ReadFile(SnapshotJSONPath(serverConfPath))
	if err != nil {
		return nil, err
	}
	var s PanelSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func normalizeVirtIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func buildSessionsFromSnapshot(snap *PanelSnapshot, clients []VPNClient) []fwSession {
	if snap == nil {
		return nil
	}
	var sessions []fwSession
	seen := map[string]bool{}
	for _, c := range clients {
		cn := strings.TrimSpace(c.CommonName)
		if cn == "" {
			continue
		}
		u, ok := snap.UsersByCn[cn]
		if !ok {
			continue
		}
		vip := normalizeVirtIP(c.VirtualIP)
		if vip == "" {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(u.FirewallMode))
		if mode == "" {
			mode = "merge"
		}
		if mode != "replace" && len(u.FirewallRules) == 0 && len(u.FirewallNatRules) == 0 {
			continue
		}
		key := cn + "|" + vip
		if seen[key] {
			continue
		}
		seen[key] = true
		sessions = append(sessions, fwSession{
			Mode:      mode,
			VirtualIP: vip,
			Rules:     u.FirewallRules,
			NatRules:  u.FirewallNatRules,
		})
	}
	return sessions
}

func deriveSessionNatRules(sessions []fwSession) []natRule {
	var out []natRule
	for _, s := range sessions {
		vip := strings.TrimSpace(s.VirtualIP)
		if vip == "" {
			continue
		}
		for _, r := range s.NatRules {
			nr := r
			if strings.TrimSpace(nr.Src) == "" {
				nr.Src = vip + "/32"
			}
			out = append(out, nr)
		}
	}
	return out
}

func (s *AgentServer) applyCCDFilesFromSnapshot(snap *PanelSnapshot) error {
	if s == nil || snap == nil || s.ServerConfPath == "" {
		return nil
	}
	dir := ReadClientConfigDirFromServerConf(s.ServerConfPath)
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(s.ServerConfPath), dir)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for cn, u := range snap.UsersByCn {
		cn = strings.TrimSpace(cn)
		if cn == "" {
			continue
		}
		path := filepath.Join(dir, cn)
		text := strings.TrimSpace(u.CcdText)
		if text == "" {
			_ = os.Remove(path)
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(text), 0600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

var panelFwMu sync.Mutex
var lastAppliedFirewallScriptHash string

func envPanelFirewallEnabled() bool {
	v := strings.TrimSpace(os.Getenv("AGENT_PANEL_FIREWALL_RUNTIME"))
	if v == "" || v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		return true
	}
	return false
}

// TryApplyFirewallFromSnapshot строит iptables-скрипт из локального снимка и живых клиентов, применяет при изменении.
func (s *AgentServer) TryApplyFirewallFromSnapshot(ctx context.Context) error {
	if s == nil || !envPanelFirewallEnabled() || s.ServerConfPath == "" || s.OpenVPN == nil {
		return nil
	}
	snap, err := LoadPanelSnapshot(s.ServerConfPath)
	if err != nil {
		return nil // нет снимка — не трогаем firewall
	}
	clients, err := s.OpenVPN.GetClients(ctx)
	if err != nil {
		return err
	}
	sessions := buildSessionsFromSnapshot(snap, clients)
	sessionNat := deriveSessionNatRules(sessions)
	mergedNat := append(append([]natRule{}, snap.TunnelFirewall.NatRules...), sessionNat...)
	p := iptablesRenderParams{
		NodeLabel:           snap.NodeName,
		TunnelInterface:   snap.TunnelContext.TunnelInterface,
		VpnSubnetCidr:       snap.TunnelContext.VpnSubnetCidr,
		TunnelDefaultPolicy: snap.TunnelFirewall.DefaultPolicy,
		TunnelRules:         snap.TunnelFirewall.Rules,
		NatRules:            mergedNat,
		Sessions:            sessions,
	}
	script := RenderFirewallRuntimeIptablesScript(p)
	sum := sha256.Sum256([]byte(script))
	hash := hex.EncodeToString(sum[:])

	panelFwMu.Lock()
	defer panelFwMu.Unlock()
	if hash == lastAppliedFirewallScriptHash {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-e", "-c", script)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("iptables apply: %w: %s", runErr, strings.TrimSpace(string(out)))
	}
	lastAppliedFirewallScriptHash = hash
	return nil
}

// ResetFirewallScriptHashAfterSnapshot сбрасывает кэш хеша (новый revision снимка).
func ResetFirewallScriptHashAfterSnapshot() {
	panelFwMu.Lock()
	lastAppliedFirewallScriptHash = ""
	panelFwMu.Unlock()
}
