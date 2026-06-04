package internal

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// managementAddrsToProbe returns candidate management TCP addresses (env default + server.conf).
func managementAddrsToProbe(confPath, defaultAddr string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}
	add(defaultAddr)
	for _, raw := range readManagementDirectivesFromConfig(confPath) {
		add(parseManagementListenAddr(raw))
	}
	if confPath != "" {
		if settings, err := ReadServerSettings(confPath); err == nil {
			if raw, ok := settings["management"].(string); ok {
				add(parseManagementListenAddr(raw))
			}
		}
	}
	return out
}

func readManagementDirectivesFromConfig(confPath string) []string {
	confPath = strings.TrimSpace(confPath)
	if confPath == "" {
		return nil
	}
	f, err := os.Open(confPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := stripInlineComment(sc.Text())
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "management ") {
			lines = append(lines, strings.TrimSpace(line[len("management"):]))
		}
	}
	return lines
}

// resolveWorkingManagement dials management until GetClients succeeds.
func (s *AgentServer) resolveWorkingManagement(ctx context.Context) (*OpenVPNManagement, string, error) {
	confPath := EffectiveServerConfigPath(s.ServerConfPath, s.ServiceUnit)
	defaultAddr := ""
	timeout := 4 * time.Second
	if s.OpenVPN != nil {
		defaultAddr = s.OpenVPN.Addr
		if s.OpenVPN.Timeout > 0 {
			timeout = s.OpenVPN.Timeout
		}
	}
	addrs := managementAddrsToProbe(confPath, defaultAddr)
	if len(addrs) == 0 {
		return nil, "", fmt.Errorf("management address is not configured (set management in server.conf or OPENVPN_MGMT_ADDR)")
	}
	var lastErr error
	for _, addr := range addrs {
		m := &OpenVPNManagement{Addr: addr, Timeout: timeout}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		_, err := m.GetClients(probeCtx)
		cancel()
		if err == nil {
			return m, addr, nil
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("management unavailable (tried %s): %v", strings.Join(addrs, ", "), lastErr)
}
