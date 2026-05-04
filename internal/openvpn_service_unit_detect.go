package internal

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func openvpnServiceUnitCandidates(preferred string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(preferred)
	add("openvpn.service")
	add("openvpn-server@server.service")
	add("openvpn@server.service")
	return out
}

func serviceUnitState(ctx context.Context, unit string) (loadState, activeState string, ok bool) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit, "--no-pager", "--property=LoadState,ActiveState")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LoadState=") {
			loadState = strings.TrimPrefix(line, "LoadState=")
		}
		if strings.HasPrefix(line, "ActiveState=") {
			activeState = strings.TrimPrefix(line, "ActiveState=")
		}
	}
	return loadState, activeState, loadState != ""
}

func detectOpenVPNServiceUnit(preferred string) string {
	candidates := openvpnServiceUnitCandidates(preferred)
	best := ""
	for _, unit := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		loadState, activeState, ok := serviceUnitState(ctx, unit)
		cancel()
		if !ok || loadState == "" || loadState == "not-found" {
			continue
		}
		// prefer currently active unit
		if activeState == "active" || activeState == "activating" {
			return unit
		}
		if best == "" {
			best = unit
		}
	}
	if best != "" {
		return best
	}
	if strings.TrimSpace(preferred) != "" {
		return strings.TrimSpace(preferred)
	}
	return "openvpn.service"
}
