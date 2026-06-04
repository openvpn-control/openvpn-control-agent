package internal

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func openvpnServiceUnitCandidates(preferred string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	preferred = strings.TrimSpace(preferred)
	// Сначала instance unit RHEL/Fedora (openvpn-server@server), затем опрос systemd, generic — в конце.
	if strings.Contains(preferred, "@") {
		add(preferred)
	}
	add("openvpn-server@server.service")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, u := range discoverOpenVPNInstanceUnits(ctx, "openvpn-server@") {
		add(u)
	}
	add("openvpn@server.service")
	for _, u := range discoverOpenVPNInstanceUnits(ctx, "openvpn@") {
		add(u)
	}
	if preferred != "" && !strings.Contains(preferred, "@") {
		add(preferred)
	}
	add("openvpn.service")
	return out
}

// discoverOpenVPNInstanceUnits returns loaded openvpn-server@* / openvpn@* units (systemctl list-units).
func discoverOpenVPNInstanceUnits(ctx context.Context, prefix string) []string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || !strings.HasSuffix(prefix, "@") {
		return nil
	}
	pattern := prefix + "*.service"
	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", pattern)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var units []string
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		unit := strings.TrimSpace(fields[0])
		if !strings.HasPrefix(unit, prefix) || !strings.HasSuffix(unit, ".service") {
			continue
		}
		if seen[unit] {
			continue
		}
		seen[unit] = true
		units = append(units, unit)
	}
	return units
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
