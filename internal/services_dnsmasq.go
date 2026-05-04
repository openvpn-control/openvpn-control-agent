package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type systemServiceRow struct {
	Unit            string  `json:"unit"`
	LoadState       string  `json:"loadState"`
	ActiveState     string  `json:"activeState"`
	SubState        string  `json:"subState"`
	Description     string  `json:"description"`
	MainPID         *int64  `json:"mainPid,omitempty"`
	UptimeSeconds   *int64  `json:"uptimeSeconds,omitempty"`
}

func parseSystemctlListUnits(raw string) []systemServiceRow {
	out := []systemServiceRow{}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) < 5 {
			continue
		}
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		out = append(out, systemServiceRow{
			Unit:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
			Description: desc,
		})
	}
	return out
}

func parseSystemctlShowProps(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		out[k] = v
	}
	return out
}

func parseSystemdActiveEnterTimestamp(val string) (time.Time, bool) {
	val = strings.TrimSpace(val)
	if val == "" || val == "n/a" {
		return time.Time{}, false
	}
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 UTC",
		"Mon 2006-01-02 15:04:05 CET",
		"Mon 2006-01-02 15:04:05 EET",
		"Mon 2006-01-02 15:04:05 MSK",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, val, time.Local); err == nil {
			return t, true
		}
		if t, err := time.Parse(layout, val); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Тот же отбор, что у панели в списке «Службы» — только для них тянем PID/аптайм (иначе list-units даёт сотни unit’ов).
func rowMatchesPanelServiceInterest(row systemServiceRow) bool {
	load := strings.TrimSpace(strings.ToLower(row.LoadState))
	if load == "not-found" {
		return false
	}
	u := strings.ToLower(row.Unit + " " + row.Description)
	return strings.Contains(u, "openvpn") ||
		strings.Contains(u, "dnsmasq") ||
		strings.Contains(u, "nftables") ||
		strings.Contains(u, "iptables") ||
		strings.Contains(u, "firewalld") ||
		strings.Contains(u, "ufw") ||
		strings.Contains(u, "openvpn-control-agent")
}

func enrichSystemServiceRow(ctx context.Context, row *systemServiceRow) {
	if row == nil || !isAllowedSystemdServiceUnit(row.Unit) {
		return
	}
	showCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(showCtx, "systemctl", "show", row.Unit, "-p", "MainPID", "-p", "ActiveEnterTimestamp", "--no-pager")
	rawOut, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	props := parseSystemctlShowProps(string(rawOut))
	pidStr := strings.TrimSpace(props["MainPID"])
	if pidStr != "" && pidStr != "[not set]" {
		if n, err := strconv.ParseInt(pidStr, 10, 64); err == nil && n >= 0 {
			pid := n
			row.MainPID = &pid
		}
	}
	ast := strings.ToLower(strings.TrimSpace(row.ActiveState))
	running := ast == "active" || ast == "reloading"
	if !running {
		return
	}
	tsStr := strings.TrimSpace(props["ActiveEnterTimestamp"])
	if ts, ok := parseSystemdActiveEnterTimestamp(tsStr); ok {
		sec := int64(time.Since(ts).Round(time.Second).Seconds())
		if sec < 0 {
			sec = 0
		}
		row.UptimeSeconds = &sec
	}
}

func (s *AgentServer) systemServices(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := runShellCommand(ctx, "systemctl list-units --type=service --all --no-pager --no-legend")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  "failed to list services",
				"output": out,
			})
			return
		}
		rows := parseSystemctlListUnits(out)
		for i := range rows {
			if rowMatchesPanelServiceInterest(rows[i]) {
				enrichSystemServiceRow(ctx, &rows[i])
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"services": rows,
		})
	})(w, r)
}

func isAllowedSystemdServiceUnit(unit string) bool {
	u := strings.TrimSpace(unit)
	if u == "" || len(u) > 256 {
		return false
	}
	if !strings.HasSuffix(u, ".service") {
		return false
	}
	base := strings.TrimSuffix(u, ".service")
	if base == "" {
		return false
	}
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '@' {
			continue
		}
		return false
	}
	return true
}

func (s *AgentServer) agentServiceUnitName() string {
	u := strings.TrimSpace(strings.ToLower(s.AgentServiceUnit))
	if u == "" {
		return "openvpn-control-agent.service"
	}
	if !strings.HasSuffix(u, ".service") {
		return "openvpn-control-agent.service"
	}
	if !isAllowedSystemdServiceUnit(u) {
		return "openvpn-control-agent.service"
	}
	return u
}

func runSystemctlUnitActionDelayed(unit, action string) {
	time.Sleep(450 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, _ = exec.CommandContext(ctx, "systemctl", action, unit).CombinedOutput()
}

func (s *AgentServer) systemServiceUnitAction(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Unit   string `json:"unit"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		unit := strings.TrimSpace(body.Unit)
		action := strings.ToLower(strings.TrimSpace(body.Action))
		if !isAllowedSystemdServiceUnit(unit) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "недопустимое имя unit"})
			return
		}
		if action != "start" && action != "stop" && action != "restart" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "action: start|stop|restart"})
			return
		}
		ownUnit := strings.TrimSpace(strings.ToLower(s.agentServiceUnitName()))
		unitKey := strings.TrimSpace(strings.ToLower(unit))
		if unitKey == ownUnit && (action == "stop" || action == "restart") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"action": action,
				"unit":   unit,
				"output": "Команда принята. Служба агента будет перезапущена; HTTP-соединение может оборваться — это нормально.",
				"async":  true,
			}); err != nil {
				return
			}
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			go runSystemctlUnitActionDelayed(unit, action)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "systemctl", action, unit)
		rawOut, err := cmd.CombinedOutput()
		out := strings.TrimSpace(string(rawOut))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  fmt.Sprintf("systemctl %s: ошибка", action),
				"output": out,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"action": action,
			"unit":   unit,
			"output": out,
		})
	})(w, r)
}

func readDnsmasqConfig(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func dnsmasqUnitState(unit string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := runShellCommand(ctx, fmt.Sprintf("systemctl show %s --no-pager --property=LoadState,ActiveState,SubState", unit))
	if err != nil {
		return map[string]any{
			"unit":        unit,
			"loadState":   "unknown",
			"activeState": "unknown",
			"subState":    "unknown",
			"error":       strings.TrimSpace(out),
		}
	}
	state := map[string]any{
		"unit":        unit,
		"loadState":   "unknown",
		"activeState": "unknown",
		"subState":    "unknown",
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "LoadState=") {
			state["loadState"] = strings.TrimPrefix(t, "LoadState=")
		} else if strings.HasPrefix(t, "ActiveState=") {
			state["activeState"] = strings.TrimPrefix(t, "ActiveState=")
		} else if strings.HasPrefix(t, "SubState=") {
			state["subState"] = strings.TrimPrefix(t, "SubState=")
		}
	}
	return state
}

func (s *AgentServer) dnsmasq(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		confPath := strings.TrimSpace(s.DNSMasqConfPath)
		if confPath == "" {
			confPath = "/etc/dnsmasq.d/openvpn-control.conf"
		}
		unit := strings.TrimSpace(s.DNSMasqServiceUnit)
		if unit == "" {
			unit = "dnsmasq.service"
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":    dnsmasqUnitState(unit),
				"configPath": confPath,
				"config":     readDnsmasqConfig(confPath),
			})
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Action string `json:"action"`
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		action := strings.ToLower(strings.TrimSpace(body.Action))
		if action == "" {
			action = "save"
		}
		if action == "save" || action == "apply" {
			if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			content := body.Config
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			if err := os.WriteFile(confPath, []byte(content), 0o644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if action == "start" || action == "stop" || action == "restart" || action == "apply" {
			cmdAction := action
			if action == "apply" {
				cmdAction = "restart"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := fmt.Sprintf("systemctl %s %s", cmdAction, unit)
			out, err := runShellCommand(ctx, cmd)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  fmt.Sprintf("failed to %s dnsmasq", cmdAction),
					"output": out,
				})
				return
			}
			_ = out
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"action":     action,
			"service":    dnsmasqUnitState(unit),
			"configPath": confPath,
			"config":     readDnsmasqConfig(confPath),
		})
	})(w, r)
}
