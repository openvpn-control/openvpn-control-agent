package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

func runShellCommand(ctx context.Context, cmd string) (string, error) {
	command := strings.TrimSpace(cmd)
	if command == "" {
		return "", errors.New("empty command")
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output == "" {
			output = err.Error()
		}
		return output, err
	}
	return output, nil
}

func (s *AgentServer) serviceCommand(action string) string {
	unit := detectOpenVPNServiceUnit(s.ServiceUnit)
	switch action {
	case "start":
		if strings.TrimSpace(s.ServiceStartCmd) != "" {
			return s.ServiceStartCmd
		}
		return fmt.Sprintf("systemctl start %s", unit)
	case "stop":
		if strings.TrimSpace(s.ServiceStopCmd) != "" {
			return s.ServiceStopCmd
		}
		return fmt.Sprintf("systemctl stop %s", unit)
	case "restart":
		if strings.TrimSpace(s.ServiceRestartCmd) != "" {
			return s.ServiceRestartCmd
		}
		return fmt.Sprintf("systemctl restart %s", unit)
	default:
		return ""
	}
}

func (s *AgentServer) openvpnService(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		action := strings.ToLower(strings.TrimSpace(body.Action))
		command := s.serviceCommand(action)
		if command == "" {
			http.Error(w, "unsupported action; use start|stop|restart", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		output, err := runShellCommand(ctx, command)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  fmt.Sprintf("failed to %s OpenVPN service", action),
				"action": action,
				"output": output,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"action": action,
			"output": output,
		})
	})(w, r)
}
