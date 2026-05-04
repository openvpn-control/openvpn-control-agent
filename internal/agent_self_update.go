package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func tailJournalForUnit(ctx context.Context, unit string, lines int) string {
	if lines < 10 {
		lines = 10
	}
	if lines > 400 {
		lines = 400
	}
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager", "--no-hostname")
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			return fmt.Sprintf("journalctl: %v", err)
		}
		return s + "\n(journalctl: " + err.Error() + ")"
	}
	return s
}

func normalizeHex(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "sha256:")))
}

func (s *AgentServer) agentUpdate(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			FileName      string `json:"fileName"`
			BinaryBase64  string `json:"binaryBase64"`
			ChecksumSha256 string `json:"checksumSha256"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.BinaryBase64) == "" {
			http.Error(w, "binaryBase64 required", http.StatusBadRequest)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(body.BinaryBase64)
		if err != nil {
			http.Error(w, "binaryBase64 decode failed", http.StatusBadRequest)
			return
		}

		sum := sha256.Sum256(payload)
		sumHex := hex.EncodeToString(sum[:])
		if expected := normalizeHex(body.ChecksumSha256); expected != "" && expected != sumHex {
			http.Error(w, "checksum mismatch", http.StatusBadRequest)
			return
		}

		exePath, err := os.Executable()
		if err != nil {
			http.Error(w, "resolve executable path failed", http.StatusInternalServerError)
			return
		}
		exePath, _ = filepath.EvalSymlinks(exePath)
		if strings.TrimSpace(exePath) == "" {
			http.Error(w, "empty executable path", http.StatusInternalServerError)
			return
		}
		dir := filepath.Dir(exePath)
		tmpPath := filepath.Join(dir, ".openvpn-control-agent.update.tmp")
		backupPath := exePath + ".bak"

		if err := os.WriteFile(tmpPath, payload, 0o755); err != nil {
			http.Error(w, fmt.Sprintf("write temp binary failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(exePath, backupPath); err != nil {
			_ = os.Remove(tmpPath)
			http.Error(w, fmt.Sprintf("backup current binary failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, exePath); err != nil {
			_ = os.Rename(backupPath, exePath)
			_ = os.Remove(tmpPath)
			http.Error(w, fmt.Sprintf("install new binary failed: %v", err), http.StatusInternalServerError)
			return
		}
		_ = os.Chmod(exePath, 0o755)

		unit := strings.TrimSpace(s.AgentServiceUnit)
		if unit == "" {
			unit = "openvpn-control-agent.service"
		}
		if !isAllowedSystemdServiceUnit(unit) {
			unit = "openvpn-control-agent.service"
		}
		jCtx, jCancel := context.WithTimeout(context.Background(), 12*time.Second)
		journalTail := tailJournalForUnit(jCtx, unit, 120)
		jCancel()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"checksum":    sumHex,
			"message":     "Agent binary updated. Restart scheduled.",
			"journalTail": journalTail,
		})

		go s.restartSelfAfterUpdate()
	})(w, r)
}

func (s *AgentServer) restartSelfAfterUpdate() {
	time.Sleep(1200 * time.Millisecond)

	cmdText := strings.TrimSpace(s.AgentRestartCmd)
	if cmdText == "" {
		unit := strings.TrimSpace(s.AgentServiceUnit)
		if unit == "" {
			unit = "openvpn-control-agent.service"
		}
		cmdText = fmt.Sprintf("systemctl restart %s", unit)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdText)
	_ = cmd.Start()
	_ = cmd.Process.Release()
}
