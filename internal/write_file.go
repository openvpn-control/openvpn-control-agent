package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func resolvePathUnderConfigDir(confPath, requested string) (string, error) {
	confDir := filepath.Clean(filepath.Dir(confPath))
	raw := strings.TrimSpace(requested)
	if raw == "" {
		return "", fmt.Errorf("path required")
	}
	if filepath.IsAbs(raw) {
		// Абсолютные пути в server.conf разрешаем как есть (часто ca/cert/key лежат не в каталоге server.conf).
		return filepath.Clean(raw), nil
	}
	target := filepath.Clean(filepath.Join(confDir, raw))
	rel, errRel := filepath.Rel(confDir, target)
	if errRel != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path must be under OpenVPN config directory")
	}
	return target, nil
}

// writeOpenvpnFile — атомарная запись файла рядом с конфигом OpenVPN (для crl, ca, ключей и т.д.).
func (s *AgentServer) writeOpenvpnFile(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.ServerConfPath == "" {
			http.Error(w, "OPENVPN_SERVER_CONF is not set", http.StatusServiceUnavailable)
			return
		}
		type reqBody struct {
			Path          string `json:"path"`
			ContentBase64 string `json:"contentBase64"`
		}
		var req reqBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Path) == "" || req.ContentBase64 == "" {
			http.Error(w, "path and contentBase64 required", http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			http.Error(w, "invalid base64", http.StatusBadRequest)
			return
		}
		target, pathErr := resolvePathUnderConfigDir(s.ServerConfPath, req.Path)
		if pathErr != nil {
			http.Error(w, "path must be under OpenVPN config directory", http.StatusBadRequest)
			return
		}
		dir := filepath.Dir(target)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmp := target + ".tmp-ovpn-control"
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmp, target); err != nil {
			_ = os.Remove(tmp)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "path": target, "bytes": len(raw)})
	})(w, r)
}
