package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// openvpnFileSha256 — SHA-256 содержимого файла под каталогом конфига OpenVPN (для сравнения с панелью).
func (s *AgentServer) openvpnFileSha256(w http.ResponseWriter, r *http.Request) {
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
			Path string `json:"path"`
		}
		var req reqBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Path) == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}
		target, pathErr := resolvePathUnderConfigDir(s.ServerConfPath, req.Path)
		if pathErr != nil {
			http.Error(w, "path must be under OpenVPN config directory", http.StatusBadRequest)
			return
		}
		raw, err := os.ReadFile(target)
		if err != nil {
			if os.IsNotExist(err) {
				_ = json.NewEncoder(w).Encode(map[string]any{"exists": false, "sha256": ""})
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exists": true,
			"sha256": hex.EncodeToString(sum[:]),
		})
	})(w, r)
}
