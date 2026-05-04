package internal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (s *AgentServer) panelSnapshot(w http.ResponseWriter, r *http.Request) {
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
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var snap PanelSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			http.Error(w, "invalid json snapshot", http.StatusBadRequest)
			return
		}
		if err := WritePanelSnapshotAtomic(s.ServerConfPath, raw); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ResetFirewallScriptHashAfterSnapshot()
		if err := s.applyCCDFilesFromSnapshot(&snap); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := s.TryApplyFirewallFromSnapshot(ctx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"revision": snap.Revision,
			"message":  "panel snapshot stored, ccd and firewall reconciled",
		})
	})(w, r)
}

// StartSnapshotFirewallLoop периодически применяет firewall из локального снимка (панель недоступна — правила всё равно догоняют сессии).
func StartSnapshotFirewallLoop(s *AgentServer, every time.Duration) {
	if s == nil || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for range t.C {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			_ = s.TryApplyFirewallFromSnapshot(ctx)
			cancel()
		}
	}()
}
