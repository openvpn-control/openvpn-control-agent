package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type AgentServer struct {
	Token          string
	OpenVPN        *OpenVPNManagement
	System         *SystemMetricsCollector
	ServerConfPath string
	ServerLogPath  string
	OpenVPNBin     string
	ServiceUnit    string
	ReloadCmd      string
	AgentServiceUnit  string
	AgentRestartCmd   string
	ServiceStartCmd   string
	ServiceStopCmd    string
	ServiceRestartCmd string
	DNSMasqConfPath   string
	DNSMasqServiceUnit string
}

func (s *AgentServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/clients", s.clients)
	mux.HandleFunc("/clients/disconnect", s.disconnectClient)
	mux.HandleFunc("/openvpn/settings", s.openvpnSettings)
	mux.HandleFunc("/openvpn/raw-config", s.openvpnRawConfig)
	mux.HandleFunc("/openvpn/check-config", s.openvpnCheckConfig)
	mux.HandleFunc("/openvpn/apply-config", s.openvpnApplyConfig)
	mux.HandleFunc("/openvpn/info", s.openvpnInfo)
	mux.HandleFunc("/openvpn/service", s.openvpnService)
	mux.HandleFunc("/openvpn/write-file", s.writeOpenvpnFile)
	mux.HandleFunc("/openvpn/file-sha256", s.openvpnFileSha256)
	mux.HandleFunc("/system/network", s.systemNetwork)
	mux.HandleFunc("/system/services", s.systemServices)
	mux.HandleFunc("/system/service-unit", s.systemServiceUnitAction)
	mux.HandleFunc("/dnsmasq", s.dnsmasq)
	mux.HandleFunc("/firewall/apply-runtime", s.firewallApplyRuntime)
	mux.HandleFunc("/panel/snapshot", s.panelSnapshot)
	mux.HandleFunc("/agent/update", s.agentUpdate)
	return mux
}

func (s *AgentServer) systemNetwork(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type ifaceRow struct {
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
		}
		rows := make([]ifaceRow, 0, len(ifaces))
		allAddrs := make([]string, 0, len(ifaces)*2)
		seenAddr := map[string]bool{}
		for _, ifc := range ifaces {
			addrRows, _ := ifc.Addrs()
			addrs := make([]string, 0, len(addrRows))
			for _, a := range addrRows {
				s := a.String()
				ip, _, parseErr := net.ParseCIDR(s)
				if parseErr == nil && ip != nil {
					s = ip.String()
				}
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				addrs = append(addrs, s)
				if !seenAddr[s] {
					seenAddr[s] = true
					allAddrs = append(allAddrs, s)
				}
			}
			rows = append(rows, ifaceRow{
				Name:      ifc.Name,
				Addresses: addrs,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"interfaces": rows,
			"addresses":  allAddrs,
		})
	})(w, r)
}

func (s *AgentServer) openvpnRawConfig(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.ServerConfPath == "" {
			http.Error(w, "OPENVPN_SERVER_CONF is not set", http.StatusServiceUnavailable)
			return
		}
		raw, err := os.ReadFile(s.ServerConfPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"configPath": s.ServerConfPath,
			"rawConfig":  string(raw),
		})
	})(w, r)
}

func (s *AgentServer) health(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

func (s *AgentServer) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != s.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *AgentServer) metrics(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		clients, err := s.OpenVPN.GetClients(context.Background())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		snapshot, err := s.System.Snapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		payload := map[string]any{
			"status":           "ONLINE",
			"cpuPercent":       snapshot.CPUPercent,
			"memoryPercent":    snapshot.MemoryPercent,
			"diskPercent":      snapshot.DiskPercent,
			"diskReadBps":      snapshot.DiskReadBps,
			"diskWriteBps":     snapshot.DiskWriteBps,
			"networkInBps":     snapshot.NetworkInBps,
			"networkOutBps":    snapshot.NetworkOutBps,
			"networkInterface": snapshot.NetworkInterface,
			"activeClients":    len(clients),
		}
		json.NewEncoder(w).Encode(payload)
	})(w, r)
}

func (s *AgentServer) clients(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		list, err := s.OpenVPN.GetClients(context.Background())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(list)
	})(w, r)
}

func (s *AgentServer) disconnectClient(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			ID string `json:"id"`
		}
		var req reqBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}

		if err := s.OpenVPN.DisconnectClient(context.Background(), req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "disconnected", "id": req.ID})
	})(w, r)
}

func (s *AgentServer) openvpnSettings(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if s.ServerConfPath == "" {
			http.Error(w, "OPENVPN_SERVER_CONF is not set", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			settings, err := ReadServerSettings(s.ServerConfPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"settings":   settings,
				"configPath": s.ServerConfPath,
			})
		case http.MethodPost:
			var body struct {
				Settings map[string]any `json:"settings"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if body.Settings == nil {
				http.Error(w, "settings required", http.StatusBadRequest)
				return
			}
			bin := s.OpenVPNBin
			if bin == "" {
				bin = "openvpn"
			}
			stagedPath, hints, err := ApplyServerSettings(s.ServerConfPath, bin, body.Settings)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": err.Error(),
					"hints": hints,
					"stagedConfigPath": stagedPath,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":             true,
				"message":        "Временный конфиг сохранён и прошёл проверку.",
				"stagedConfigPath": stagedPath,
				"configPath":     s.ServerConfPath,
			})
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})(w, r)
}

func (s *AgentServer) openvpnInfo(w http.ResponseWriter, r *http.Request) {
	s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		mgmtAddr := ""
		if s.OpenVPN != nil {
			mgmtAddr = s.OpenVPN.Addr
		}
		info := DetectOpenVPNRuntimeInfo(
			context.Background(),
			s.OpenVPNBin,
			s.ServerConfPath,
			s.ServerLogPath,
			mgmtAddr,
			s.ServiceUnit,
			s.OpenVPN,
		)
		_ = json.NewEncoder(w).Encode(info)
	})(w, r)
}

func (s *AgentServer) openvpnCheckConfig(w http.ResponseWriter, r *http.Request) {
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
		bin := s.OpenVPNBin
		if bin == "" {
			bin = "openvpn"
		}
		dir := filepath.Dir(s.ServerConfPath)
		stagedPath := filepath.Join(dir, stagedServerConfigName)
		targetPath := s.ServerConfPath
		if _, statErr := os.Stat(stagedPath); statErr == nil {
			targetPath = stagedPath
		}
		commandStr := BuildOpenVPNCheckCommand(bin, targetPath)
		hints, err := ValidateOpenVPNConfig(context.Background(), bin, targetPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":         false,
				"error":      err.Error(),
				"output":     err.Error(),
				"command":    commandStr,
				"hints":      hints,
				"configPath": targetPath,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"message":    "Конфигурация OpenVPN прошла проверку.",
			"output":     "",
			"command":    commandStr,
			"configPath": targetPath,
		})
	})(w, r)
}

func (s *AgentServer) openvpnApplyConfig(w http.ResponseWriter, r *http.Request) {
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
		dir := filepath.Dir(s.ServerConfPath)
		stagedPath := filepath.Join(dir, stagedServerConfigName)
		if _, err := os.Stat(stagedPath); err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "staged config not found; save settings first", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		restartCommand := s.serviceCommand("restart")
		if restartCommand == "" {
			restartCommand = "systemctl restart " + detectOpenVPNServiceUnit(s.ServiceUnit)
		}
		serviceUnit := detectOpenVPNServiceUnit(s.ServiceUnit)
		res, applyErr := ApplyStagedServerConfig(s.ServerConfPath, stagedPath, restartCommand, serviceUnit)
		if applyErr != nil {
			fail, ok := applyErr.(*ApplyConfigFailure)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			if ok {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":              false,
					"error":           fail.Error(),
					"hints":           fail.Hints,
					"output":          fail.Output,
					"serviceLog":      fail.ServiceLog,
					"rolledBack":      fail.RolledBack,
					"backupPath":      fail.BackupPath,
					"stagedConfigPath": stagedPath,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": applyErr.Error(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":              true,
			"message":         "Конфигурация применена. Служба OpenVPN перезапущена успешно.",
			"backupPath":      res.BackupPath,
			"output":          res.Output,
			"serviceLog":      res.ServiceLog,
			"configPath":      s.ServerConfPath,
			"serviceUnit":     serviceUnit,
			"stagedConfigPath": stagedPath,
		})
	})(w, r)
}
