package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"openvpn-control-agent/internal"
)

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	addr := envOrDefault("AGENT_ADDR", ":9443")
	tokenPath := envOrDefault("AGENT_TOKEN_FILE", "/var/lib/openvpn-control-agent/token")
	openvpnMgmtAddr := envOrDefault("OPENVPN_MGMT_ADDR", "127.0.0.1:7505")
	networkInterface := os.Getenv("OPENVPN_NET_INTERFACE")

	token, created, err := internal.LoadOrCreateToken(tokenPath)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("New agent token generated: %s", token)
	}
	log.Printf("Agent token file: %s", tokenPath)

	server := &internal.AgentServer{
		Token: token,
		OpenVPN: &internal.OpenVPNManagement{
			Addr:    openvpnMgmtAddr,
			Timeout: 4 * time.Second,
		},
		System: &internal.SystemMetricsCollector{
			Interface: networkInterface,
		},
		ServerConfPath: envOrDefault("OPENVPN_SERVER_CONF", "/etc/openvpn/server.conf"),
		ServerLogPath:  os.Getenv("OPENVPN_SERVER_LOG"),
		OpenVPNBin:     envOrDefault("OPENVPN_BINARY", "openvpn"),
		ServiceUnit:    envOrDefault("OPENVPN_SERVICE_UNIT", "openvpn.service"),
		ReloadCmd:      os.Getenv("OPENVPN_RELOAD_CMD"),
		AgentServiceUnit: envOrDefault("AGENT_SERVICE_UNIT", "openvpn-control-agent.service"),
		AgentRestartCmd:  os.Getenv("AGENT_RESTART_CMD"),
		ServiceStartCmd:   os.Getenv("OPENVPN_SERVICE_START_CMD"),
		ServiceStopCmd:    os.Getenv("OPENVPN_SERVICE_STOP_CMD"),
		ServiceRestartCmd: os.Getenv("OPENVPN_SERVICE_RESTART_CMD"),
		DNSMasqConfPath:   envOrDefault("DNSMASQ_CONF", "/etc/dnsmasq.d/openvpn-control.conf"),
		DNSMasqServiceUnit: envOrDefault("DNSMASQ_SERVICE_UNIT", "dnsmasq.service"),
	}

	// Локальный снимок панели: firewall из snapshot + живых клиентов, даже если панель недоступна.
	internal.StartSnapshotFirewallLoop(server, 5*time.Second)

	log.Printf("OpenVPN agent listening on http://%s", addr)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: server.Routes(),
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
