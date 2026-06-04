package internal

import "testing"

func TestMergeManagedSettingsOverlayPreservesExisting(t *testing.T) {
	existing := map[string]any{"port": float64(1194), "proto": "udp"}
	overlay := map[string]any{"port": float64(1195)}
	got := mergeManagedSettingsOverlay(existing, overlay)
	if got["port"] != float64(1195) {
		t.Fatalf("port=%v", got["port"])
	}
	if got["proto"] != "udp" {
		t.Fatalf("proto=%v", got["proto"])
	}
}

func TestMergeManagedSettingsOverlayIgnoresRemoteCertTls(t *testing.T) {
	existing := map[string]any{"port": float64(1194)}
	overlay := map[string]any{"remote-cert-tls": "client", "port": float64(1195)}
	got := mergeManagedSettingsOverlay(existing, overlay)
	if _, ok := got["remote-cert-tls"]; ok {
		t.Fatalf("remote-cert-tls must not be managed in server.conf, got %v", got["remote-cert-tls"])
	}
	if got["port"] != float64(1195) {
		t.Fatalf("port=%v", got["port"])
	}
}
