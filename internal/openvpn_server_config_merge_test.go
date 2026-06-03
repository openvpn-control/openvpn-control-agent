package internal

import "testing"

func TestMergeManagedSettingsOverlayPreservesExisting(t *testing.T) {
	existing := map[string]any{"port": float64(1194), "proto": "udp"}
	overlay := map[string]any{"remote-cert-tls": "client"}
	got := mergeManagedSettingsOverlay(existing, overlay)
	if got["port"] != float64(1194) {
		t.Fatalf("port=%v", got["port"])
	}
	if got["remote-cert-tls"] != "client" {
		t.Fatalf("remote-cert-tls=%v", got["remote-cert-tls"])
	}
}

func TestMergeManagedSettingsOverlayClearsEmpty(t *testing.T) {
	existing := map[string]any{"remote-cert-tls": "client"}
	overlay := map[string]any{"remote-cert-tls": ""}
	got := mergeManagedSettingsOverlay(existing, overlay)
	if _, ok := got["remote-cert-tls"]; ok {
		t.Fatalf("expected cleared, got %v", got)
	}
}
