package internal

import "testing"

func TestNormalizeManagementValue(t *testing.T) {
	got := normalizeManagementValue("127.0.0.1:7505")
	if got != "127.0.0.1 7505" {
		t.Fatalf("got %q", got)
	}
}

func TestDataCiphersUseAuth(t *testing.T) {
	if dataCiphersUseAuth("AES-256-GCM:AES-128-GCM") {
		t.Fatal("GCM should not need auth")
	}
	if !dataCiphersUseAuth("AES-256-CBC") {
		t.Fatal("CBC should need auth")
	}
}

func TestNormalizeCryptoSettingsDropsAuthForGCM(t *testing.T) {
	s := map[string]any{
		"data-ciphers": "AES-256-GCM:AES-128-GCM",
		"auth":         "SHA256",
	}
	normalizeCryptoSettings(s)
	if _, ok := s["auth"]; ok {
		t.Fatal("auth should be removed for GCM-only")
	}
}
