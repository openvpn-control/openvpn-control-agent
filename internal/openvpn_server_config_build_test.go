package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildServerConfigBytesSkipsRemoteCertTlsOverlay(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(conf, []byte("port 1194\nproto udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := BuildServerConfigBytes(conf, "", map[string]any{"remote-cert-tls": "client"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "remote-cert-tls") {
		t.Fatalf("remote-cert-tls is client-only, must not be written to server.conf:\n%s", text)
	}
}
