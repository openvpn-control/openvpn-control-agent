package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildServerConfigBytesIncludesRemoteCertTls(t *testing.T) {
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
	if !strings.Contains(text, "remote-cert-tls client") {
		t.Fatalf("expected remote-cert-tls in config:\n%s", text)
	}
}
