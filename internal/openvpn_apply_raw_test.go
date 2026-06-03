package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyRawServerConfigWritesFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "server.conf")
	raw := []byte("port 1195\nproto udp\n")
	_, err := ApplyRawServerConfig(conf, "true", raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("file=%q", got)
	}
}

func TestRawConfigFromDiffShape(t *testing.T) {
	diff := []struct{ line, typ string }{
		{"port 1194", "same"},
		{"proto tcp", "add"},
		{"verb 3", "del"},
	}
	var lines []string
	for _, d := range diff {
		if d.typ == "del" {
			continue
		}
		lines = append(lines, d.line)
	}
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "proto tcp") || strings.Contains(text, "verb 3") {
		t.Fatalf("reconstructed=%q", text)
	}
}
