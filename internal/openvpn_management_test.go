package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadManagementDirectivesFromConfig(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "server.conf")
	body := "port 1194\nmanagement 127.0.0.1 7505\nmanagement localhost 7506\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readManagementDirectivesFromConfig(conf)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	addrs := managementAddrsToProbe(conf, "")
	if len(addrs) < 2 {
		t.Fatalf("addrs=%v", addrs)
	}
	if addrs[0] != "127.0.0.1:7505" && addrs[1] != "127.0.0.1:7505" {
		t.Fatalf("expected 127.0.0.1:7505 in %v", addrs)
	}
}
