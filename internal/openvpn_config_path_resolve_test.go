package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseExecStartConfigPathDebianLayout(t *testing.T) {
	execStart := `{ path=/usr/sbin/openvpn ; argv[]=/usr/sbin/openvpn ; argv[]=--config ; argv[]=server.conf }`
	cfg := configArgFromSystemdExecStart(execStart)
	got := buildOpenVPNConfigPath(cfg, "/etc/openvpn", "server")
	want := "/etc/openvpn/server.conf"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseExecStartConfigPathAbsolute(t *testing.T) {
	execStart := `{ argv[]=/usr/sbin/openvpn ; argv[]=--config ; argv[]=/etc/openvpn/my.conf }`
	cfg := configArgFromSystemdExecStart(execStart)
	got := buildOpenVPNConfigPath(cfg, "", "server")
	want := "/etc/openvpn/my.conf"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestBuildOpenVPNConfigPathRHELOpenVPNServer(t *testing.T) {
	const unitBody = `[Service]
WorkingDirectory=/etc/openvpn/server
ExecStart=/usr/sbin/openvpn --status %t/openvpn-server/status-%i.log --config %i.conf
`
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "openvpn-server@.service")
	if err := os.WriteFile(unitPath, []byte(unitBody), 0o644); err != nil {
		t.Fatal(err)
	}
	wd, cfgTpl := parseOpenVPNUnitFile(unitPath)
	got := buildOpenVPNConfigPath(cfgTpl, wd, "server")
	want := "/etc/openvpn/server/server.conf"
	if got != want {
		t.Fatalf("got %q want %q (wd=%q cfg=%q)", got, want, wd, cfgTpl)
	}
}

func TestExpandSystemdInstanceSpecifiers(t *testing.T) {
	got := expandSystemdInstanceSpecifiers("%i.conf", "server")
	if got != "server.conf" {
		t.Fatalf("got %q", got)
	}
}
