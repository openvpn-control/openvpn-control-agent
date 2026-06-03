package internal

import "testing"

func TestArgvFromUnitFileExecStartRHEL(t *testing.T) {
	argv := argvFromUnitFileExecStart("openvpn-server@server.service")
	if len(argv) == 0 {
		t.Skip("unit file not present on this host")
	}
	found := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--data-ciphers" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected --data-ciphers in argv: %v", argv)
	}
	keys := openVPNConfigKeysSetOnExecStart("openvpn-server@server.service")
	if !keys["data-ciphers"] || !keys["cipher"] {
		t.Fatalf("keys=%v", keys)
	}
}
