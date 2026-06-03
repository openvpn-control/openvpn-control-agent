package internal

import "testing"

func TestParseManagementListenAddr(t *testing.T) {
	got := parseManagementListenAddr("127.0.0.1 7505")
	if got != "127.0.0.1:7505" {
		t.Fatalf("got %q", got)
	}
}

func TestOpenVPNServiceProcessRunning(t *testing.T) {
	if !openVPNServiceProcessRunning(&OpenVPNRuntimeInfo{ActiveState: "active", MainPID: 248670}) {
		t.Fatal("expected running")
	}
	if openVPNServiceProcessRunning(&OpenVPNRuntimeInfo{ActiveState: "inactive", MainPID: 0}) {
		t.Fatal("expected not running")
	}
}
