package internal

import "testing"

func TestOpenVPNServiceUnitCandidatesPrioritizeServerInstance(t *testing.T) {
	c := openvpnServiceUnitCandidates("openvpn.service")
	idxServer := -1
	idxGeneric := -1
	for i, u := range c {
		switch u {
		case "openvpn-server@server.service":
			idxServer = i
		case "openvpn.service":
			idxGeneric = i
		}
	}
	if idxServer < 0 {
		t.Fatalf("missing openvpn-server@server.service in %v", c)
	}
	if idxGeneric < 0 {
		t.Fatalf("missing openvpn.service in %v", c)
	}
	if idxServer >= idxGeneric {
		t.Fatalf("openvpn-server@server.service must precede openvpn.service, got %v", c)
	}
}

func TestOpenVPNServiceUnitCandidatesPreferredInstanceFirst(t *testing.T) {
	c := openvpnServiceUnitCandidates("openvpn-server@foo.service")
	if len(c) == 0 || c[0] != "openvpn-server@foo.service" {
		t.Fatalf("preferred instance unit first, got %v", c)
	}
}
