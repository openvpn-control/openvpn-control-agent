package internal

import (
	"strings"
	"testing"
)

func TestNatAppendLine_DnatUsesInputInterface(t *testing.T) {
	line := natAppendLine(chainNatPre, natRule{
		Type:         "dnat",
		Src:          "10.220.0.10/32",
		OutInterface: "eth0",
		ToAddress:    "172.16.1.20",
	})

	if !strings.Contains(line, "-i 'eth0'") {
		t.Fatalf("expected DNAT rule to use input interface, got: %s", line)
	}
	if strings.Contains(line, "-o 'eth0'") {
		t.Fatalf("expected DNAT rule not to use output interface, got: %s", line)
	}
	if !strings.Contains(line, "--to-destination '172.16.1.20'") {
		t.Fatalf("expected DNAT to-address in rule, got: %s", line)
	}
}

func TestRenderFirewallRuntimeIptablesScript_SplitsNatChains(t *testing.T) {
	script := RenderFirewallRuntimeIptablesScript(iptablesRenderParams{
		NodeLabel:           "node-1",
		TunnelInterface:     "tun0",
		VpnSubnetCidr:       "10.220.0.0/22",
		TunnelDefaultPolicy: "deny",
		TunnelRules:         []fwRule{},
		NatRules: []natRule{
			{Type: "dnat", ToAddress: "172.16.1.20"},
			{Type: "snat", ToAddress: "203.0.113.10"},
		},
	})

	if !strings.Contains(script, "iptables -t nat -I PREROUTING 1 -j "+chainNatPre) {
		t.Fatalf("expected prerouting hook for DNAT chain")
	}
	if !strings.Contains(script, "iptables -t nat -I POSTROUTING 1 -s '10.220.0.0/22' -j "+chainNatPost) {
		t.Fatalf("expected postrouting hook for SNAT/MASQUERADE chain")
	}
}
