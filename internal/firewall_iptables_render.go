package internal

import (
	"fmt"
	"strings"
)

const chainBase = "OPENVPN_PANEL_BASE"
const chainNat = "OPENVPN_PANEL_NAT"
const chainNatPost = "OPENVPN_PANEL_NAT_POST"
const chainNatPre = "OPENVPN_PANEL_NAT_PRE"
const legacyDispatch = "OPENVPN_PANEL_FWD"

type fwRule struct {
	Action      string `json:"action"`
	Proto       string `json:"proto"`
	Destination string `json:"destination"`
	Ports       string `json:"ports"`
}

type natRule struct {
	Type          string `json:"type"`
	Src           string `json:"src"`
	Dst           string `json:"dst"`
	OutInterface  string `json:"outInterface"`
	ToAddress     string `json:"toAddress"`
}

type fwSession struct {
	Mode      string    `json:"-"`
	VirtualIP string    `json:"virtualIp"`
	Rules     []fwRule  `json:"rules"`
	NatRules  []natRule `json:"natRules"`
}

type iptablesRenderParams struct {
	NodeLabel           string
	TunnelInterface     string
	VpnSubnetCidr       string
	TunnelDefaultPolicy string
	TunnelRules         []fwRule
	NatRules            []natRule
	Sessions            []fwSession
}

func chainSuffixFromVirtIP(ip string) string {
	base := strings.TrimSpace(ip)
	if i := strings.Index(base, "/"); i >= 0 {
		base = base[:i]
	}
	base = strings.ReplaceAll(base, ".", "_")
	base = strings.ReplaceAll(base, ":", "_")
	return base
}

func shQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}

func normalizeTunnelIfName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "tun0"
	}
	switch strings.ToLower(s) {
	case "tun":
		return "tun0"
	case "tap":
		return "tap0"
	default:
		return s
	}
}

func orderedRulesForIptables(baseRules, userRules []fwRule, mode string) []fwRule {
	var combined []fwRule
	if mode == "replace" {
		combined = append([]fwRule{}, userRules...)
	} else {
		combined = append(append([]fwRule{}, baseRules...), userRules...)
	}
	// reverse
	for i, j := 0, len(combined)-1; i < j; i, j = i+1, j-1 {
		combined[i], combined[j] = combined[j], combined[i]
	}
	return combined
}

func portMatchArgs(r fwRule) string {
	ports := strings.ReplaceAll(strings.TrimSpace(r.Ports), " ", "")
	if ports == "" {
		return ""
	}
	if strings.Contains(ports, ",") || strings.Contains(ports, ":") {
		return "-m multiport --dports " + ports
	}
	return "--dport " + ports
}

func emitFilterAppends(chain string, r fwRule) []string {
	tgt := "ACCEPT"
	if strings.ToLower(r.Action) == "deny" {
		tgt = "DROP"
	}
	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	if proto == "icmp" {
		dst := ""
		if strings.TrimSpace(r.Destination) != "" {
			dst = "-d " + shQuote(r.Destination) + " "
		}
		line := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p icmp %s-j %s", chain, dst, tgt))
		line = strings.Join(strings.Fields(line), " ")
		return []string{line}
	}
	dst := ""
	if strings.TrimSpace(r.Destination) != "" {
		dst = "-d " + shQuote(r.Destination) + " "
	}
	pm := portMatchArgs(r)
	if proto == "any" {
		if pm != "" {
			a := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p tcp %s%s -j %s", chain, dst, pm, tgt))
			b := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p udp %s%s -j %s", chain, dst, pm, tgt))
			return []string{strings.Join(strings.Fields(a), " "), strings.Join(strings.Fields(b), " ")}
		}
		a := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p tcp %s-j %s", chain, dst, tgt))
		b := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p udp %s-j %s", chain, dst, tgt))
		return []string{strings.Join(strings.Fields(a), " "), strings.Join(strings.Fields(b), " ")}
	}
	p := "tcp"
	if proto == "udp" {
		p = "udp"
	}
	portPart := ""
	if pm != "" {
		portPart = " " + pm
	}
	line := strings.TrimSpace(fmt.Sprintf("iptables -t filter -A %s -p %s %s%s -j %s", chain, p, dst, portPart, tgt))
	return []string{strings.Join(strings.Fields(line), " ")}
}

func appendDefaultEnd(chain, defaultPolicy string) []string {
	if strings.ToLower(defaultPolicy) == "allow" {
		return []string{fmt.Sprintf("iptables -t filter -A %s -j RETURN", chain)}
	}
	return []string{fmt.Sprintf("iptables -t filter -A %s -j DROP", chain)}
}

func buildFilterChainContent(chainName, defaultPolicy string, orderedRules []fwRule) []string {
	var lines []string
	for _, rule := range orderedRules {
		lines = append(lines, emitFilterAppends(chainName, rule)...)
	}
	lines = append(lines, appendDefaultEnd(chainName, defaultPolicy)...)
	return lines
}

func natAppendLine(chain string, r natRule) string {
	if strings.ToLower(r.Type) == "snat" {
		src := ""
		if strings.TrimSpace(r.Src) != "" {
			src = "-s " + shQuote(r.Src) + " "
		}
		dst := ""
		if strings.TrimSpace(r.Dst) != "" {
			dst = "-d " + shQuote(r.Dst) + " "
		}
		out := ""
		if strings.TrimSpace(r.OutInterface) != "" {
			out = "-o " + shQuote(r.OutInterface) + " "
		}
		to := ""
		if strings.TrimSpace(r.ToAddress) != "" {
			to = " --to-source " + shQuote(r.ToAddress)
		}
		line := fmt.Sprintf("iptables -t nat -A %s %s%s%s-j SNAT%s", chain, src, dst, out, to)
		return strings.Join(strings.Fields(line), " ")
	}
	if strings.ToLower(r.Type) == "dnat" {
		src := ""
		if strings.TrimSpace(r.Src) != "" {
			src = "-s " + shQuote(r.Src) + " "
		}
		dst := ""
		if strings.TrimSpace(r.Dst) != "" {
			dst = "-d " + shQuote(r.Dst) + " "
		}
		in := ""
		if strings.TrimSpace(r.OutInterface) != "" {
			in = "-i " + shQuote(r.OutInterface) + " "
		}
		to := ""
		if strings.TrimSpace(r.ToAddress) != "" {
			to = " --to-destination " + shQuote(r.ToAddress)
		}
		line := fmt.Sprintf("iptables -t nat -A %s %s%s%s-j DNAT%s", chain, src, dst, in, to)
		return strings.Join(strings.Fields(line), " ")
	}
	src := ""
	if strings.TrimSpace(r.Src) != "" {
		src = "-s " + shQuote(r.Src) + " "
	}
	dst := ""
	if strings.TrimSpace(r.Dst) != "" {
		dst = "-d " + shQuote(r.Dst) + " "
	}
	out := ""
	if strings.TrimSpace(r.OutInterface) != "" {
		out = "-o " + shQuote(r.OutInterface) + " "
	}
	line := fmt.Sprintf("iptables -t nat -A %s %s%s%s-j MASQUERADE", chain, src, dst, out)
	return strings.Join(strings.Fields(line), " ")
}

// RenderFirewallRuntimeIptablesScript — паритет с backend firewallIptablesRuntime.js
func RenderFirewallRuntimeIptablesScript(p iptablesRenderParams) string {
	iface := normalizeTunnelIfName(p.TunnelInterface)
	cidr := strings.TrimSpace(p.VpnSubnetCidr)
	IF := shQuote(iface)
	SN := ""
	if cidr != "" {
		SN = shQuote(cidr)
	}
	sessions := p.Sessions

	lines := []string{
		"#!/bin/sh",
		"set -e",
		fmt.Sprintf("# openvpn-panel runtime firewall (iptables) — %s", p.NodeLabel),
		"set +e",
		"while iptables -t filter -S FORWARD 2>/dev/null | grep -qE -- '-j OVPN_| -j OPENVPN_PANEL_'; do SPEC=$(iptables -t filter -S FORWARD 2>/dev/null | grep -E -- '-j OVPN_| -j OPENVPN_PANEL_' | head -n1 | sed 's/^-A FORWARD //'); [ -z \"$SPEC\" ] && break; iptables -t filter -D FORWARD $SPEC 2>/dev/null || break; done",
		"for c in $(iptables -t filter -L 2>/dev/null | sed -n 's/^Chain \\(OVPN_[^ ]*\\) .*/\\1/p'); do iptables -t filter -F \"$c\" 2>/dev/null; iptables -t filter -X \"$c\" 2>/dev/null; done",
		fmt.Sprintf("iptables -t filter -F %s 2>/dev/null || true", legacyDispatch),
		fmt.Sprintf("iptables -t filter -X %s 2>/dev/null || true", legacyDispatch),
		fmt.Sprintf("iptables -t filter -F %s 2>/dev/null || true", chainBase),
		fmt.Sprintf("iptables -t filter -X %s 2>/dev/null || true", chainBase),
	}
	if cidr != "" {
		lines = append(lines, fmt.Sprintf("while iptables -t nat -C POSTROUTING -s %s -j %s 2>/dev/null; do iptables -t nat -D POSTROUTING -s %s -j %s; done", SN, chainNat, SN, chainNat))
		lines = append(lines, fmt.Sprintf("while iptables -t nat -C POSTROUTING -s %s -j %s 2>/dev/null; do iptables -t nat -D POSTROUTING -s %s -j %s; done", SN, chainNatPost, SN, chainNatPost))
	}
	lines = append(lines,
		fmt.Sprintf("while iptables -t nat -C POSTROUTING -j %s 2>/dev/null; do iptables -t nat -D POSTROUTING -j %s; done", chainNat, chainNat),
		fmt.Sprintf("while iptables -t nat -C POSTROUTING -j %s 2>/dev/null; do iptables -t nat -D POSTROUTING -j %s; done", chainNatPost, chainNatPost),
		fmt.Sprintf("while iptables -t nat -C PREROUTING -j %s 2>/dev/null; do iptables -t nat -D PREROUTING -j %s; done", chainNatPre, chainNatPre),
		fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chainNat),
		fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chainNat),
		fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chainNatPost),
		fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chainNatPost),
		fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chainNatPre),
		fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chainNatPre),
		"set -e",
	)

	for _, s := range sessions {
		suf := chainSuffixFromVirtIP(s.VirtualIP)
		vip := strings.TrimSpace(s.VirtualIP)
		if idx := strings.Index(vip, "/"); idx >= 0 {
			vip = vip[:idx]
		}
		vip = strings.TrimSpace(vip)
		if vip == "" {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(s.Mode))
		if mode == "replace" {
			ord := orderedRulesForIptables(nil, s.Rules, "replace")
			lines = append(lines, fmt.Sprintf("iptables -t filter -N OVPN_REP_%s", suf))
			lines = append(lines, buildFilterChainContent("OVPN_REP_"+suf, p.TunnelDefaultPolicy, ord)...)
		} else if len(s.Rules) > 0 {
			ord := orderedRulesForIptables(p.TunnelRules, s.Rules, "merge")
			lines = append(lines, fmt.Sprintf("iptables -t filter -N OVPN_MRG_%s", suf))
			lines = append(lines, buildFilterChainContent("OVPN_MRG_"+suf, p.TunnelDefaultPolicy, ord)...)
		}
	}

	baseOrd := orderedRulesForIptables(p.TunnelRules, nil, "merge")
	lines = append(lines, fmt.Sprintf("iptables -t filter -N %s", chainBase))
	lines = append(lines, buildFilterChainContent(chainBase, p.TunnelDefaultPolicy, baseOrd)...)

	if cidr != "" {
		lines = append(lines, fmt.Sprintf("iptables -t filter -I FORWARD 1 -i %s -s %s -j %s", IF, SN, chainBase))
	} else {
		lines = append(lines, fmt.Sprintf("iptables -t filter -I FORWARD 1 -i %s -j %s", IF, chainBase))
	}
	for _, s := range sessions {
		suf := chainSuffixFromVirtIP(s.VirtualIP)
		vip := strings.TrimSpace(s.VirtualIP)
		if idx := strings.Index(vip, "/"); idx >= 0 {
			vip = vip[:idx]
		}
		vip = strings.TrimSpace(vip)
		if vip == "" {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(s.Mode))
		if mode == "replace" {
			lines = append(lines, fmt.Sprintf("iptables -t filter -I FORWARD 1 -i %s -s %s -j OVPN_REP_%s", IF, shQuote(vip+"/32"), suf))
		} else if len(s.Rules) > 0 {
			lines = append(lines, fmt.Sprintf("iptables -t filter -I FORWARD 1 -i %s -s %s -j OVPN_MRG_%s", IF, shQuote(vip+"/32"), suf))
		}
	}

	natRules := p.NatRules
	if len(natRules) > 0 {
		postRules := make([]natRule, 0, len(natRules))
		preRules := make([]natRule, 0, len(natRules))
		for _, r := range natRules {
			if strings.ToLower(strings.TrimSpace(r.Type)) == "dnat" {
				preRules = append(preRules, r)
			} else {
				postRules = append(postRules, r)
			}
		}
		if len(postRules) > 0 {
			lines = append(lines, fmt.Sprintf("iptables -t nat -N %s", chainNatPost))
			for _, r := range postRules {
				lines = append(lines, natAppendLine(chainNatPost, r))
			}
			if cidr != "" {
				lines = append(lines, fmt.Sprintf("iptables -t nat -I POSTROUTING 1 -s %s -j %s", SN, chainNatPost))
			} else {
				lines = append(lines, fmt.Sprintf("iptables -t nat -I POSTROUTING 1 -j %s", chainNatPost))
			}
		}
		if len(preRules) > 0 {
			lines = append(lines, fmt.Sprintf("iptables -t nat -N %s", chainNatPre))
			for _, r := range preRules {
				lines = append(lines, natAppendLine(chainNatPre, r))
			}
			lines = append(lines, fmt.Sprintf("iptables -t nat -I PREROUTING 1 -j %s", chainNatPre))
		}
	}

	return strings.Join(lines, "\n")
}
