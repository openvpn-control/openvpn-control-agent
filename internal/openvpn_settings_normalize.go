package internal

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func normalizeServerSettings(settings map[string]any, serviceUnit string) {
	if settings == nil {
		return
	}
	normalizeRuntimeUserGroup(settings)
	normalizeCryptoSettings(settings)
	normalizeManagementSetting(settings)
	normalizeTunnelSettings(settings)
	normalizeSystemdExecOverrides(settings, serviceUnit)
}

func normalizeTunnelSettings(settings map[string]any) {
	if settings == nil {
		return
	}
	if n, ok := numericSetting(settings["fragment"]); ok && n == 0 {
		delete(settings, "fragment")
	}
	if s := fmtSettingString(settings["user"]); s == "" {
		delete(settings, "user")
	}
	if s := fmtSettingString(settings["group"]); s == "" {
		delete(settings, "group")
	}
}

func numericSetting(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
}

func normalizeManagementSetting(settings map[string]any) {
	raw := strings.TrimSpace(fmtSettingString(settings["management"]))
	if raw == "" {
		return
	}
	settings["management"] = normalizeManagementValue(raw)
}

func normalizeManagementValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, " ") {
		return raw
	}
	if host, port, err := net.SplitHostPort(raw); err == nil && host != "" && port != "" {
		return host + " " + port
	}
	return raw
}

func normalizeCryptoSettings(settings map[string]any) {
	if settings == nil {
		return
	}
	dc := fmtSettingString(settings["data-ciphers"])
	if dc == "" {
		settings["data-ciphers"] = "AES-256-GCM:AES-128-GCM"
		dc = "AES-256-GCM:AES-128-GCM"
	}
	if v, ok := settings["cipher"]; ok && strings.TrimSpace(fmtSettingString(v)) == "" {
		delete(settings, "cipher")
	}
	if !dataCiphersUseAuth(dc) {
		delete(settings, "auth")
	}
}

func dataCiphersUseAuth(dc string) bool {
	low := strings.ToLower(strings.TrimSpace(dc))
	if low == "" {
		return true
	}
	if strings.Contains(low, "cbc") {
		return true
	}
	if strings.Contains(low, "gcm") {
		return false
	}
	return true
}

func mutateConfigForOpenVPN(data []byte, serviceUnit string) []byte {
	data = rewriteInvalidGroupInConfig(data)
	data = rewriteCryptoIncompatibilitiesInConfig(data)
	data = rewriteInvalidTunnelDirectivesInConfig(data)
	data = rewriteStripSystemdExecOverrides(data, serviceUnit)
	return data
}

func rewriteInvalidTunnelDirectivesInConfig(data []byte) []byte {
	text := strings.ToLower(string(data))
	gcmOnly := strings.Contains(text, "gcm") && !strings.Contains(text, "cbc")
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		tok := firstToken(stripInlineComment(raw))
		if tok == "fragment" {
			fields := strings.Fields(stripInlineComment(raw))
			if len(fields) >= 2 && fields[1] == "0" {
				continue
			}
		}
		if gcmOnly && tok == "cipher" {
			continue
		}
		out = append(out, raw)
	}
	return []byte(strings.Join(out, "\n"))
}

func rewriteCryptoIncompatibilitiesInConfig(data []byte) []byte {
	text := string(data)
	if !strings.Contains(strings.ToLower(text), "gcm") {
		return data
	}
	if strings.Contains(strings.ToLower(text), "cbc") {
		return data
	}
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		if firstToken(stripInlineComment(raw)) == "auth" {
			continue
		}
		out = append(out, raw)
	}
	return []byte(strings.Join(out, "\n"))
}

func fmtSettingString(v any) string {
	if v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	s = strings.Trim(s, `"`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}
