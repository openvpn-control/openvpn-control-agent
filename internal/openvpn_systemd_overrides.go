package internal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// openVPNConfigKeysSetOnExecStart lists server.conf keys already passed on the systemd command line.
func openVPNConfigKeysSetOnExecStart(serviceUnit string) map[string]bool {
	unit := strings.TrimSpace(serviceUnit)
	if unit == "" {
		unit = DetectOpenVPNServiceUnit("")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	argv := argvFromSystemdExecStart(systemdUnitProperty(ctx, unit, "ExecStart"))
	if len(argv) == 0 {
		tpl := openVPNTemplateUnitName(unit)
		if tpl != "" && tpl != unit {
			argv = argvFromSystemdExecStart(systemdUnitProperty(ctx, tpl, "ExecStart"))
		}
	}
	if len(argv) == 0 {
		argv = argvFromUnitFileExecStart(unit)
	}
	out := map[string]bool{}
	for i := 0; i < len(argv)-1; i++ {
		switch argv[i] {
		case "--cipher":
			out["cipher"] = true
		case "--data-ciphers":
			out["data-ciphers"] = true
		case "--auth":
			out["auth"] = true
		}
	}
	return out
}

func argvFromSystemdExecStart(execStart string) []string {
	execStart = strings.TrimSpace(execStart)
	if execStart == "" {
		return nil
	}
	var argv []string
	for _, part := range strings.Split(execStart, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "argv[]=") {
			argv = append(argv, strings.TrimPrefix(part, "argv[]="))
		}
	}
	return argv
}

func argvFromUnitFileExecStart(unit string) []string {
	tpl := openVPNTemplateUnitName(unit)
	if tpl == "" {
		return nil
	}
	for _, dir := range systemdUnitSearchDirs {
		path := filepath.Join(dir, tpl)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ExecStart=") {
				return strings.Fields(strings.TrimPrefix(line, "ExecStart="))
			}
		}
	}
	return nil
}

func normalizeSystemdExecOverrides(settings map[string]any, serviceUnit string) {
	if settings == nil {
		return
	}
	for key := range openVPNConfigKeysSetOnExecStart(serviceUnit) {
		delete(settings, key)
	}
}

// execStartCryptoArgsForValidate returns --cipher/--data-ciphers/--auth from the unit (as systemd runs).
func execStartCryptoArgsForValidate(serviceUnit string) []string {
	unit := strings.TrimSpace(serviceUnit)
	if unit == "" {
		unit = DetectOpenVPNServiceUnit("")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	argv := argvFromSystemdExecStart(systemdUnitProperty(ctx, unit, "ExecStart"))
	if len(argv) == 0 {
		tpl := openVPNTemplateUnitName(unit)
		if tpl != "" && tpl != unit {
			argv = argvFromSystemdExecStart(systemdUnitProperty(ctx, tpl, "ExecStart"))
		}
	}
	if len(argv) == 0 {
		argv = argvFromUnitFileExecStart(unit)
	}
	var out []string
	for i := 0; i < len(argv)-1; i++ {
		switch argv[i] {
		case "--cipher", "--data-ciphers", "--auth":
			out = append(out, argv[i], argv[i+1])
		}
	}
	return out
}

func openVPNServiceIsActive(serviceUnit string) bool {
	unit := strings.TrimSpace(serviceUnit)
	if unit == "" {
		unit = DetectOpenVPNServiceUnit("")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	_, active, ok := serviceUnitState(ctx, unit)
	return ok && (active == "active" || active == "activating")
}

func rewriteStripSystemdExecOverrides(data []byte, serviceUnit string) []byte {
	skip := openVPNConfigKeysSetOnExecStart(serviceUnit)
	if len(skip) == 0 {
		return data
	}
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		tok := firstToken(stripInlineComment(raw))
		if skip[tok] {
			continue
		}
		out = append(out, raw)
	}
	return []byte(strings.Join(out, "\n"))
}
