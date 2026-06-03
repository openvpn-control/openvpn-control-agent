package internal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DetectOpenVPNServiceUnit picks the OpenVPN systemd unit present on this host.
func DetectOpenVPNServiceUnit(preferred string) string {
	return detectOpenVPNServiceUnit(preferred)
}

// ResolveServerConfigPath returns the config file path the active OpenVPN unit expects.
// envPath (OPENVPN_SERVER_CONF) is used when systemd does not expose --config.
func ResolveServerConfigPath(envPath, serviceUnit string) string {
	envPath = strings.TrimSpace(envPath)
	unit := strings.TrimSpace(serviceUnit)
	if p := configPathFromSystemdUnit(unit); p != "" {
		return p
	}
	if envPath != "" {
		return envPath
	}
	return "/etc/openvpn/server.conf"
}

func openVPNInstanceFromUnit(unit string) string {
	unit = strings.TrimSpace(unit)
	for _, prefix := range []string{"openvpn-server@", "openvpn@"} {
		if !strings.HasPrefix(unit, prefix) {
			continue
		}
		inst := strings.TrimPrefix(unit, prefix)
		inst = strings.TrimSuffix(inst, ".service")
		if inst != "" && inst != "." {
			return inst
		}
	}
	return ""
}

func openVPNTemplateUnitName(unit string) string {
	unit = strings.TrimSpace(unit)
	for _, prefix := range []string{"openvpn-server@", "openvpn@"} {
		if strings.HasPrefix(unit, prefix) {
			return prefix + ".service"
		}
	}
	return ""
}

func expandSystemdInstanceSpecifiers(value, instance string) string {
	value = strings.TrimSpace(value)
	instance = strings.TrimSpace(instance)
	if value == "" || instance == "" {
		return value
	}
	value = strings.ReplaceAll(value, "%i", instance)
	value = strings.ReplaceAll(value, "%I", instance)
	return value
}

func buildOpenVPNConfigPath(configArg, workingDir, instance string) string {
	configArg = expandSystemdInstanceSpecifiers(strings.TrimSpace(configArg), instance)
	if configArg == "" {
		return ""
	}
	if filepath.IsAbs(configArg) {
		return filepath.Clean(configArg)
	}
	wd := strings.TrimSpace(workingDir)
	if wd == "" {
		return ""
	}
	return filepath.Clean(filepath.Join(wd, configArg))
}

func configArgFromExecStartLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "--config" || fields[i] == "-config" {
			return strings.TrimSpace(fields[i+1])
		}
	}
	return ""
}

func trimSystemdExecToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimRight(s, "}")
	return strings.TrimSpace(s)
}

func configArgFromSystemdExecStart(execStart string) string {
	execStart = strings.TrimSpace(execStart)
	if execStart == "" {
		return ""
	}
	var argv []string
	for _, part := range strings.Split(execStart, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "argv[]=") {
			argv = append(argv, trimSystemdExecToken(strings.TrimPrefix(part, "argv[]=")))
		}
	}
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--config" || argv[i] == "-config" {
			return trimSystemdExecToken(argv[i+1])
		}
	}
	return ""
}

func parseOpenVPNUnitFile(path string) (workingDir, configTemplate string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "WorkingDirectory=") {
			workingDir = strings.TrimSpace(strings.TrimPrefix(line, "WorkingDirectory="))
			continue
		}
		if strings.HasPrefix(line, "ExecStart=") {
			configTemplate = configArgFromExecStartLine(strings.TrimPrefix(line, "ExecStart="))
		}
	}
	return workingDir, configTemplate
}

var systemdUnitSearchDirs = []string{
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/etc/systemd/system",
}

func configPathFromInstalledUnitTemplate(templateUnit, instance string) string {
	templateUnit = strings.TrimSpace(templateUnit)
	instance = strings.TrimSpace(instance)
	if templateUnit == "" || instance == "" {
		return ""
	}
	for _, dir := range systemdUnitSearchDirs {
		path := filepath.Join(dir, templateUnit)
		wd, cfgTpl := parseOpenVPNUnitFile(path)
		if cfgTpl == "" {
			continue
		}
		if p := buildOpenVPNConfigPath(cfgTpl, wd, instance); p != "" {
			return p
		}
	}
	return ""
}

func configPathFromSystemdShow(ctx context.Context, unit, instance string) string {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return ""
	}
	wd := systemdUnitProperty(ctx, unit, "WorkingDirectory")
	execStart := systemdUnitProperty(ctx, unit, "ExecStart")
	cfgArg := configArgFromSystemdExecStart(execStart)
	if cfgArg == "" {
		return ""
	}
	if p := buildOpenVPNConfigPath(cfgArg, wd, instance); p != "" {
		return p
	}
	// Instance unit may omit WorkingDirectory; read it from the template unit file.
	if tpl := openVPNTemplateUnitName(unit); tpl != "" {
		if fileWD, _ := parseOpenVPNUnitFileFirst(tpl); fileWD != "" {
			return buildOpenVPNConfigPath(cfgArg, fileWD, instance)
		}
	}
	return ""
}

func parseOpenVPNUnitFileFirst(templateUnit string) (workingDir, configTemplate string) {
	for _, dir := range systemdUnitSearchDirs {
		path := filepath.Join(dir, templateUnit)
		wd, cfg := parseOpenVPNUnitFile(path)
		if wd != "" || cfg != "" {
			return wd, cfg
		}
	}
	return "", ""
}

func configPathFromSystemdUnit(unit string) string {
	unit = strings.TrimSpace(unit)
	instance := openVPNInstanceFromUnit(unit)
	if instance == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	loadState, _, ok := serviceUnitState(ctx, unit)
	unitLoaded := ok && loadState != "" && loadState != "not-found"

	if unitLoaded {
		if p := configPathFromSystemdShow(ctx, unit, instance); p != "" {
			return p
		}
	}

	tpl := openVPNTemplateUnitName(unit)
	if tpl == "" {
		return ""
	}

	if tpl != unit {
		if p := configPathFromSystemdShow(ctx, tpl, instance); p != "" {
			return p
		}
	}
	return configPathFromInstalledUnitTemplate(tpl, instance)
}

func systemdUnitProperty(ctx context.Context, unit, property string) string {
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit, "--no-pager", "--property="+property)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	prefix := property + "="
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// effectiveServerConfigPaths returns the path to install and optional staged lookup dirs.
func effectiveServerConfigPaths(envConfPath, preferredUnit string) (confPath string, stagedDirs []string) {
	unit := DetectOpenVPNServiceUnit(preferredUnit)
	confPath = ResolveServerConfigPath(envConfPath, unit)
	seen := map[string]bool{}
	addDir := func(p string) {
		d := filepath.Dir(strings.TrimSpace(p))
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		stagedDirs = append(stagedDirs, d)
	}
	addDir(confPath)
	addDir(envConfPath)
	return confPath, stagedDirs
}

func findStagedServerConfig(envConfPath, preferredUnit string) (stagedPath, confPath string, err error) {
	confPath, _ = effectiveServerConfigPaths(envConfPath, preferredUnit)
	stagedPath = filepath.Join(filepath.Dir(confPath), stagedServerConfigName)
	if _, statErr := os.Stat(stagedPath); statErr == nil {
		return stagedPath, confPath, nil
	}
	return "", confPath, os.ErrNotExist
}
