package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const stagedServerConfigName = "~agent.server.conf"

// ManagedServerKeys — директивы server.conf, которыми управляет панель (остальные строки не трогаем).
var managedServerKeys = map[string]bool{
	"port": true, "proto": true, "dev": true, "topology": true,
	"local": true, "daemon": true, "mode": true,
	"server": true, "server-bridge": true, "max-clients": true, "keepalive": true,
	"ca": true, "cert": true, "key": true, "dh": true, "ecdh-curve": true,
	"tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "crl-verify": true,
	"remote-cert-tls": true, "verify-x509-name": true,
	"management": true, "status": true, "log": true, "log-append": true,
	"plugin": true, "up": true, "down": true,
	"persist-key": true, "persist-tun": true, "duplicate-cn": true, "client-to-client": true,
	"float": true, "data-ciphers": true, "tls-ciphersuites": true, "auth": true, "cipher": true,
	"tls-version-min": true, "verb": true, "mute": true, "mute-replay-warnings": true,
	"script-security": true, "reneg-sec": true, "hand-window": true, "tun-mtu": true,
	"mssfix": true, "fragment": true, "user": true, "group": true,
	"ifconfig-pool-persist": true, "comp-lzo": true, "allow-compression": true, "push": true, "route": true,
}

func firstToken(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}

func stripInlineComment(line string) string {
	inQuote := false
	escape := false
	for i, r := range line {
		if escape {
			escape = false
			continue
		}
		switch r {
		case '\\':
			escape = true
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

// ReadServerSettings читает server.conf и возвращает значения только для управляемых ключей.
func ReadServerSettings(confPath string) (map[string]any, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	out := map[string]any{}
	var pushLines []string
	var routeLines []string
	var pluginLines []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := stripInlineComment(sc.Text())
		tok := firstToken(line)
		if tok == "" {
			continue
		}
		if !managedServerKeys[tok] {
			continue
		}
		if tok == "push" {
			pushLines = append(pushLines, extractDirectiveValue(line, "push"))
			continue
		}
		if tok == "route" {
			routeLines = append(routeLines, extractDirectiveValue(line, "route"))
			continue
		}
		if tok == "plugin" {
			lineTrim := strings.TrimSpace(line)
			fields := strings.Fields(lineTrim)
			if len(fields) > 1 {
				prefix := fields[0]
				idx := strings.Index(lineTrim, prefix)
				if idx >= 0 {
					rest := strings.TrimSpace(lineTrim[idx+len(prefix):])
					if rest != "" {
						pluginLines = append(pluginLines, rest)
					}
				}
			}
			continue
		}
		if tok == "comp-lzo" {
			val := strings.TrimSpace(line[len(tok):])
			val = strings.Trim(val, `"`)
			if val == "" {
				out["comp-lzo"] = "yes"
			} else {
				out["comp-lzo"] = val
			}
			continue
		}
		if isBoolDirective(tok) {
			out[tok] = true
			continue
		}
		val := strings.TrimSpace(line[len(tok):])
		val = strings.Trim(val, `"`)
		out[tok] = val
	}
	if len(pushLines) > 0 {
		out["push"] = pushLines
	}
	if len(routeLines) > 0 {
		out["route"] = routeLines
	}
	if len(pluginLines) > 0 {
		out["plugin"] = pluginLines
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func extractDirectiveValue(line, key string) string {
	prefix := key
	rest := strings.TrimSpace(line[len(prefix):])
	rest = strings.TrimSpace(rest)
	if len(rest) >= 2 && rest[0] == '"' {
		end := strings.Index(rest[1:], `"`)
		if end >= 0 {
			return rest[1 : end+1]
		}
	}
	return rest
}

func isBoolDirective(tok string) bool {
	switch tok {
	case "persist-key", "persist-tun", "duplicate-cn", "client-to-client", "float", "mute-replay-warnings", "daemon":
		return true
	default:
		return false
	}
}

// multiTokenDirective — значение может содержать несколько токенов; не заключаем всё значение в одну пару кавычек.
func multiTokenDirective(k string) bool {
	switch k {
	case "server", "server-bridge", "keepalive", "tls-auth", "management", "status", "verify-x509-name", "local", "mode":
		return true
	default:
		return false
	}
}

// Порядок вывода управляемых директив (стабильный diff).
var settingsWriteOrder = []string{
	"port", "proto", "dev", "topology", "local", "daemon", "mode",
	"server", "server-bridge", "max-clients", "keepalive",
	"ca", "cert", "key", "dh", "ecdh-curve",
	"tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify",
	"remote-cert-tls", "verify-x509-name",
	"management", "status", "log", "log-append",
	"plugin", "up", "down",
	"persist-key", "persist-tun", "duplicate-cn", "client-to-client", "float",
	"data-ciphers", "tls-ciphersuites", "cipher", "auth", "tls-version-min",
	"verb", "mute", "mute-replay-warnings", "script-security", "reneg-sec", "hand-window",
	"tun-mtu", "mssfix", "fragment", "user", "group", "ifconfig-pool-persist", "comp-lzo", "allow-compression",
	"push", "route",
}

// MergeServerSettings оставляет неуправляемые строки как есть,
// а управляемые записывает в фиксированном порядке settingsWriteOrder.
func MergeServerSettings(confPath string, settings map[string]any) ([]byte, error) {
	var kept []string
	if _, err := os.Stat(confPath); err == nil {
		f, err := os.Open(confPath)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			raw := sc.Text()
			if strings.Contains(strings.ToLower(raw), "ovpn control: managed directives") {
				continue
			}
			line := stripInlineComment(raw)
			tok := firstToken(line)
			if tok != "" && managedServerKeys[tok] {
				continue
			}
			kept = append(kept, raw)
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	norm := map[string]any{}
	for key, val := range settings {
		k := strings.ToLower(strings.TrimSpace(key))
		norm[k] = val
	}

	var managed []string
	for _, k := range settingsWriteOrder {
		val, ok := norm[k]
		if !ok || val == nil || !managedServerKeys[k] {
			continue
		}
		managed = append(managed, buildManagedDirectiveLines(k, val)...)
	}

	var b strings.Builder
	for _, ln := range kept {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	if len(kept) > 0 && len(managed) > 0 && strings.TrimSpace(kept[len(kept)-1]) != "" {
		b.WriteByte('\n')
	}
	for _, ln := range managed {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func buildManagedDirectiveLines(k string, val any) []string {
	switch k {
	case "push":
		var out []string
		for _, item := range toStringSlice(val) {
			s := strings.TrimSpace(item)
			if s != "" {
				out = append(out, fmt.Sprintf("push %q", s))
			}
		}
		return out
	case "route":
		var out []string
		for _, item := range toStringSlice(val) {
			s := strings.TrimSpace(item)
			if s != "" {
				out = append(out, fmt.Sprintf("route %q", s))
			}
		}
		return out
	case "plugin":
		var out []string
		for _, item := range toStringSlice(val) {
			s := strings.TrimSpace(item)
			if s != "" {
				out = append(out, "plugin "+s)
			}
		}
		return out
	default:
		if isBoolDirective(k) {
			if isTruthy(val) {
				return []string{k}
			}
			return nil
		}
		s := strings.TrimSpace(fmt.Sprint(val))
		if s == "" {
			return nil
		}
		if strings.ContainsAny(s, " \t\"") && !multiTokenDirective(k) {
			return []string{fmt.Sprintf("%s %q", k, s)}
		}
		return []string{k + " " + s}
	}
}

func toStringSlice(val any) []string {
	switch x := val.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, v := range x {
			out = append(out, fmt.Sprint(v))
		}
		return out
	case []string:
		return x
	default:
		s := strings.TrimSpace(fmt.Sprint(val))
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
}

func isTruthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x == "1" || strings.EqualFold(x, "yes")
	case float64:
		return x != 0
	case json.Number:
		i, _ := x.Int64()
		return i != 0
	default:
		return v != nil
	}
}

// ValidateOpenVPNConfig запускает openvpn с конфигом; при ошибках парсинга процесс обычно сразу пишет в stderr.
func ValidateOpenVPNConfig(ctx context.Context, openvpnBin, configPath string) (hints []string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, openvpnBin, "--config", configPath, "--verb", "4")

	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out

	startErr := cmd.Start()
	if startErr != nil {
		return []string{
			"Убедитесь, что бинарник OpenVPN установлен и путь OPENVPN_BINARY верен.",
			"Проверьте права пользователя, под которым запущен агент (нужен запуск openvpn).",
		}, fmt.Errorf("openvpn start: %w", startErr)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		waitErr = ctx.Err()
	}

	text := strings.ToLower(out.String())
	if strings.Contains(text, "options error") || strings.Contains(text, "fatal") ||
		strings.Contains(text, "errno=") && strings.Contains(text, "error") {
		hints = hintsForOpenVPNOutput(out.String())
		if len(hints) == 0 {
			hints = []string{
				"Проверьте синтаксис директив в официальной документации OpenVPN для вашей версии.",
				"Убедитесь, что пути к ca/cert/key/dh/tls-crypt в конфиге существуют на сервере.",
			}
		}
		return hints, errors.New(strings.TrimSpace(out.String()))
	}

	if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) && !errors.Is(waitErr, context.Canceled) {
		// быстрый ненулевой код без явного FATAL
		if strings.TrimSpace(out.String()) != "" {
			return hintsForOpenVPNOutput(out.String()), fmt.Errorf("openvpn: %w — %s", waitErr, strings.TrimSpace(out.String()))
		}
	}

	// Таймаут без явной ошибки — считаем, что конфиг принят (сервер пошёл в работу / завис на bind).
	return nil, nil
}

func BuildOpenVPNCheckCommand(openvpnBin, configPath string) string {
	bin := strings.TrimSpace(openvpnBin)
	if bin == "" {
		bin = "openvpn"
	}
	return fmt.Sprintf("%s --config %s --verb 4", bin, configPath)
}

func hintsForOpenVPNOutput(log string) []string {
	low := strings.ToLower(log)
	var h []string
	if strings.Contains(low, "tls") && strings.Contains(low, "error") {
		h = append(h, "Проверьте tls-version-min, data-ciphers и tls-ciphersuites на совместимость с клиентами.")
	}
	if strings.Contains(low, "cannot resolve") || strings.Contains(low, "resolv") {
		h = append(h, "Проверьте DNS и имена хостов в remote/ifconfig.")
	}
	if strings.Contains(low, "permission denied") || strings.Contains(low, "access denied") {
		h = append(h, "Проверьте права на файлы сертификатов, ключей и каталога /var/log/openvpn.")
	}
	if strings.Contains(low, "address already in use") || strings.Contains(low, "bind") {
		h = append(h, "Порт занят: смените port/proto или остановите другой процесс на этом порту.")
	}
	if strings.Contains(low, "cipher") || strings.Contains(low, "crypto") {
		h = append(h, "Несовместимый cipher: для OpenVPN 2.5+ используйте data-ciphers (например AES-256-GCM:AES-128-GCM).")
	}
	if strings.Contains(low, "mtu") {
		h = append(h, "Попробуйте уменьшить tun-mtu или включить/настроить fragment/mssfix.")
	}
	if len(h) == 0 {
		h = append(h, "Сохраните вывод журнала OpenVPN и сверьте последнюю добавленную директиву с документацией.")
	}
	return h
}

// ApplyServerSettings пишет черновой конфиг во временный файл рядом с рабочим и проверяет его OpenVPN.
func ApplyServerSettings(confPath, openvpnBin string, settings map[string]any) (tmpPath string, hints []string, err error) {
	data, err := MergeServerSettings(confPath, settings)
	if err != nil {
		return "", nil, err
	}
	dir := filepath.Dir(confPath)
	tmp := filepath.Join(dir, stagedServerConfigName)
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", nil, fmt.Errorf("write temp config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if h, vErr := ValidateOpenVPNConfig(ctx, openvpnBin, tmp); vErr != nil {
		return tmp, h, vErr
	}
	return tmp, nil, nil
}

func backupSuffixNow() string {
	return time.Now().Format("20060102150405")
}

func createConfigBackup(confPath string) (string, error) {
	backup := confPath + "." + backupSuffixNow()
	original, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("read current config: %w", err)
	}
	if err := os.WriteFile(backup, original, 0o600); err != nil {
		return "", fmt.Errorf("write backup config: %w", err)
	}
	return backup, nil
}

type ApplyConfigResult struct {
	BackupPath string
	Output     string
	ServiceLog string
}

type ApplyConfigFailure struct {
	Err        error
	Hints      []string
	Output     string
	ServiceLog string
	RolledBack bool
	BackupPath string
}

func (e *ApplyConfigFailure) Error() string {
	if e == nil || e.Err == nil {
		return "apply config failed"
	}
	return e.Err.Error()
}

func ApplyStagedServerConfig(confPath, stagedPath, restartCommand, serviceUnit string) (*ApplyConfigResult, error) {
	backupPath, err := createConfigBackup(confPath)
	if err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("backup: %w", err),
			Hints: []string{"Проверьте права записи в каталог конфигурации OpenVPN."},
		}
	}

	stagedData, err := os.ReadFile(stagedPath)
	if err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("read staged config: %w", err),
			Hints: []string{"Временный конфиг не найден. Сохраните настройки и проверьте конфигурацию заново."},
		}
	}
	if err := os.WriteFile(confPath, stagedData, 0o600); err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("install config: %w", err),
			Hints: []string{"Проверьте права записи в каталог конфигурации OpenVPN."},
		}
	}
	_ = os.Remove(stagedPath)

	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, restartErr := runShellCommand(ctx, restartCommand)
	serviceLog := readRestartLogsSince(confPath, startedAt, serviceUnit)
	if restartErr == nil {
		return &ApplyConfigResult{
			BackupPath: backupPath,
			Output:     output,
			ServiceLog: serviceLog,
		}, nil
	}

	rollbackErr := restoreConfigFromBackup(confPath, backupPath)
	rolledBack := rollbackErr == nil

	hints := []string{"Не удалось применить конфигурацию: выполнен откат к предыдущему файлу."}
	if !rolledBack {
		hints = append(hints, "Откат завершился с ошибкой — проверьте права доступа к конфигурационным файлам.")
	}
	return nil, &ApplyConfigFailure{
		Err:        fmt.Errorf("restart openvpn service: %w", restartErr),
		Hints:      hints,
		Output:     output,
		ServiceLog: serviceLog,
		RolledBack: rolledBack,
		BackupPath: backupPath,
	}
}

func readRestartLogsSince(confPath string, since time.Time, serviceUnit string) string {
	var parts []string
	if fp := readOpenVPNLogFileTail(confPath); fp != "" {
		parts = append(parts, fp)
	}
	if j := readServiceLogsSince(since, serviceUnit); j != "" {
		parts = append(parts, j)
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

func readOpenVPNLogFileTail(confPath string) string {
	logPath, ok, err := detectLogPathFromConfig(confPath)
	if err != nil || !ok || strings.TrimSpace(logPath) == "" {
		return ""
	}
	tail, err := readFileTail(logPath, 200, 256*1024)
	if err != nil {
		return ""
	}
	return tail
}

func readFileTail(path string, maxLines, maxBytes int) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if maxBytes > 0 && len(raw) > maxBytes {
		raw = raw[len(raw)-maxBytes:]
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}

func restoreConfigFromBackup(confPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	if err := os.WriteFile(confPath, data, 0o600); err != nil {
		return fmt.Errorf("write restored config: %w", err)
	}
	return nil
}

func readServiceLogsSince(since time.Time, serviceUnit string) string {
	unit := strings.TrimSpace(serviceUnit)
	if unit == "" {
		return ""
	}
	sinceArg := since.Format("2006-01-02 15:04:05")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(
		ctx,
		"journalctl",
		"-u",
		unit,
		"--since",
		sinceArg,
		"--no-pager",
		"-n",
		"200",
	).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}
