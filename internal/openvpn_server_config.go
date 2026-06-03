package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	stagedServerConfigName = "~agent.server.conf"
	checkServerConfigName  = "~agent.check.conf"
)

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
		if k == "fragment" {
			if n, err := strconv.ParseFloat(s, 64); err == nil && n == 0 {
				return nil
			}
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

// writeMutatedCheckConfig writes a temp config with fixes applied (auth/fragment/group/cipher).
func writeMutatedCheckConfig(src, serviceUnit string) (path string, cleanup func(), err error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", nil, err
	}
	data = mutateConfigForOpenVPN(data, serviceUnit)
	if openVPNServiceIsActive(serviceUnit) {
		data = rewriteValidateInstanceOverrides(data)
	}
	tmp := filepath.Join(filepath.Dir(src), checkServerConfigName)
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", nil, err
	}
	return tmp, func() { _ = os.Remove(tmp) }, nil
}

const (
	openvpnValidateCheckPort      = 61194
	openvpnValidateManagementPort = 7506
	openvpnValidateDev            = "tun99"
	openvpnValidateTapDev         = "tap99"
)

// ValidateOpenVPNConfig запускает openvpn с конфигом; при ошибках парсинга процесс обычно сразу пишет в stderr.
// extraArgs — флаги из systemd ExecStart (--cipher/--data-ciphers), чтобы проверка совпадала с restart службы.
// output — полный stdout/stderr OpenVPN (для UI); err — краткое сообщение.
func ValidateOpenVPNConfig(ctx context.Context, openvpnBin, configPath string, extraArgs []string) (hints []string, output string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	absConfig, absErr := filepath.Abs(configPath)
	if absErr != nil {
		absConfig = configPath
	}
	args := []string{openvpnBin}
	args = append(args, extraArgs...)
	args = append(args, "--config", absConfig, "--verb", "4")
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = filepath.Dir(absConfig)

	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out

	startErr := cmd.Start()
	if startErr != nil {
		return []string{
			"Убедитесь, что бинарник OpenVPN установлен и путь OPENVPN_BINARY верен.",
			"Проверьте права пользователя, под которым запущен агент (нужен запуск openvpn).",
		}, "", fmt.Errorf("openvpn start: %w", startErr)
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

	rawOut := out.String()
	text := strings.ToLower(rawOut)
	if strings.Contains(text, "options error") || strings.Contains(text, "exiting due to fatal error") ||
		(strings.Contains(text, "errno=") && strings.Contains(text, "error")) {
		hints = hintsForOpenVPNOutput(rawOut)
		if len(hints) == 0 {
			hints = []string{
				"Проверьте синтаксис директив в официальной документации OpenVPN для вашей версии.",
				"Убедитесь, что пути к ca/cert/key/dh/tls-crypt в конфиге существуют на сервере.",
			}
		}
		return hints, rawOut, errors.New(extractOpenVPNFatalMessage(rawOut))
	}

	if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) && !errors.Is(waitErr, context.Canceled) {
		// быстрый ненулевой код без явного FATAL
		if strings.TrimSpace(rawOut) != "" {
			return hintsForOpenVPNOutput(rawOut), rawOut, fmt.Errorf("openvpn: %w — %s", waitErr, strings.TrimSpace(rawOut))
		}
	}

	// Таймаут без явной ошибки — считаем, что конфиг принят (сервер пошёл в работу / завис на bind).
	return nil, rawOut, nil
}

func BuildOpenVPNCheckCommand(openvpnBin, configPath string, extraArgs []string) string {
	bin := strings.TrimSpace(openvpnBin)
	if bin == "" {
		bin = "openvpn"
	}
	var b strings.Builder
	b.WriteString(bin)
	for _, a := range extraArgs {
		if strings.ContainsAny(a, " \t") {
			b.WriteString(" ")
			b.WriteString(strconv.Quote(a))
		} else {
			b.WriteString(" ")
			b.WriteString(a)
		}
	}
	b.WriteString(" --config ")
	b.WriteString(configPath)
	b.WriteString(" --verb 4")
	return b.String()
}

func extractOpenVPNFatalMessage(log string) string {
	lines := strings.Split(strings.ReplaceAll(log, "\r\n", "\n"), "\n")
	var (
		optionsErr string
		fatalLine  string
		beforeExit string
	)
	for i, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		low := strings.ToLower(s)
		if strings.Contains(low, "options error") {
			optionsErr = s
		}
		if strings.Contains(low, "failed to find gid") || strings.Contains(low, "failed to find uid") {
			return s
		}
		if strings.Contains(low, "exiting due to fatal error") {
			fatalLine = s
			if i > 0 {
				prev := strings.TrimSpace(lines[i-1])
				if prev != "" && !strings.Contains(strings.ToLower(prev), "exiting due to fatal") {
					beforeExit = prev
				}
			}
		}
	}
	if optionsErr != "" {
		return optionsErr
	}
	if beforeExit != "" && fatalLine != "" {
		return beforeExit + " — " + fatalLine
	}
	if beforeExit != "" {
		return beforeExit
	}
	if fatalLine != "" {
		return fatalLine
	}
	return strings.TrimSpace(log)
}

func hintsForOpenVPNOutput(log string) []string {
	low := strings.ToLower(log)
	var h []string
	if strings.Contains(low, "failed to find gid") || strings.Contains(low, "failed to find uid") {
		h = append(h, "На RHEL/Alma/Rocky/CentOS укажите group nobody (не nogroup). На Debian/Ubuntu — nogroup. Либо очистите поля user/group в настройках панели.")
		return h
	}
	if strings.Contains(low, "options error") && strings.Contains(low, "tls") {
		h = append(h, "Проверьте tls-version-min, data-ciphers и tls-ciphersuites на совместимость с клиентами.")
	}
	if strings.Contains(low, "cannot resolve") || strings.Contains(low, "resolv") {
		h = append(h, "Проверьте DNS и имена хостов в remote/ifconfig.")
	}
	if strings.Contains(low, "permission denied") || strings.Contains(low, "access denied") {
		h = append(h, "Проверьте права на файлы сертификатов, ключей и каталога /var/log/openvpn.")
	}
	if strings.Contains(low, "address already in use") || strings.Contains(low, "errno=98") {
		h = append(h, "Порт занят: OpenVPN уже запущен. Агент проверяет конфиг на отдельном порту — обновите openvpn-control-agent.")
	}
	if strings.Contains(low, "tunsetiff") || strings.Contains(low, "device or resource busy") || strings.Contains(low, "errno=16") {
		h = append(h, "Интерфейс TUN/TAP занят работающим OpenVPN. Проверка должна использовать отдельный dev (tun99) — обновите openvpn-control-agent.")
		return h
	}
	if strings.Contains(low, "must define dh") || strings.Contains(low, "--dh") {
		h = append(h, "Задайте директиву dh (путь к файлу DH) в настройках OpenVPN и создайте/импортируйте DH на вкладке «Сертификаты и ключи» (обычно /etc/openvpn/dh.pem).")
	}
	if strings.Contains(low, "must define ca") || strings.Contains(low, "--ca") || strings.Contains(low, "--capath") {
		h = append(h, "Задайте директиву ca (путь к корневому сертификату), привяжите корневой УЦ к серверу и укажите ca /etc/openvpn/ca.crt — затем дождитесь задачи openvpn_ca_sync.")
	}
	if strings.Contains(low, "must define cert") || strings.Contains(low, "--cert") {
		h = append(h, "Выпустите сертификат сервера на вкладке «Сертификаты и ключи» и укажите cert/key (обычно /etc/openvpn/server.crt и server.key).")
	}
	if strings.Contains(low, "options error") && (strings.Contains(low, "cipher") || strings.Contains(low, "must define")) {
		h = append(h, "Для OpenVPN 2.5+ укажите data-ciphers (например AES-256-GCM:AES-128-GCM) и не используйте устаревший cipher.")
	}
	if strings.Contains(low, "options error") && strings.Contains(low, "auth") {
		h = append(h, "При шифрах AES-*-GCM в data-ciphers уберите директиву auth из server.conf (панель больше не добавляет auth SHA256 для GCM).")
	}
	if strings.Contains(low, "management") {
		h = append(h, "Management: формат «IP порт» через пробел, например 127.0.0.1 7505 (не 127.0.0.1:7505).")
	}
	if strings.Contains(low, "options error") &&
		(strings.Contains(low, "fragment") || strings.Contains(low, "mssfix") || strings.Contains(low, "tun-mtu")) {
		h = append(h, "Уберите fragment 0 из конфига; для mssfix/fragment задайте ненулевые значения или очистите поля в панели.")
	}
	if strings.Contains(low, "options error") && (strings.Contains(low, "cipher") || strings.Contains(low, "data-ciphers")) {
		h = append(h, "На RHEL unit openvpn-server@ часто задаёт --cipher и --data-ciphers в ExecStart — не дублируйте cipher/data-ciphers в server.conf.")
	}
	if len(h) == 0 {
		h = append(h, "Сохраните вывод журнала OpenVPN и сверьте последнюю добавленную директиву с документацией.")
	}
	return h
}

// normalizeRuntimeUserGroup подставляет существующую на узле группу (nogroup на Debian, nobody на RHEL).
func normalizeRuntimeUserGroup(settings map[string]any) {
	if settings == nil {
		return
	}
	g := strings.TrimSpace(fmt.Sprint(settings["group"]))
	if g == "" {
		return
	}
	if _, err := user.LookupGroup(g); err == nil {
		return
	}
	for _, fallback := range []string{"nobody", "nogroup"} {
		if fallback == g {
			continue
		}
		if _, err := user.LookupGroup(fallback); err == nil {
			settings["group"] = fallback
			return
		}
	}
	delete(settings, "group")
}

func rewriteInvalidGroupInConfig(data []byte) []byte {
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := stripInlineComment(raw)
		tok := firstToken(line)
		if tok == "group" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				g := fields[1]
				if _, err := user.LookupGroup(g); err != nil {
					for _, fallback := range []string{"nobody", "nogroup"} {
						if fallback == g {
							continue
						}
						if _, err2 := user.LookupGroup(fallback); err2 == nil {
							out = append(out, "group "+fallback)
							continue
						}
					}
					continue
				}
			}
		}
		out = append(out, raw)
	}
	return []byte(strings.Join(out, "\n"))
}

// StageServerSettings пишет черновой server.conf без запуска openvpn (для apply).
func StageServerSettings(confPath, serviceUnit string, settings map[string]any) (tmpPath string, err error) {
	normalizeServerSettings(settings, serviceUnit)
	data, err := MergeServerSettings(confPath, settings)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(confPath)
	tmp := filepath.Join(dir, stagedServerConfigName)
	if err := os.WriteFile(tmp, mutateConfigForOpenVPN(data, serviceUnit), 0o600); err != nil {
		return "", fmt.Errorf("write temp config: %w", err)
	}
	return tmp, nil
}

// ApplyServerSettings пишет черновой конфиг и проверяет его запуском openvpn (кнопка «Проверить» / save с validate).
func ApplyServerSettings(confPath, openvpnBin, serviceUnit string, settings map[string]any) (tmpPath string, hints []string, err error) {
	tmp, err := StageServerSettings(confPath, serviceUnit, settings)
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	extra := execStartCryptoArgsForValidate(serviceUnit)
	if h, _, vErr := ValidateOpenVPNConfig(ctx, openvpnBin, tmp, extra); vErr != nil {
		return tmp, h, vErr
	}
	return tmp, nil, nil
}

func validateDevNameFromConfig(data []byte) string {
	for _, raw := range strings.Split(string(data), "\n") {
		tok := firstToken(stripInlineComment(raw))
		if tok != "dev" {
			continue
		}
		fields := strings.Fields(stripInlineComment(raw))
		if len(fields) >= 2 && strings.HasPrefix(strings.ToLower(fields[1]), "tap") {
			return openvpnValidateTapDev
		}
		break
	}
	return openvpnValidateDev
}

func rewriteValidateInstanceOverrides(data []byte) []byte {
	devName := validateDevNameFromConfig(data)
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		tok := firstToken(stripInlineComment(raw))
		if tok == "port" || tok == "management" || tok == "status" || tok == "dev" {
			continue
		}
		out = append(out, raw)
	}
	out = append(out,
		"",
		"# openvpn-control: validate-only (production OpenVPN is already running)",
		"dev "+devName,
		fmt.Sprintf("port %d", openvpnValidateCheckPort),
		fmt.Sprintf("management 127.0.0.1 %d", openvpnValidateManagementPort),
	)
	return []byte(strings.Join(out, "\n"))
}

func backupSuffixNow() string {
	return time.Now().Format("20060102150405")
}

func createConfigBackup(confPath string) (string, error) {
	if _, err := os.Stat(confPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat current config: %w", err)
	}
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
	stagedData = mutateConfigForOpenVPN(stagedData, serviceUnit)
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("create config dir: %w", err),
			Hints: []string{"Создайте каталог " + filepath.Dir(confPath) + " или проверьте OPENVPN_SERVER_CONF на агенте."},
		}
	}
	if err := os.WriteFile(confPath, stagedData, 0o600); err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("install config: %w", err),
			Hints: []string{"Проверьте права записи в каталог конфигурации OpenVPN."},
		}
	}
	_ = os.Remove(stagedPath)

	if _, err := os.Stat(confPath); err != nil {
		return nil, &ApplyConfigFailure{
			Err:   fmt.Errorf("config missing after install: %w", err),
			Hints: []string{"Файл конфигурации не найден по пути " + confPath + ". Проверьте OPENVPN_SERVER_CONF и unit " + serviceUnit + "."},
		}
	}

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

	var rolledBack bool
	if strings.TrimSpace(backupPath) != "" {
		rollbackErr := restoreConfigFromBackup(confPath, backupPath)
		rolledBack = rollbackErr == nil
	}

	hints := []string{"Не удалось перезапустить OpenVPN после установки конфигурации."}
	hints = append(hints, "Конфиг записан в "+confPath+". Проверьте: systemctl cat "+serviceUnit)
	if skip := openVPNConfigKeysSetOnExecStart(serviceUnit); len(skip) > 0 {
		var keys []string
		for k := range skip {
			keys = append(keys, k)
		}
		hints = append(hints, "В unit systemd уже заданы параметры "+strings.Join(keys, ", ")+
			" — они не дублируются в server.conf.")
	}
	if detail := extractOpenVPNFatalMessage(serviceLog); detail != "" && !strings.Contains(strings.ToLower(detail), "exiting due to fatal error") {
		hints = append(hints, detail)
	} else if detail := extractOpenVPNFatalMessage(serviceLog + "\n" + output); detail != "" {
		hints = append(hints, detail)
	}
	if rolledBack {
		hints = append(hints, "Выполнен откат к предыдущему server.conf.")
	} else if strings.TrimSpace(backupPath) == "" {
		hints = append(hints, "Первичная установка: файл конфигурации оставлен на диске — исправьте ошибки и примените снова.")
	} else if !rolledBack {
		hints = append(hints, "Откат не удался — проверьте права на "+filepath.Dir(confPath)+".")
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
