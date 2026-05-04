package internal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type OpenVPNRuntimeInfo struct {
	AgentVersion      string   `json:"agentVersion"`
	Available         bool     `json:"available"`
	Running           bool     `json:"running"`
	BinaryPath        string   `json:"binaryPath"`
	Version           string   `json:"version"`
	Build             string   `json:"build"`
	ConfigPath        string   `json:"configPath"`
	ServerLogPath     string   `json:"serverLogPath"`
	ManagementAddr    string   `json:"managementAddr"`
	ServiceUnit       string   `json:"serviceUnit"`
	ActiveState       string   `json:"activeState"`
	SubState          string   `json:"subState"`
	MainPID           int      `json:"mainPid"`
	ActiveSince       string   `json:"activeSince"`
	LogsEnabled       bool     `json:"logsEnabled"`
	LogsNote          string   `json:"logsNote,omitempty"`
	RecentLogs        []string `json:"recentLogs"`
	CompressedLogsB64 string   `json:"compressedLogsB64,omitempty"`
	LastError         string   `json:"lastError,omitempty"`
}

var (
	logOffsetsMu sync.Mutex
	logOffsets   = map[string]int64{}
)

const (
	maxLogLinesPerSync = 1000
	maxRawLogBytesPerSync = 8 * 1024 * 1024 // 8 MB raw lines per poll
)

func DetectOpenVPNRuntimeInfo(ctx context.Context, bin, confPath, serverLogPath, mgmtAddr, serviceUnit string, mgmt *OpenVPNManagement) OpenVPNRuntimeInfo {
	info := OpenVPNRuntimeInfo{
		AgentVersion:   AgentVersion,
		ConfigPath:     confPath,
		ManagementAddr: mgmtAddr,
		ServiceUnit:    strings.TrimSpace(serviceUnit),
	}
	info.ServiceUnit = detectOpenVPNServiceUnit(info.ServiceUnit)

	if bin == "" {
		bin = "openvpn"
	}

	resolved, err := exec.LookPath(bin)
	if err != nil {
		info.LastError = "openvpn binary not found in PATH"
		return info
	}
	info.Available = true
	info.BinaryPath = resolved

	cmdCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, resolved, "--version").CombinedOutput()
	if err != nil {
		info.LastError = strings.TrimSpace(string(out))
		if info.LastError == "" {
			info.LastError = err.Error()
		}
	} else {
		lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
		nonEmpty := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				nonEmpty = append(nonEmpty, line)
			}
		}
		if len(nonEmpty) > 0 {
			info.Version = nonEmpty[0]
		}
		if len(nonEmpty) > 1 {
			info.Build = nonEmpty[1]
		}
	}

	if mgmt != nil {
		mgmtCtx, cancelMgmt := context.WithTimeout(ctx, 3*time.Second)
		defer cancelMgmt()
		if _, err := mgmt.GetClients(mgmtCtx); err == nil {
			info.Running = true
		}
	}

	resolveServerLogPath(&info, serverLogPath)
	detectOpenVPNServiceState(ctx, &info)
	collectIncrementalServerLogs(&info)
	return info
}

func resolveServerLogPath(info *OpenVPNRuntimeInfo, overridePath string) {
	overridePath = strings.TrimSpace(overridePath)
	if overridePath != "" {
		info.ServerLogPath = overridePath
		info.LogsEnabled = true
		return
	}
	if strings.TrimSpace(info.ConfigPath) == "" {
		info.LogsEnabled = false
		info.LogsNote = "log file is not configured (empty OPENVPN_SERVER_CONF)"
		return
	}
	path, ok, err := detectLogPathFromConfig(info.ConfigPath)
	if err != nil {
		info.LogsEnabled = false
		info.LogsNote = fmt.Sprintf("log file detect failed: %v", err)
		return
	}
	if !ok || strings.TrimSpace(path) == "" {
		info.LogsEnabled = false
		info.LogsNote = "OpenVPN server logs are not enabled in config (log/log-append not set)"
		return
	}
	info.ServerLogPath = path
	info.LogsEnabled = true
}

func detectLogPathFromConfig(confPath string) (string, bool, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	last := ""
	baseDir := filepath.Dir(confPath)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		if key != "log" && key != "log-append" {
			continue
		}
		p := strings.Trim(strings.Join(parts[1:], " "), `"'`)
		if p != "" {
			last = p
		}
	}
	if err := sc.Err(); err != nil {
		return "", false, err
	}
	if last == "" {
		return "", false, nil
	}
	if !filepath.IsAbs(last) {
		last = filepath.Join(baseDir, last)
	}
	return last, true, nil
}

func collectIncrementalServerLogs(info *OpenVPNRuntimeInfo) {
	if !info.LogsEnabled {
		return
	}
	logPath := strings.TrimSpace(info.ServerLogPath)
	if logPath == "" {
		info.LogsEnabled = false
		info.LogsNote = "OpenVPN server logs are not enabled in config (log/log-append not set)"
		return
	}

	file, err := os.Open(logPath)
	if err != nil {
		if info.LastError == "" {
			info.LastError = fmt.Sprintf("openvpn log read failed: %v", err)
		}
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		if info.LastError == "" {
			info.LastError = fmt.Sprintf("openvpn log stat failed: %v", err)
		}
		return
	}
	size := stat.Size()

	logOffsetsMu.Lock()
	offset := logOffsets[logPath]
	seen := offset > 0
	if offset < 0 || offset > size {
		offset = 0
		seen = false
	}
	logOffsetsMu.Unlock()

	if !seen {
		lines := make([]string, 0, maxLogLinesPerSync)
		bytesRead := 0
		truncated := false
		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				bytesRead += len(line) + 1
				if bytesRead > maxRawLogBytesPerSync {
					truncated = true
					break
				}
				if len(lines) < maxLogLinesPerSync {
					lines = append(lines, line)
				} else {
					copy(lines, lines[1:])
					lines[len(lines)-1] = line
				}
			}
		}
		if err := scanner.Err(); err != nil {
			if info.LastError == "" {
				info.LastError = fmt.Sprintf("openvpn log parse failed: %v", err)
			}
			return
		}
		info.RecentLogs = lines
		if truncated {
			info.LogsNote = "Логи ограничены: прочитан только безопасный объём за один опрос."
		}
		logOffsetsMu.Lock()
		if pos, seekErr := file.Seek(0, 1); seekErr == nil {
			logOffsets[logPath] = pos
		} else {
			logOffsets[logPath] = size
		}
		logOffsetsMu.Unlock()
		return
	}

	if _, err := file.Seek(offset, 0); err != nil {
		if info.LastError == "" {
			info.LastError = fmt.Sprintf("openvpn log seek failed: %v", err)
		}
		return
	}

	lines := make([]string, 0, maxLogLinesPerSync)
	firstBatch := make([]string, 0, maxLogLinesPerSync)
	total := 0
	bytesRead := 0
	truncated := false
	var gzBuf bytes.Buffer
	var gzWriter *gzip.Writer
	compressing := false
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			bytesRead += len(line) + 1
			if bytesRead > maxRawLogBytesPerSync {
				truncated = true
				break
			}
			total++
			if len(lines) < maxLogLinesPerSync {
				lines = append(lines, line)
			} else {
				copy(lines, lines[1:])
				lines[len(lines)-1] = line
			}

			if !compressing {
				if len(firstBatch) < maxLogLinesPerSync {
					firstBatch = append(firstBatch, line)
				} else {
					compressing = true
					gzWriter = gzip.NewWriter(&gzBuf)
					for _, ln := range firstBatch {
						_, _ = gzWriter.Write([]byte(ln))
						_, _ = gzWriter.Write([]byte{'\n'})
					}
					_, _ = gzWriter.Write([]byte(line))
					_, _ = gzWriter.Write([]byte{'\n'})
				}
			} else {
				_, _ = gzWriter.Write([]byte(line))
				_, _ = gzWriter.Write([]byte{'\n'})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		if info.LastError == "" {
			info.LastError = fmt.Sprintf("openvpn log parse failed: %v", err)
		}
		return
	}

	if compressing && gzWriter != nil {
		_ = gzWriter.Close()
		info.CompressedLogsB64 = base64.StdEncoding.EncodeToString(gzBuf.Bytes())
		info.RecentLogs = nil
	} else if total > maxLogLinesPerSync {
		// Safety fallback (should not happen): send whatever tail is available.
		info.RecentLogs = lines
	} else {
		info.RecentLogs = lines
	}
	if truncated {
		info.LogsNote = "Логи ограничены: превышен безопасный объём за один опрос."
	}

	newOffset, seekErr := file.Seek(0, 1)
	if seekErr != nil {
		newOffset = size
	}
	logOffsetsMu.Lock()
	logOffsets[logPath] = newOffset
	logOffsetsMu.Unlock()
}

func detectOpenVPNServiceState(ctx context.Context, info *OpenVPNRuntimeInfo) {
	unit := strings.TrimSpace(info.ServiceUnit)
	if unit == "" {
		unit = "openvpn.service"
	}
	info.ServiceUnit = unit

	showCtx, cancelShow := context.WithTimeout(ctx, 4*time.Second)
	defer cancelShow()
	showOut, err := exec.CommandContext(
		showCtx,
		"systemctl",
		"show",
		unit,
		"--no-pager",
		"--property=ActiveState,SubState,MainPID,ActiveEnterTimestamp",
	).CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.ReplaceAll(string(showOut), "\r\n", "\n"), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ActiveState=") {
				info.ActiveState = strings.TrimPrefix(line, "ActiveState=")
			} else if strings.HasPrefix(line, "SubState=") {
				info.SubState = strings.TrimPrefix(line, "SubState=")
			} else if strings.HasPrefix(line, "MainPID=") {
				v := strings.TrimPrefix(line, "MainPID=")
				if v != "" && v != "0" {
					var pid int
					_, _ = fmt.Sscanf(v, "%d", &pid)
					info.MainPID = pid
				}
			} else if strings.HasPrefix(line, "ActiveEnterTimestamp=") {
				info.ActiveSince = strings.TrimPrefix(line, "ActiveEnterTimestamp=")
			}
		}
	}
}
