package internal

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type VPNClient struct {
	ID          string `json:"id"`
	CommonName  string `json:"commonName"`
	RemoteIP    string `json:"remoteIp"`
	VirtualIP   string `json:"virtualIp"`
	ConnectedAt string `json:"connectedAt"`
	RxBytes     uint64 `json:"rxBytes"`
	TxBytes     uint64 `json:"txBytes"`
}

type OpenVPNManagement struct {
	Addr    string
	Timeout time.Duration
}

func (m *OpenVPNManagement) dial(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	dialer := &net.Dialer{Timeout: m.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", m.Addr)
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // INFO banner
	return conn, reader, nil
}

func (m *OpenVPNManagement) runStatus(ctx context.Context) ([]string, error) {
	conn, reader, err := m.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err = fmt.Fprint(conn, "status 3\n"); err != nil {
		return nil, err
	}

	var lines []string
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil, readErr
		}
		line = strings.TrimSpace(line)
		if line == "END" {
			break
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func (m *OpenVPNManagement) GetClients(ctx context.Context) ([]VPNClient, error) {
	lines, err := m.runStatus(ctx)
	if err != nil {
		return nil, err
	}
	return parseClientsFromLines(lines), nil
}

func parseClientsFromLines(lines []string) []VPNClient {
	clients := make([]VPNClient, 0)
	clientHeaderMap := map[string]int{}
	for _, line := range lines {
		fields := splitStatusFields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "HEADER" && len(fields) > 2 && fields[1] == "CLIENT_LIST" {
			clientHeaderMap = parseHeaderMap(fields[2:])
			continue
		}
		if fields[0] == "CLIENT_LIST" {
			parts := fields
			if len(parts) < 3 {
				continue
			}
			commonName := getPart(parts, indexByHeader(clientHeaderMap, "Common Name", 1))
			realAddr := getPart(parts, indexByHeader(clientHeaderMap, "Real Address", 2))
			virtualAddr := getPart(parts, indexByHeader(clientHeaderMap, "Virtual Address", 3))
			rxBytes, _ := parseUint64(getPart(parts, indexByHeader(clientHeaderMap, "Bytes Received", 5)))
			txBytes, _ := parseUint64(getPart(parts, indexByHeader(clientHeaderMap, "Bytes Sent", 6)))
			connectedSince := getPart(parts, indexByHeader(clientHeaderMap, "Connected Since (time_t)", 8))
			if connectedSince == "" {
				connectedSince = getPart(parts, indexByHeader(clientHeaderMap, "Connected Since", 7))
			}
			if commonName == "" || realAddr == "" {
				continue
			}
			clients = append(clients, VPNClient{
				ID:          fmt.Sprintf("%s|%s", commonName, connectedSince),
				CommonName:  commonName,
				RemoteIP:    realAddr,
				VirtualIP:   virtualAddr,
				ConnectedAt: connectedSince,
				RxBytes:     rxBytes,
				TxBytes:     txBytes,
			})
			continue
		}
	}
	return clients
}

func parseUint64(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
}

func parseHeaderMap(columns []string) map[string]int {
	result := map[string]int{}
	for i, col := range columns {
		result[strings.TrimSpace(col)] = i + 1 // +1 because CLIENT_LIST marker is index 0
	}
	return result
}

func indexByHeader(headerMap map[string]int, key string, fallback int) int {
	if idx, ok := headerMap[key]; ok {
		return idx
	}
	return fallback
}

func getPart(parts []string, idx int) string {
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return strings.TrimSpace(parts[idx])
}

func splitStatusFields(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if strings.Contains(line, "\t") {
		raw := strings.Split(line, "\t")
		out := make([]string, len(raw))
		for i, item := range raw {
			out[i] = strings.TrimSpace(item)
		}
		return out
	}
	raw := strings.Split(line, ",")
	out := make([]string, len(raw))
	for i, item := range raw {
		out[i] = strings.TrimSpace(item)
	}
	return out
}

// managementKillName превращает id клиента из статуса (CommonName|time_t) в имя для команды kill.
// В интерфейсе управления OpenVPN ожидается common name, а не составной идентификатор.
func managementKillName(clientID string) string {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return clientID
	}
	name, _, found := strings.Cut(clientID, "|")
	if found && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return clientID
}

func (m *OpenVPNManagement) DisconnectClient(ctx context.Context, clientID string) error {
	conn, reader, err := m.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	killTarget := managementKillName(clientID)
	if _, err = fmt.Fprintf(conn, "kill %s\n", killTarget); err != nil {
		return err
	}
	reply, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	reply = strings.ToUpper(strings.TrimSpace(reply))
	if strings.Contains(reply, "ERROR") {
		return fmt.Errorf("openvpn returned error: %s", reply)
	}
	return nil
}
