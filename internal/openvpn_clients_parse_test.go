package internal

import "testing"

func TestParseClientsFromLinesUsesRoutingTableVirtualIP(t *testing.T) {
	lines := []string{
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)",
		"CLIENT_LIST\talice\t1.2.3.4:12345\t\t100\t200\t1710000000",
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address",
		"ROUTING_TABLE\t10.8.0.2\talice\t1.2.3.4:12345",
		"END",
	}
	clients := parseClientsFromLines(lines)
	if len(clients) != 1 {
		t.Fatalf("len=%d", len(clients))
	}
	if clients[0].VirtualIP != "10.8.0.2" {
		t.Fatalf("virtualIp=%q", clients[0].VirtualIP)
	}
}

func TestParseClientsFromLinesKeepsClientWithoutVirtualIP(t *testing.T) {
	lines := []string{
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)",
		"CLIENT_LIST\tbob\t5.6.7.8:443\t\t0\t0\t1710000001",
		"END",
	}
	clients := parseClientsFromLines(lines)
	if len(clients) != 1 {
		t.Fatalf("len=%d", len(clients))
	}
	if clients[0].CommonName != "bob" {
		t.Fatalf("cn=%q", clients[0].CommonName)
	}
}
