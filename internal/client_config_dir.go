package internal

import (
	"bufio"
	"os"
	"strings"
)

// ReadClientConfigDirFromServerConf — первая директива client-config-dir в server.conf (путь как в файле).
func ReadClientConfigDirFromServerConf(confPath string) string {
	f, err := os.Open(confPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.ToLower(fields[0]) != "client-config-dir" {
			continue
		}
		val := strings.TrimSpace(strings.Trim(line[len(fields[0]):], " \t"))
		val = strings.Trim(val, `"`)
		return val
	}
	return ""
}
