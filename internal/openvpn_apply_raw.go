package internal

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// ApplyRawServerConfig записывает текст конфига в server.conf и перезапускает службу.
func ApplyRawServerConfig(confPath, restartCommand string, raw []byte) (restartOutput string, err error) {
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(confPath, raw, 0o600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runShellCommand(ctx, restartCommand)
}
