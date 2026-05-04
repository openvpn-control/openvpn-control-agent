package internal

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

func LoadOrCreateToken(path string) (token string, created bool, err error) {
	if data, readErr := os.ReadFile(path); readErr == nil {
		return strings.TrimSpace(string(data)), false, nil
	}

	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return "", false, err
	}
	token = hex.EncodeToString(bytes)

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	if err = os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", false, err
	}
	return token, true, nil
}
