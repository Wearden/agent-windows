package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Identity struct {
	Server  string `json:"server"`
	AgentID string `json:"agent_id"`
	Token   string `json:"agent_token"`
}

func Load(path string) (Identity, error) {
	var value Identity
	f, err := os.Open(path)
	if err != nil {
		return value, errors.New("cannot open encrypted identity")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return value, errors.New("invalid identity file")
	}
	data := make([]byte, info.Size())
	if _, err = f.ReadAt(data, 0); err != nil && len(data) > 0 {
		return value, errors.New("cannot read encrypted identity")
	}
	plain, err := crypt(data, false)
	if err != nil {
		return value, err
	}
	if json.Unmarshal(plain, &value) != nil || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(value.AgentID) || len(value.Token) == 0 || len(value.Token) > 512 || strings.ContainsAny(value.Token, "\r\n") {
		return Identity{}, errors.New("invalid identity payload")
	}
	return value, nil
}

func SaveNew(path string, value Identity) error {
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data, err := crypt(plain, true)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "identity-*.tmp")
	if err != nil {
		return errors.New("cannot create encrypted identity temporary file")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot protect identity temporary file")
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist identity; preserve file for recovery")
	}
	return commitNewIdentity(f.Name(), path)
}
