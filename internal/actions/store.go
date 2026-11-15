package actions

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Wearden/agent-windows/internal/identity"
)

func store(path string, value any, exclusive bool) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := identity.Seal(data)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "sealed-*.tmp")
	if err != nil {
		return errors.New("cannot create encrypted state temporary file")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot protect encrypted state file")
	}
	_, writeErr := f.Write(encrypted)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist encrypted state; temporary file retained")
	}
	return commit(f.Name(), path, !exclusive)
}

func load(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("invalid encrypted state file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return errors.New("cannot read encrypted state within limit")
	}
	plain, err := identity.Open(data)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return errors.New("invalid encrypted state JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing encrypted state data")
	}
	return nil
}

func prepareRoot(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil || strings.HasPrefix(abs, `\\`) {
		return errors.New("task state must use a local filesystem path")
	}
	for _, path := range []string{root, filepath.Join(root, "backups"), filepath.Join(root, "completed"), filepath.Join(root, "watchdogs")} {
		if err = os.MkdirAll(path, 0700); err != nil {
			return errors.New("cannot create private task state directory")
		}
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("task state directory must not be a link")
		}
		absolute, e := filepath.Abs(path)
		if e != nil {
			return errors.New("cannot resolve task state directory")
		}
		resolved, e := filepath.EvalSymlinks(absolute)
		if e != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(absolute)) {
			return errors.New("task state path must not traverse filesystem links")
		}
		if err = privateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}
