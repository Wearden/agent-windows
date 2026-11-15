package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/Wearden/proto/wire"
)

type pendingEnrollment struct {
	Server  string          `json:"server"`
	Request wire.Enrollment `json:"request"`
}

// PrepareEnrollment persists the complete immutable request before its first POST.
// No enrollment token is ever stored in this record.
func PrepareEnrollment(path, server string) (wire.Enrollment, error) {
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
			return wire.Enrollment{}, errors.New("invalid pending enrollment file")
		}
		data, e := io.ReadAll(io.LimitReader(f, 16385))
		if e != nil || len(data) > 16384 {
			return wire.Enrollment{}, errors.New("cannot read bounded pending enrollment")
		}
		plain, e := Open(data)
		if e != nil {
			return wire.Enrollment{}, e
		}
		var record pendingEnrollment
		decoder := json.NewDecoder(bytes.NewReader(plain))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
			return wire.Enrollment{}, errors.New("invalid pending enrollment JSON")
		}
		if record.Server != server || record.Request.Version != wire.Version || record.Request.OS != "windows" || record.Request.Hostname == "" || len(record.Request.Hostname) > 253 || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(record.Request.RequestID) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(record.Request.AgentVersion) {
			return wire.Enrollment{}, errors.New("pending enrollment does not match this core origin or protocol")
		}
		return record.Request, nil
	}
	if !os.IsNotExist(err) {
		return wire.Enrollment{}, errors.New("cannot inspect pending enrollment file")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return wire.Enrollment{}, err
	}
	if hostname == "" || len(hostname) > 253 {
		return wire.Enrollment{}, errors.New("invalid enrollment hostname")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return wire.Enrollment{}, err
	}
	request := wire.Enrollment{Version: wire.Version, RequestID: hex.EncodeToString(random[:]), Hostname: hostname, OS: "windows", AgentVersion: "0.1.0"}
	plain, err := json.Marshal(pendingEnrollment{Server: server, Request: request})
	if err != nil {
		return wire.Enrollment{}, err
	}
	encrypted, err := Seal(plain)
	if err != nil {
		return wire.Enrollment{}, err
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return wire.Enrollment{}, errors.New("cannot exclusively create pending enrollment file")
	}
	_, writeErr := f.Write(encrypted)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return wire.Enrollment{}, errors.New("cannot persist enrollment request; no POST authorized")
	}
	return request, nil
}
