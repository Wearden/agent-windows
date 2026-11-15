package identity

import "errors"

// Seal/Open retain current-user DPAPI scope for local task journals and backups.
func Seal(data []byte) ([]byte, error) {
	if len(data) > 512<<10 {
		return nil, errors.New("local encrypted payload exceeds limit")
	}
	return crypt(data, true)
}
func Open(data []byte) ([]byte, error) {
	plain, err := crypt(data, false)
	if err != nil {
		return nil, err
	}
	if len(plain) > 512<<10 {
		return nil, errors.New("decrypted local payload exceeds limit")
	}
	return plain, nil
}
