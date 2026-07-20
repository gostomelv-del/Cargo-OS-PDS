package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

type UUID [16]byte

var Nil UUID

var ErrInvalidUUID = errors.New("uuid: invalid UUID")

func New() UUID {
	var u UUID
	if _, err := rand.Read(u[:]); err != nil {
		panic(err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}
func (u UUID) String() string {
	b := make([]byte, 36)
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b)
}

func Parse(value string) (UUID, error) {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(compact) != 32 {
		return Nil, ErrInvalidUUID
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil {
		return Nil, ErrInvalidUUID
	}
	var id UUID
	copy(id[:], decoded)
	return id, nil
}

func (u UUID) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

func (u *UUID) UnmarshalText(value []byte) error {
	if u == nil {
		return ErrInvalidUUID
	}
	parsed, err := Parse(string(value))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}
