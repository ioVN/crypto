package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

type HASH []byte

func (value HASH) Hex() string {
	return hex.EncodeToString(value)
}

func SHA256(data []byte) HASH {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
