package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

// ParsePrivateKey returns the rsa private key repr for a pem-encoded private key.
func ParsePrivateKey(pemEncodedRSAPvtKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncodedRSAPvtKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse private key")
	}
	return privKey.(*rsa.PrivateKey), nil
}
