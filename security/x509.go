package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

// ParseX509Cert parses an x.509 cert.
func ParseX509Cert(pemEncodedCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemEncodedCert))
	if block == nil {
		return nil, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse cert")
	}
	return cert, nil
}

// ParsePrivateKey returns the rsa private key repr for a pem-encoded private key.
func ParsePrivateKey(pemEncodedRSAPvtKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(_testRootPvtKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse private key")
	}
	return privKey.(*rsa.PrivateKey), nil
}

// GenerateIntermediateCert generates an intermediate cerdt from the given parent
func GenerateIntermediateCert(
	parent, settingsTemplate *x509.Certificate,
	parentPrivKey *rsa.PrivateKey,
) (*x509.Certificate, []byte, []byte, error) {
	templateCopy := x509.Certificate{} // TODO check w/o init
	err := copier.Copy(&templateCopy, &settingsTemplate)
	if err != nil {
		return nil, nil, nil, errors.New("failed to make a copy of the settings template")
	}

	// since this is an intermediate cert, be explicit
	templateCopy.IsCA = true
	templateCopy.MaxPathLen = parent.MaxPathLen - 1
	// -1 is treated as unset in the std lib, but we'd expect leaf certs generated
	// from that to fail, therefore not returning an error here. TODO (this needs to be verified)
	if templateCopy.MaxPathLen < 0 {
		templateCopy.MaxPathLen = 0
	}

	templateCopy.MaxPathLenZero = templateCopy.MaxPathLen == 0
	templateCopy.BasicConstraintsValid = true

	return generateX509Cert(parent, &templateCopy, parentPrivKey)
}

// VerifyIntermediateCert verifies an intermediate certificate. Not sure if it is currently walking up the chain correctly.
func VerifyIntermediateCert(root, intermediate *x509.Certificate) (bool, [][]*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	var chain [][]*x509.Certificate
	var err error
	if chain, err = intermediate.Verify(opts); err != nil {
		return false, nil, errors.Wrap(err, "failed to verify intermediate cert")
	}
	return true, chain, nil
}

// GenerateLeafCert generates a leaf cert from the given parent.
func GenerateLeafCert(
	parent, settingsTemplate *x509.Certificate,
	parentPrivKey *rsa.PrivateKey,
) (*x509.Certificate, []byte, []byte, error) {
	templateCopy := x509.Certificate{} // TODO check w/o init
	err := copier.Copy(&templateCopy, &settingsTemplate)
	if err != nil {
		return nil, nil, nil, errors.New("failed to make a copy of the settings template")
	}

	// since this is a leaf cert, be explicit
	templateCopy.IsCA = false
	templateCopy.BasicConstraintsValid = true
	templateCopy.NotBefore = time.Now().Add(-10 * time.Second)

	// TODO (debo): revisit this to see if any other template params need to be changed
	return generateX509Cert(parent, &templateCopy, parentPrivKey)
}

// VerifyLeafCert verifies a leaf certificate. Not sure if it is currently walking up the chain correctly.
func VerifyLeafCert(root, child *x509.Certificate, intermediates ...*x509.Certificate) (bool, [][]*x509.Certificate, error) {
	roots := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()
	roots.AddCert(root)
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatePool,
	}

	var chain [][]*x509.Certificate
	var err error
	if _, err = child.Verify(opts); err != nil {
		return false, nil, errors.Wrap(err, "failed to verify leaf cert")
	}
	return true, chain, nil
}

func generateX509Cert(
	parent, template *x509.Certificate,
	parentPrivKey *rsa.PrivateKey,
) (*x509.Certificate, []byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate private key")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, parentPrivKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create certificate")
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to parse certificate")
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pemEncodedCert := pem.EncodeToMemory(&b)

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pemEncodedPrivKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)

	return cert, pemEncodedCert, pemEncodedPrivKey, nil
}
