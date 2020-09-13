package security

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	_testRootCert = []byte(`-----BEGIN CERTIFICATE-----
MIIE1zCCAr+gAwIBAgIUOoeb4AEe0KJ7nrrtpLycbsR/77cwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGZm9vLmlvMB4XDTIwMDkwNDAxNDUxM1oXDTMwMDkwMjAx
NDUxM1owETEPMA0GA1UEAwwGZm9vLmlvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAwvVYDq0qah5E7KHgS9kYzc98DjFuaO0m4h39lNx6zG8MphAJ+YYC
Q3745OMI7XEJzp7i8ozTcJkmMLRauacWyCnFNp5e4QBzSYuKMhNcwUBxbjhay4IS
vYg6kSlYzAkhk/OFN8SPjILXU4hJLgDFfQZQhnBDVg5k9R8mZ0GasqgVEipA50eA
+fNDMBH9AuQP/V4kgCk0Aai3RBTmx7WUhR9A+GUVdfBAa9WIVMgWMkgrb0KfB+EN
vTRWvsZiwb6Im23ypfzT4EjI7kLNzRdWHGc1wyZ4BjEp3lic52o5rERx6mXtaMec
C7FNTLwqk/QkK8hnV0oxYypDfESASnB3sAD6C9P2NSVwYwfDhwyp+DUy+A/KP4pV
2znXGaJBNFfwpVxWA1CZd0TnT8x142OFbpqryVVE7JqRg6gXC6Tb7RkxdhrLp6oW
hTLM6//BtLgwS0AvxTpIllY99jjtnl8kY4qhZ7O4MpOA7xouoWe/mqthM5opeM6d
exVtGmsqYJNiO2nei/u25SAjS+pVA/M6w9NxtD8OXqi2kFOCIiV9r+WA537yodM0
A0wYhjEV6hRyXU5nbAnKuth+mUa5X8cTKs4tUm64uSukgtdr8ceFIr1rEhFi5ZQy
Jo5JjH3y4NKywmpe19WwS1g2OOMQhXq/tnK+elzo94xg2TwWAzPehVsCAwEAAaMn
MCUwIwYDVR0RBBwwGoIGZm9vLmlvggp3d3cuZm9vLmlvhwQBAQEBMA0GCSqGSIb3
DQEBCwUAA4ICAQBm3AjdQDv+3bwj/vM/59yLxl39V+zerBzCvLSmEqOuJ6Enx1qs
o3l2aasewmVMZacbnKwcxzIgZKfK+UUZQByyWO9XFrSCXw6KaAhrDwrPrFRI4lAS
mSOGEi+clOF/ddw2vxtAg1Y5FYpppkOTFvkWAFfQqMVKVBWimoN/rW2CkJ8fiGlM
6nZnCCCTOEY8x6ZLpjrEZefePOZa0Np/5Z93nxBtX+eUU6a2sr2aDPdcyo16T5PV
2MgGhSQKZmyldUFJkSJvdN97gMLynRY4VgBqRoGqTZADNcx0HOPIEh08+kZi41FU
DV0NekYsKBeOwd8He7EP8sF8sBF19tMtbI+7NUpjFC92ZeiYiUUDDyRmUWGSr8yA
FA77r87VG9OOq6bft8UdWAQKR7G16uF48P1IQcKjf4uj6u8k9n7tSLU8iUqSkj+F
EYTa8kXPVN8BTgwb/L+FhoWzuvZWBEvhOXclkWtCQlCN11nv1bEF3CadzVZq9OMn
YB5hlVy6PyGIfYH7H7hSfsevdSVkxNN6yNau5az8r/Rny5ihF2QgpgZHwISV8Yr2
k82fzFoES/DBjTuVWu09v25jAZjJ/zHmrRahKdffWUIiZ5UxOYUvI8BVpA0Fd/Sz
mTwLIRuPYbqTF7NomvoWwCTegCR/u4dLPd/MuwgBW6z/oTu3jpu0IA8Puw==
-----END CERTIFICATE-----`)

	_testRootPvtKey = []byte(`-----BEGIN PRIVATE KEY-----
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
KIrb6SCWRfGbTIkDLdUhckG002cHZLk=
-----END PRIVATE KEY-----`)
)

func TestParseX509Cert(t *testing.T) {
	cert, err := ParseX509Cert(_testRootCert)
	require.NoError(t, err)
	require.Equal(t, "foo.io", cert.Subject.CommonName)
	require.False(t, cert.IsCA, "since its a self-signed cert, should be set to false")
}

func TestIntermediateOps(t *testing.T) {
	tests := []struct {
		description                  string
		getRoot                      func() (*x509.Certificate, *rsa.PrivateKey)
		getIntermediateTemplate      func() *x509.Certificate
		assertOnGenerateExpectations func(t *testing.T, intermediate *x509.Certificate, encodedCert []byte, encodedKey []byte, err error)
		assertOnValidateExpectations func(t *testing.T, valid bool, chain [][]*x509.Certificate, err error)
	}{
		{
			description: "parent w/ path len 1",
			getRoot: func() (*x509.Certificate, *rsa.PrivateKey) {
				rootCert, err := ParseX509Cert(_testRootCert)
				require.NoError(t, err)
				rootCert.IsCA = true
				rootCert.BasicConstraintsValid = true
				rootCert.MaxPathLen = 1

				rootKey, err := ParsePrivateKey(_testRootPvtKey)
				require.NoError(t, err)
				return rootCert, rootKey
			},
			getIntermediateTemplate: func() *x509.Certificate {
				return &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						Organization:       []string{"fum.foo.io"},
						OrganizationalUnit: []string{uuid.New().String()},
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year, 0 months, 0 days

					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				}
			},
			assertOnGenerateExpectations: func(t *testing.T, intermediate *x509.Certificate, encodedCert []byte, encodedKey []byte, err error) {
				require.NoError(t, err)
			},
			assertOnValidateExpectations: func(t *testing.T, valid bool, chain [][]*x509.Certificate, err error) {
				require.NoError(t, err)
				require.True(t, valid)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			rootCert, rootKey := test.getRoot()
			intermediateTemplate := test.getIntermediateTemplate()
			intermediateCert, encodedIntermediateCert, encodedPrivKey, err := GenerateIntermediateCert(rootCert, intermediateTemplate, rootKey)
			test.assertOnGenerateExpectations(t, intermediateCert, encodedIntermediateCert, encodedPrivKey, err)
			// if there was an error in cert generation, no point continuing
			if err != nil {
				return
			}
			valid, chain, err := VerifyIntermediateCert(rootCert, intermediateCert)
			test.assertOnValidateExpectations(t, valid, chain, err)
		})
	}
}

func TestLeafOps(t *testing.T) {
	tests := []struct {
		description                  string
		getRoot                      func() (*x509.Certificate, *rsa.PrivateKey)
		getIntermediate              func(rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey)
		getLeafTemplate              func() *x509.Certificate
		assertOnGenerateExpectations func(t *testing.T, leaf *x509.Certificate, encodedCert []byte, encodedKey []byte, err error)
		assertOnValidateExpectations func(t *testing.T, valid bool, chain [][]*x509.Certificate, err error)
	}{
		{
			description: "parent w/ path len 1",
			getRoot: func() (*x509.Certificate, *rsa.PrivateKey) {
				rootCert, err := ParseX509Cert(_testRootCert)
				require.NoError(t, err)
				rootCert.IsCA = true
				rootCert.BasicConstraintsValid = true
				rootCert.MaxPathLen = 1

				rootKey, err := ParsePrivateKey(_testRootPvtKey)
				require.NoError(t, err)
				return rootCert, rootKey
			},
			getIntermediate: func(rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
				intermediateTemplate := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						Organization:       []string{"fum.foo.io"},
						OrganizationalUnit: []string{uuid.New().String()},
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year, 0 months, 0 days

					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				}
				intermediateCert, _, encodedPrivKey, err := GenerateIntermediateCert(rootCert, intermediateTemplate, rootKey)
				require.NoError(t, err)

				pvtKey, err := ParsePrivateKey(encodedPrivKey)
				require.NoError(t, err)

				return intermediateCert, pvtKey
			},
			getLeafTemplate: func() *x509.Certificate {
				return &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						Organization:       []string{"fum.foo.io"},
						OrganizationalUnit: []string{uuid.New().String()},
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year, 0 months, 0 days

					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				}
			},
			assertOnGenerateExpectations: func(t *testing.T, leaf *x509.Certificate, encodedCert []byte, encodedKey []byte, err error) {
				require.NoError(t, err)
			},
			assertOnValidateExpectations: func(t *testing.T, valid bool, chain [][]*x509.Certificate, err error) {
				require.NoError(t, err)
				require.True(t, valid)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			rootCert, rootKey := test.getRoot()
			intermediateCert, intermediateKey := test.getIntermediate(rootCert, rootKey)
			leafTemplate := test.getLeafTemplate()

			leafCert, encodedLeafCert, encodedPrivKey, err := GenerateLeafCert(intermediateCert, leafTemplate, intermediateKey)
			test.assertOnGenerateExpectations(t, leafCert, encodedLeafCert, encodedPrivKey, err)
			// if there was an error in cert generation, no point continuing
			if err != nil {
				return
			}
			valid, chain, err := VerifyLeafCert(rootCert, intermediateCert)
			test.assertOnValidateExpectations(t, valid, chain, err)
		})
	}
}

func TestGenerateLeafCert(t *testing.T) {
	// load up the parent successfully first
	parentCert, err := ParseX509Cert(_testRootCert)
	require.NoError(t, err)
	require.NotNil(t, parentCert)

	// modify vars since we are treating this as the root
	parentCert.BasicConstraintsValid = true
	parentCert.IsCA = true
	parentCert.MaxPathLenZero = false
	parentCert.MaxPathLen = 0
	parentCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	parentPrivKey, err := ParsePrivateKey(_testRootPvtKey)
	require.NoError(t, err)

	var template = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"fum.foo.io"},
			OrganizationalUnit: []string{uuid.New().String()},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 360), // one day

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  false,
	}

	leafCert, pemEncodedCert, pemEncodedKey, err := GenerateLeafCert(parentCert, template, parentPrivKey)
	require.NoError(t, err)
	require.NotNil(t, pemEncodedCert)
	require.NotNil(t, pemEncodedKey)
	require.NotNil(t, leafCert)

	decodedLeafCert, err := ParseX509Cert(pemEncodedCert)
	require.NoError(t, err)
	require.Equal(t, "foo.io", decodedLeafCert.Issuer.CommonName, "should match the CN of the parent root cert")
	require.False(t, decodedLeafCert.IsCA, "leaf cert cannot be an intermediate CA")
}
