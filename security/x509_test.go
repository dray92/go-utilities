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

func TestMain(t *testing.T) {
	main()
}

func TestParseX509Cert(t *testing.T) {
	cert, err := ParseX509Cert(_testRootCert)
	require.NoError(t, err)
	require.Equal(t, "foo.io", cert.Subject.CommonName)
	require.False(t, cert.IsCA, "since its a self-signed cert, should be set to false")
}

func TestIntermediateOps(t *testing.T) {

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

	leafCert, pemEncodedBytes, err := GenerateLeafCert(parentCert, template, parentPrivKey)
	require.NoError(t, err)
	require.NotNil(t, pemEncodedBytes)
	require.NotNil(t, leafCert)

	decodedLeafCert, err := ParseX509Cert(pemEncodedBytes)
	require.NoError(t, err)
	require.Equal(t, "foo.io", decodedLeafCert.Issuer.CommonName, "should match the CN of the parent root cert")
	require.False(t, decodedLeafCert.IsCA, "leaf cert cannot be an intermediate CA")
}

func TestVerifyLeaf(t *testing.T) {
	tests := []struct {
		description          string
		getRoot              func() (*x509.Certificate, *rsa.PrivateKey)
		getIntermediates     func(*x509.Certificate) []*x509.Certificate
		assertOnExpectations func(*testing.T, bool, [][]*x509.Certificate)
	}{
		{
			description: "no intermediates",
			getRoot: func() (*x509.Certificate, *rsa.PrivateKey) {
				parentCert, err := ParseX509Cert(_testRootCert)
				require.NoError(t, err)
				require.NotNil(t, parentCert)

				// modify vars since we are treating this as the root
				parentCert.BasicConstraintsValid = true
				parentCert.IsCA = true
				parentCert.MaxPathLenZero = false
				parentCert.MaxPathLen = 1
				parentCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

				parentPrivKey, err := ParsePrivateKey(_testRootPvtKey)
				require.NoError(t, err)

				return parentCert, parentPrivKey
			},
			getIntermediates: func(root *x509.Certificate) []*x509.Certificate {
				var intermediates []*x509.Certificate
				intermediates = append(intermediates, root)
				return intermediates
			},
			assertOnExpectations: func(t *testing.T, valid bool, chain [][]*x509.Certificate) {
				require.True(t, valid)
				require.Equal(t, 1, len(chain), "only one root")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			root, priv := test.getRoot()
			intermediates := test.getIntermediates(root)

			// if there are intermediates, pick the last one to generate the leaf from
			var lowestCA *x509.Certificate
			if len(intermediates) != 0 {
				lowestCA = intermediates[len(intermediates)-1]
			} else {
				lowestCA = root
			}

			leafCert, _, err := GenerateLeafCert(lowestCA, &x509.Certificate{
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
			}, priv)
			require.NoError(t, err)
			require.NotNil(t, leafCert)

			valid, chain := VerifyLeaf(leafCert, root, intermediates...)
			test.assertOnExpectations(t, valid, chain)
		})
	}
}

func TestGenerateIntermediateCertAndGenerateLeafCert(t *testing.T) {
	t.Skip("this is shit - don't review")
	// code duplication in this test is intentional for better readability

	// load up the parent successfully first
	parentCert, err := ParseX509Cert(_testRootCert)
	require.NoError(t, err)
	require.NotNil(t, parentCert)

	// modify vars since we are treating this as the root
	parentCert.BasicConstraintsValid = true
	parentCert.IsCA = true
	parentCert.MaxPathLenZero = false
	parentCert.MaxPathLen = 1 // allow for one intermediate
	parentCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	parentPrivKey, err := ParsePrivateKey(_testRootPvtKey)
	require.NoError(t, err)

	var intermediateTemplate = &x509.Certificate{
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

	intermediateCert, pemEncodedBytesForIntermediate, err := GenerateIntermediateCert(parentCert, intermediateTemplate, parentPrivKey)
	require.NoError(t, err)
	require.NotNil(t, intermediateCert)

	decodedIntermediateCert, err := ParseX509Cert(pemEncodedBytesForIntermediate)
	require.NoError(t, err)
	require.Equal(t, "foo.io", decodedIntermediateCert.Issuer.CommonName, "should match the CN of the parent root cert")
	require.True(t, decodedIntermediateCert.IsCA, "this is an intermediate cert")
	require.Equal(t, 0, decodedIntermediateCert.MaxPathLen, "since the root had a max path length of 1, this must be 0")
	require.True(t, decodedIntermediateCert.MaxPathLenZero, "since the root had a max path length of 1, this must be 0")

	var leafTemplate = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"fee.fum.foo.io"},
			OrganizationalUnit: []string{uuid.New().String()},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 360), // 1 day

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	leafCert, pemEncodedBytesForLeaf, err := GenerateLeafCert(decodedIntermediateCert, leafTemplate, nil)
	require.NoError(t, err)
	require.NotNil(t, pemEncodedBytesForLeaf)
	require.NotNil(t, leafCert)

	decodedLeafCert, err := ParseX509Cert(pemEncodedBytesForLeaf)
	require.NoError(t, err)
	require.Equal(t, intermediateTemplate.Subject.Organization[0], decodedLeafCert.Issuer.Organization[0], "should match the CN of the intermediate root cert")
	require.False(t, decodedLeafCert.IsCA, "leaf cert cannot be an intermediate CA")

	// parent certs max path length is set to 1. Therefore, attempting to generate an intermediate off the intermediate should fail.
	secondaryIntermediate, _, err := GenerateIntermediateCert(decodedIntermediateCert, intermediateTemplate, parentPrivKey)
	require.NoError(t, err)

	leafFromSecondaryIntermediate, _, err := GenerateLeafCert(secondaryIntermediate, leafTemplate, nil)
	require.NoError(t, err)
	require.NotNil(t, leafFromSecondaryIntermediate)
}
