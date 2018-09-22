package testcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// SelfSigned -
func SelfSigned(bits int, duration time.Duration) (cert []byte, pkey []byte, err error) {
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(0),
		Subject:               pkix.Name{Organization: []string{"for test purpose only"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	var rsakey *rsa.PrivateKey
	rsakey, err = rsa.GenerateKey(rand.Reader, bits)
	if err == nil {
		var certder, pkeyder []byte
		certder, err = x509.CreateCertificate(rand.Reader, template, template, &rsakey.PublicKey, rsakey)
		pkeyder = x509.MarshalPKCS1PrivateKey(rsakey)
		if err == nil {
			cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certder})
			pkey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkeyder})
		}
	}
	return
}
