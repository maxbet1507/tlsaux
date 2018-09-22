package testcert_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/maxbet1507/tlsaux/testcert"
)

func TestSelfSigned(t *testing.T) {
	cert, pkey, err := testcert.SelfSigned(1024, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tls.X509KeyPair(cert, pkey); err != nil {
		t.Fatal(err)
	}
}
