package tlsaux_test

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/maxbet1507/tlsaux"
	"github.com/maxbet1507/tlsaux/testcert"
	"golang.org/x/sync/errgroup"
)

func netpipe() (svconn net.Conn, clconn net.Conn, err error) {
	var l net.Listener
	if l, err = net.Listen("tcp", ""); err == nil {
		eg := errgroup.Group{}
		eg.Go(func() (err error) {
			svconn, err = l.Accept()
			return
		})
		eg.Go(func() (err error) {
			clconn, err = net.Dial("tcp", l.Addr().String())
			return
		})
		err = eg.Wait()
	}
	return
}

func TestCapture(t *testing.T) {
	cert, pkey, _ := testcert.SelfSigned(1024, 10*time.Second)
	pair, _ := tls.X509KeyPair(cert, pkey)

	svconfig := &tls.Config{
		Certificates: []tls.Certificate{pair},
	}
	clconfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	clconn, svconn, err := netpipe()
	if err != nil {
		t.Fatal(err)
	}
	defer clconn.Close()
	defer svconn.Close()

	client, clcapture := tlsaux.Capture(clconn, clconfig, tls.Client)
	server, svcapture := tlsaux.Capture(svconn, svconfig, tls.Server)

	eg := errgroup.Group{}

	eg.Go(func() error {
		return client.Handshake()
	})
	eg.Go(func() error {
		return server.Handshake()
	})

	if err := eg.Wait(); err != nil {
		t.Fatal(err)
	}

	clparams, svparams := clcapture(), svcapture()

	svresult := make([]byte, 128)
	svparams.PRF(svresult, svparams.MasterSecret, []byte("label"), append(svparams.ClientRandom, svparams.ServerRandom...))

	clresult := make([]byte, 128)
	clparams.PRF(clresult, clparams.MasterSecret, []byte("label"), append(clparams.ClientRandom, clparams.ServerRandom...))

	if bytes.Compare(svresult, clresult) != 0 {
		t.Fatal(svresult, clresult)
	}

	if l, r := client.LocalAddr(), server.RemoteAddr(); l.String() != r.String() {
		t.Fatal(l, r)
	}
	if l, r := server.LocalAddr(), client.RemoteAddr(); l.String() != r.String() {
		t.Fatal(l, r)
	}

	now := time.Now().Add(10 * time.Second)
	if e1, e2 := client.SetDeadline(now), server.SetDeadline(now); e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	if e1, e2 := client.SetReadDeadline(now), server.SetReadDeadline(now); e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	if e1, e2 := client.SetWriteDeadline(now), server.SetWriteDeadline(now); e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	if e1, e2 := client.Close(), server.Close(); e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
}
