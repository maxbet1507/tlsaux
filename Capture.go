package tlsaux

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/maxbet1507/tlsaux/nsskeylog"
	"github.com/maxbet1507/tlsaux/prf"
	"github.com/maxbet1507/tlsaux/recordfmt"
)

// SecurityParameters -
type SecurityParameters struct {
	PRF               func(result, secret, label, seed []byte)
	Version           int
	CipherSuite       uint16
	CompressionMethod uint8
	MasterSecret      []byte
	ClientRandom      []byte
	ServerRandom      []byte
}

type auxTLSPlaintextDecoder struct {
	Done              bool
	Buffer            bytes.Buffer
	HandleClientHello func(*recordfmt.ClientHello)
	HandleServerHello func(*recordfmt.ServerHello)
}

func (s *auxTLSPlaintextDecoder) DecodeClientHello(r io.Reader) {
	var v recordfmt.ClientHello
	if err := v.Decode(r); err == nil {
		s.HandleClientHello(&v)
		s.Done = true
	}
}

func (s *auxTLSPlaintextDecoder) DecodeServerHello(r io.Reader) {
	var v recordfmt.ServerHello
	if err := v.Decode(r); err == nil {
		s.HandleServerHello(&v)
		s.Done = true
	}
}

func (s *auxTLSPlaintextDecoder) DecodeHandshake(r io.Reader) {
	var v recordfmt.Handshake
	if err := v.Decode(r); err == nil {
		switch v.MsgType {
		case recordfmt.TypeClientHello:
			s.DecodeClientHello(bytes.NewReader(v.Body))
		case recordfmt.TypeServerHello:
			s.DecodeServerHello(bytes.NewReader(v.Body))
		}
	}
}

func (s *auxTLSPlaintextDecoder) DecodeTLSPlaintext(r io.Reader) {
	var v recordfmt.TLSPlaintext
	if err := v.Decode(r); err == nil && v.Type == recordfmt.TypeHandshake {
		s.DecodeHandshake(bytes.NewReader(v.Fragment))
	}
}

func (s *auxTLSPlaintextDecoder) Push(v []byte) {
	if !s.Done {
		s.Buffer.Write(v) // always success

		aux := struct {
			ContentType     uint8
			ProtocolVersion uint16
			FragmentLength  uint16
		}{}

		for binary.Read(bytes.NewReader(s.Buffer.Bytes()), binary.BigEndian, &aux) == nil {
			if int(aux.FragmentLength)+5 <= s.Buffer.Len() {
				s.DecodeTLSPlaintext(&s.Buffer)
			}
		}
	}
}

type auxConn struct {
	Conn          net.Conn
	ReaderDecoder *auxTLSPlaintextDecoder
	WriterDecoder *auxTLSPlaintextDecoder
}

func (s *auxConn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *auxConn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *auxConn) SetDeadline(v time.Time) error {
	return s.Conn.SetDeadline(v)
}

func (s *auxConn) SetReadDeadline(v time.Time) error {
	return s.Conn.SetReadDeadline(v)
}

func (s *auxConn) SetWriteDeadline(v time.Time) error {
	return s.Conn.SetWriteDeadline(v)
}

func (s *auxConn) Read(p []byte) (n int, err error) {
	n, err = s.Conn.Read(p)
	if n > 0 {
		s.ReaderDecoder.Push(p[:n])
	}
	return
}

func (s *auxConn) Write(p []byte) (n int, err error) {
	n, err = s.Conn.Write(p)
	if n > 0 {
		s.WriterDecoder.Push(p[:n])
	}
	return
}

func (s *auxConn) Close() (err error) {
	err = s.Conn.Close()
	return
}

type auxWriter struct {
	HandleNSSKeyLog func(nsskeylog.Label, []byte, []byte)
	Locker          sync.Mutex
	Buffer          []byte
}

func (s *auxWriter) ReadLines() []string {
	ret := []string{}
	for {
		// to avoid blocking, not use standard scanner.
		idx := bytes.IndexByte(s.Buffer, '\n')
		if idx < 0 {
			break
		}
		ret = append(ret, string(s.Buffer[:idx]))
		s.Buffer = s.Buffer[idx+1:]
	}
	return ret
}

func (s *auxWriter) Write(p []byte) (n int, err error) {
	s.Locker.Lock()
	n, s.Buffer = len(p), append(s.Buffer, p...)

	for _, line := range s.ReadLines() {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			if label, crand, secret, err := nsskeylog.Parse(line); err == nil && label == nsskeylog.ClientRandom {
				s.HandleNSSKeyLog(label, crand, secret)
			}
		}
	}

	s.Locker.Unlock()
	return
}

type rawCapture struct {
	Locker             sync.Mutex
	ClientHello        *recordfmt.ClientHello
	ServerHello        *recordfmt.ServerHello
	SecurityParameters *SecurityParameters
}

func (s *rawCapture) HandleClientHello(v *recordfmt.ClientHello) {
	s.Locker.Lock()
	s.ClientHello = v
	s.ServerHello = nil
	s.SecurityParameters = nil
	s.Locker.Unlock()
}

func (s *rawCapture) HandleServerHello(v *recordfmt.ServerHello) {
	s.Locker.Lock()
	s.ServerHello = v
	s.Locker.Unlock()
}

func (s *rawCapture) HandleNSSKeyLog(label nsskeylog.Label, crand, secret []byte) {
	s.Locker.Lock()
	if bytes.Compare(s.ClientHello.Random, crand) == 0 {
		s.SecurityParameters = &SecurityParameters{
			PRF:               prf.New(int(s.ServerHello.ServerVersion), uint16(s.ServerHello.CipherSuite)),
			Version:           int(s.ServerHello.ServerVersion),
			CipherSuite:       uint16(s.ServerHello.CipherSuite),
			CompressionMethod: uint8(s.ServerHello.CompressionMethod),
			MasterSecret:      secret[:],
			ClientRandom:      s.ClientHello.Random[:],
			ServerRandom:      s.ServerHello.Random[:],
		}
	}
	s.Locker.Unlock()
}

func (s *rawCapture) Retrieve() (r *SecurityParameters) {
	s.Locker.Lock()
	r = s.SecurityParameters
	s.Locker.Unlock()
	return
}

func mergeWriters(w ...io.Writer) io.Writer {
	var m []io.Writer
	for _, w := range w {
		if w != nil {
			m = append(m, w)
		}
	}
	return io.MultiWriter(m...)
}

// Capture -
func Capture(conn net.Conn, config *tls.Config, fn func(net.Conn, *tls.Config) *tls.Conn) (*tls.Conn, func() *SecurityParameters) {
	capture := &rawCapture{}

	conn = &auxConn{
		Conn: conn,
		ReaderDecoder: &auxTLSPlaintextDecoder{
			HandleClientHello: capture.HandleClientHello,
			HandleServerHello: capture.HandleServerHello,
		},
		WriterDecoder: &auxTLSPlaintextDecoder{
			HandleClientHello: capture.HandleClientHello,
			HandleServerHello: capture.HandleServerHello,
		},
	}

	config = config.Clone()
	config.KeyLogWriter = mergeWriters(
		config.KeyLogWriter,
		&auxWriter{HandleNSSKeyLog: capture.HandleNSSKeyLog})

	return fn(conn, config), capture.Retrieve
}
