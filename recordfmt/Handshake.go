package recordfmt

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
)

// HandshakeType -
type HandshakeType int

// -
const (
	TypeHelloRequest       = HandshakeType(0)
	TypeClientHello        = HandshakeType(1)
	TypeServerHello        = HandshakeType(2)
	TypeCertificate        = HandshakeType(11)
	TypeServerKeyExchange  = HandshakeType(12)
	TypeCertificateRequest = HandshakeType(13)
	TypeServerHelloDone    = HandshakeType(14)
	TypeCertificateVerify  = HandshakeType(15)
	TypeClientKeyExchange  = HandshakeType(16)
	TypeFinished           = HandshakeType(20)
)

// Decode -
func (s *HandshakeType) Decode(r io.Reader) (err error) {
	var raw uint8
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = HandshakeType(raw)
	}
	return
}

// HandshakeBody -
type HandshakeBody []byte

// Decode -
func (s *HandshakeBody) Decode(r io.Reader) (err error) {
	aux := make([]byte, 3)
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, (int(aux[0])<<16)+(int(aux[1])<<8)+int(aux[2]))
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			*s = raw
		}
	}
	return
}

// Handshake -
type Handshake struct {
	MsgType HandshakeType
	Body    HandshakeBody
}

// Decode -
func (s *Handshake) Decode(r io.Reader) (err error) {
	var v Handshake

	fn := []func(io.Reader) error{
		v.MsgType.Decode,
		v.Body.Decode,
	}
	for i := 0; i < len(fn) && err == nil; i++ {
		err = fn[i](r)
	}

	if err == nil {
		*s = v
	}
	return
}

// ExtensionType -
type ExtensionType uint16

// Decode -
func (s *ExtensionType) Decode(r io.Reader) (err error) {
	var raw uint16
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = ExtensionType(raw)
	}
	return
}

// ExtensionData -
type ExtensionData []byte

// Decode -
func (s *ExtensionData) Decode(r io.Reader) (err error) {
	var aux uint16
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			*s = raw
		}
	}
	return
}

// HelloExtension -
type HelloExtension struct {
	ExtensionType ExtensionType
	ExtensionData ExtensionData
}

// Decode -
func (s *HelloExtension) Decode(r io.Reader) (err error) {
	var v HelloExtension

	fn := []func(io.Reader) error{
		v.ExtensionType.Decode,
		v.ExtensionData.Decode,
	}
	for i := 0; i < len(fn) && err == nil; i++ {
		err = fn[i](r)
	}

	if err == nil {
		*s = v
	}
	return
}

// HelloExtensions -
type HelloExtensions []HelloExtension

// Decode -
func (s *HelloExtensions) Decode(r io.Reader) (err error) {
	var v HelloExtensions

	var aux uint16
	switch err = binary.Read(r, binary.BigEndian, &aux); err {
	case nil:
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			for r := bytes.NewBuffer(raw); r.Len() > 0 && err == nil; {
				var w HelloExtension
				if err = w.Decode(r); err == nil {
					v = append(v, w)
				}
			}
		}
	case io.EOF:
		err = nil
	}

	if err == nil {
		*s = v
	}
	return
}

// Random -
type Random []byte

// Decode -
func (s *Random) Decode(r io.Reader) (err error) {
	raw := make([]byte, 32)
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = raw
	}
	return
}

// SessionID -
type SessionID []byte

// Decode -
func (s *SessionID) Decode(r io.Reader) (err error) {
	var aux uint8
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			*s = raw
		}
	}
	return
}

// CipherSuite -
type CipherSuite uint16

// Decode -
func (s *CipherSuite) Decode(r io.Reader) (err error) {
	var raw uint16
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = CipherSuite(raw)
	}
	return
}

// CipherSuites -
type CipherSuites []CipherSuite

// Decode -
func (s *CipherSuites) Decode(r io.Reader) (err error) {
	var v CipherSuites

	var aux uint16
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			for r := bytes.NewBuffer(raw); r.Len() > 0 && err == nil; {
				var w CipherSuite
				if err = w.Decode(r); err == nil {
					v = append(v, w)
				}
			}
		}
	}

	if err == nil {
		*s = v
	}
	return nil
}

// CompressionMethod -
type CompressionMethod uint8

// Decode -
func (s *CompressionMethod) Decode(r io.Reader) (err error) {
	var raw uint8
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = CompressionMethod(raw)
	}
	return
}

// CompressionMethods -
type CompressionMethods []CompressionMethod

// Decode -
func (s *CompressionMethods) Decode(r io.Reader) (err error) {
	var v CompressionMethods

	var aux uint8
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			for r := bytes.NewBuffer(raw); r.Len() > 0 && err == nil; {
				var w CompressionMethod
				if err = w.Decode(r); err == nil {
					v = append(v, w)
				}
			}
		}
	}

	if err == nil {
		*s = v
	}
	return
}

// ClientHello -
type ClientHello struct {
	ClientVersion      ProtocolVersion
	Random             Random
	SessionID          SessionID
	CipherSuites       CipherSuites
	CompressionMethods CompressionMethods
	Extensions         HelloExtensions
}

// Decode -
func (s *ClientHello) Decode(r io.Reader) (err error) {
	var v ClientHello

	fn := []func(io.Reader) error{
		v.ClientVersion.Decode,
		v.Random.Decode,
		v.SessionID.Decode,
		v.CipherSuites.Decode,
		v.CompressionMethods.Decode,
	}
	for i := 0; i < len(fn) && err == nil; i++ {
		err = fn[i](r)
	}
	if err == nil && v.ClientVersion >= tls.VersionTLS12 {
		err = v.Extensions.Decode(r)
	}

	if err == nil {
		*s = v
	}
	return
}

// ServerHello -
type ServerHello struct {
	ServerVersion     ProtocolVersion
	Random            Random
	SessionID         SessionID
	CipherSuite       CipherSuite
	CompressionMethod CompressionMethod
	Extensions        HelloExtensions
}

// Decode -
func (s *ServerHello) Decode(r io.Reader) (err error) {
	var v ServerHello

	fn := []func(io.Reader) error{
		v.ServerVersion.Decode,
		v.Random.Decode,
		v.SessionID.Decode,
		v.CipherSuite.Decode,
		v.CompressionMethod.Decode,
	}
	for i := 0; i < len(fn) && err == nil; i++ {
		err = fn[i](r)
	}
	if err == nil && v.ServerVersion >= tls.VersionTLS12 {
		err = v.Extensions.Decode(r)
	}

	if err == nil {
		*s = v
	}
	return
}
