package recordfmt

import (
	"encoding/binary"
	"io"
)

// ContentType -
type ContentType int

// -
const (
	TypeChangeCipherSpec = ContentType(20)
	TypeAlert            = ContentType(21)
	TypeHandshake        = ContentType(22)
	TypeApplicationData  = ContentType(23)
)

// Decode -
func (s *ContentType) Decode(r io.Reader) (err error) {
	var raw uint8
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = ContentType(raw)
	}
	return
}

// ProtocolVersion -
type ProtocolVersion int

// Decode -
func (s *ProtocolVersion) Decode(r io.Reader) (err error) {
	var raw uint16
	if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
		*s = ProtocolVersion(raw)
	}
	return
}

// Fragment -
type Fragment []byte

// Decode -
func (s *Fragment) Decode(r io.Reader) (err error) {
	var aux uint16
	if err = binary.Read(r, binary.BigEndian, &aux); err == nil {
		raw := make([]byte, aux)
		if err = binary.Read(r, binary.BigEndian, &raw); err == nil {
			*s = raw
		}
	}
	return
}

// TLSPlaintext -
type TLSPlaintext struct {
	Type     ContentType
	Version  ProtocolVersion
	Fragment Fragment
}

// Decode -
func (s *TLSPlaintext) Decode(r io.Reader) (err error) {
	var v TLSPlaintext

	fn := []func(io.Reader) error{
		v.Type.Decode,
		v.Version.Decode,
		v.Fragment.Decode,
	}
	for i := 0; i < len(fn) && err == nil; i++ {
		err = fn[i](r)
	}

	if err == nil {
		*s = v
	}
	return
}
