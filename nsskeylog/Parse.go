package nsskeylog

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// Label -
type Label int

func (s Label) String() string {
	return label2string[s]
}

// -
const (
	Unknown Label = iota
	RSA
	ClientRandom
	ClientEarlyTrafficSecret
	ServerEarlyTrafficSecret
	ClientHandshakeTrafficSecret
	ServerHandshakeTrafficSecret
	ClientTrafficSecret0
	ServerTrafficSecret0
	EarlyExporterSecret
	ExporterSecret
)

// -
var (
	ErrInvalidFormat = fmt.Errorf("Invalid Format")

	label2string      map[Label]string
	label2decode      map[Label]func(string) ([]byte, error)
	string2label      map[string]Label
	hexDecodeString32 func(string) ([]byte, error)
	hexDecodeString48 func(string) ([]byte, error)
)

func init() {
	hexDecodeStringN := func(l int) func(string) ([]byte, error) {
		return func(v string) (ret []byte, err error) {
			if ret, err = hex.DecodeString(v); err == nil {
				err = assert(len(ret) == l, ErrInvalidFormat)
				err = errors.Wrap(err, "Length")
			}
			return
		}
	}
	hexDecodeString32 = hexDecodeStringN(32)
	hexDecodeString48 = hexDecodeStringN(48)

	label2string = map[Label]string{
		RSA:                          "RSA",
		ClientRandom:                 "CLIENT_RANDOM",
		ClientEarlyTrafficSecret:     "CLIENT_EARLY_TRAFFIC_SECRET",
		ServerEarlyTrafficSecret:     "SERVER_EARLY_TRAFFIC_SECRET",
		ClientHandshakeTrafficSecret: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		ServerHandshakeTrafficSecret: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
		ClientTrafficSecret0:         "CLIENT_TRAFFIC_SECRET_0",
		ServerTrafficSecret0:         "SERVER_TRAFFIC_SECRET_0",
		EarlyExporterSecret:          "EARLY_EXPORTER_SECRET",
		ExporterSecret:               "EXPORTER_SECRET",
	}

	label2decode = map[Label]func(string) ([]byte, error){
		RSA:                          hexDecodeString48,
		ClientRandom:                 hexDecodeString48,
		ClientEarlyTrafficSecret:     hex.DecodeString,
		ServerEarlyTrafficSecret:     hex.DecodeString,
		ClientHandshakeTrafficSecret: hex.DecodeString,
		ServerHandshakeTrafficSecret: hex.DecodeString,
		ClientTrafficSecret0:         hex.DecodeString,
		ServerTrafficSecret0:         hex.DecodeString,
		EarlyExporterSecret:          hex.DecodeString,
		ExporterSecret:               hex.DecodeString,
	}

	string2label = map[string]Label{}
	for l, s := range label2string {
		string2label[s] = l
	}
}

type rawParser struct {
	Error        error
	Columns      []string
	Label        Label
	ClientRandom []byte
	Secret       []byte
}

func (s *rawParser) ParseLine(v string) {
	if s.Error == nil {
		v = strings.TrimSpace(v)
		s.Columns = strings.SplitN(v, " ", 3)
		s.Error = assert(len(s.Columns) == 3, ErrInvalidFormat)
		s.Error = errors.Wrap(s.Error, "Columns")
	}
	return
}

func (s *rawParser) ParseLabel() (err error) {
	if s.Error == nil {
		var ok bool
		s.Label, ok = string2label[s.Columns[0]]
		s.Error = assert(ok, ErrInvalidFormat)
		s.Error = errors.Wrap(s.Error, "Label")
	}
	return
}

func (s *rawParser) ParseClientRandom() {
	if s.Error == nil {
		s.ClientRandom, s.Error = hexDecodeString32(s.Columns[1])
		s.Error = errors.Wrap(s.Error, "ClientRandom")
	}
	return
}

func (s *rawParser) ParseSecret() {
	if s.Error == nil {
		fn := label2decode[s.Label]
		s.Error = assert(fn != nil, ErrInvalidFormat)
		if s.Error == nil {
			s.Secret, s.Error = fn(s.Columns[2])
		}
		s.Error = errors.Wrap(s.Error, "Secret")
	}
	return
}

// Parse -
func Parse(v string) (Label, []byte, []byte, error) {
	var r rawParser
	r.ParseLine(v)
	r.ParseLabel()
	r.ParseClientRandom()
	r.ParseSecret()
	return r.Label, r.ClientRandom, r.Secret, r.Error
}
