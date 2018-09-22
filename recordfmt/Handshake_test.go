package recordfmt_test

import (
	"bytes"
	"testing"

	"github.com/maxbet1507/tlsaux/recordfmt"
)

func TestHandshakeUnmarshal(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// handshake type
		0x10,
		// body length
		0x00, 0x00, 0x05,
		// body
		0x20, 0x21, 0x22, 0x23, 0x24,

		// debris
		0x30,
	})

	var val recordfmt.Handshake
	if err := val.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if val.MsgType != 0x10 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Body, []byte{0x20, 0x21, 0x22, 0x23, 0x24}) != 0 {
		t.Fatal(val)
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x30}) != 0 {
		t.Fatal(v)
	}
}

func TestHelloExtensionUnmarshal(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// extension[0] type
		0x10, 0x11,
		// extension[0] length
		0x00, 0x05,
		// extension[0] data
		0x20, 0x21, 0x22, 0x23, 0x24,

		// debris
		0x30,
	})

	var val recordfmt.HelloExtension
	if err := val.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if val.ExtensionType != 0x1011 {
		t.Fatal(val)
	}
	if bytes.Compare(val.ExtensionData, []byte{0x20, 0x21, 0x22, 0x23, 0x24}) != 0 {
		t.Fatal(val)
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x30}) != 0 {
		t.Fatal(v)
	}
}

func TestHelloExtensionsUnmarshal(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// extensions length
		0x00, 0x09,
		// extension[0] type
		0x10, 0x11,
		// extension[0] length
		0x00, 0x05,
		// extension[0] data
		0x20, 0x21, 0x22, 0x23, 0x24,

		// debris
		0x30,
	})

	var val recordfmt.HelloExtensions
	if err := val.Decode(buf); len(val) != 1 || err != nil {
		t.Fatal(val, err)
	}

	if val[0].ExtensionType != 0x1011 {
		t.Fatal(val[0])
	}
	if bytes.Compare(val[0].ExtensionData, []byte{0x20, 0x21, 0x22, 0x23, 0x24}) != 0 {
		t.Fatal(val[0])
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x30}) != 0 {
		t.Fatal(v)
	}
}

func TestHelloExtensionsUnmarshal_NoExtensions(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	val := recordfmt.HelloExtensions{recordfmt.HelloExtension{}}

	if err := val.Decode(buf); len(val) != 0 || err != nil {
		t.Fatal(val, err)
	}
}

func TestClientHelloUnmarshal_TLS12(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// server version
		0x03, 0x03,
		// server random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		// session id length
		0x01,
		// session id
		0x20,
		// cipher suites length
		0x00, 0x02,
		// cipher suites[0]
		0x30, 0x31,
		// compression methods length
		0x01,
		// compression methods[0]
		0x40,

		// extensions length
		0x00, 0x09,
		// extension[0] type
		0x50, 0x51,
		// extension[0] length
		0x00, 0x05,
		// extension[0] data
		0x60, 0x61, 0x62, 0x63, 0x64,

		// debris
		0x70,
	})

	var val recordfmt.ClientHello
	if err := val.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if val.ClientVersion != 0x0303 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Random[:], []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}) != 0 {
		t.Fatal(val)
	}
	if bytes.Compare(val.SessionID, []byte{0x20}) != 0 {
		t.Fatal(val)
	}
	if len(val.CipherSuites) != 1 || val.CipherSuites[0] != 0x3031 {
		t.Fatal(val)
	}
	if len(val.CompressionMethods) != 1 || val.CompressionMethods[0] != 0x40 {
		t.Fatal(val)
	}
	if len(val.Extensions) != 1 {
		t.Fatal(val)
	}
	if val.Extensions[0].ExtensionType != 0x5051 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Extensions[0].ExtensionData, []byte{0x60, 0x61, 0x62, 0x63, 0x64}) != 0 {
		t.Fatal(val)
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x70}) != 0 {
		t.Fatal(v)
	}
}

func TestServerHelloUnmarshal_TLS12(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// server version
		0x03, 0x03,
		// server random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		// session id length
		0x01,
		// session id
		0x20,
		// cipher suite
		0x30, 0x31,
		// compression method
		0x40,

		// extensions length
		0x00, 0x09,
		// extension[0] type
		0x50, 0x51,
		// extension[0] length
		0x00, 0x05,
		// extension[0] data
		0x60, 0x61, 0x62, 0x63, 0x64,

		// debris
		0x70,
	})

	var val recordfmt.ServerHello
	if err := val.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if val.ServerVersion != 0x0303 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Random[:], []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}) != 0 {
		t.Fatal(val)
	}
	if bytes.Compare(val.SessionID, []byte{0x20}) != 0 {
		t.Fatal(val)
	}
	if val.CipherSuite != 0x3031 {
		t.Fatal(val)
	}
	if val.CompressionMethod != 0x40 {
		t.Fatal(val)
	}
	if len(val.Extensions) != 1 {
		t.Fatal(val)
	}
	if val.Extensions[0].ExtensionType != 0x5051 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Extensions[0].ExtensionData, []byte{0x60, 0x61, 0x62, 0x63, 0x64}) != 0 {
		t.Fatal(val)
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x70}) != 0 {
		t.Fatal(v)
	}
}
