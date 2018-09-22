package recordfmt_test

import (
	"bytes"
	"testing"

	"github.com/maxbet1507/tlsaux/recordfmt"
)

func TestTLSPlaintextDecode(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		// content type
		0x10,
		// protocol version
		0x20, 0x21,
		// fragment length
		0x00, 0x05,
		// fragment
		0x30, 0x31, 0x32, 0x33, 0x34,

		// debris
		0x40,
	})

	var val recordfmt.TLSPlaintext
	if err := val.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if val.Type != 0x10 {
		t.Fatal(val)
	}
	if val.Version != 0x2021 {
		t.Fatal(val)
	}
	if bytes.Compare(val.Fragment, []byte{0x30, 0x31, 0x32, 0x33, 0x34}) != 0 {
		t.Fatal(val)
	}

	if v := buf.Bytes(); bytes.Compare(v, []byte{0x40}) != 0 {
		t.Fatal(v)
	}
}
