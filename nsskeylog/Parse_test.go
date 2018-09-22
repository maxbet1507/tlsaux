package nsskeylog_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/maxbet1507/tlsaux/nsskeylog"
	"github.com/pkg/errors"
)

func TestParse(t *testing.T) {
	line := strings.Join([]string{
		"CLIENT_RANDOM",
		" ",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		" ",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"\n",
	}, "")

	label, crand, secret, err := nsskeylog.Parse(line)
	if err != nil ||
		label.String() != nsskeylog.ClientRandom.String() ||
		hex.EncodeToString(crand) != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ||
		hex.EncodeToString(secret) != "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" {
		t.Fatal(label, crand, secret, err)
	}
}

func TestParseError_UnknownLabel(t *testing.T) {
	line := strings.Join([]string{
		"cLIENT_RANDOM",
		" ",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		" ",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"\n",
	}, "")

	_, _, _, err := nsskeylog.Parse(line)
	if errors.Cause(err) != nsskeylog.ErrInvalidFormat {
		t.Fatal(err)
	}
}

func TestParseError_ClientRamdomLength(t *testing.T) {
	line := strings.Join([]string{
		"CLIENT_RANDOM",
		" ",
		"ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		" ",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"\n",
	}, "")

	_, _, _, err := nsskeylog.Parse(line)
	if errors.Cause(err) != nsskeylog.ErrInvalidFormat {
		t.Fatal(err)
	}
}

func TestParseError_SingleSpace(t *testing.T) {
	line := strings.Join([]string{
		"CLIENT_RANDOM",
		"  ",
		"ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		" ",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"\n",
	}, "")

	_, _, _, err := nsskeylog.Parse(line)
	if errors.Cause(err) != nsskeylog.ErrInvalidFormat {
		t.Fatal(err)
	}
}
