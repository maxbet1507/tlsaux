package prf

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"hash"
)

func hsum(h hash.Hash, v ...[]byte) []byte {
	h.Reset()
	for _, v := range v {
		h.Write(v) // always success
	}
	return h.Sum(nil)
}

func phash(hashfn func() hash.Hash, result, secret, seed []byte) {
	hmac := hmac.New(hashfn, secret)
	an := seed

	var concat []byte
	for len(concat) < len(result) {
		an = hsum(hmac, an)
		concat = append(concat, hsum(hmac, an, seed)...)
	}
	copy(result, concat)
}

func prf10(result, secret, label, seed []byte) {
	s1 := secret[:(len(secret)+1)/2]
	s2 := secret[len(secret)/2:]
	labelseed := append(label, seed...)

	r1 := make([]byte, len(result))
	r2 := make([]byte, len(result))

	phash(md5.New, r1, s1, labelseed)
	phash(sha1.New, r2, s2, labelseed)

	for i := range result {
		result[i] = r1[i] ^ r2[i]
	}
}

func prf12(hashfn func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelseed := append(label, seed...)
		phash(hashfn, result, secret, labelseed)
	}
}

var (
	tls12hash = map[uint16]func() hash.Hash{
		0x009D: sha512.New384, //RSA_WITH_AES_256_GCM_SHA384
		0x009F: sha512.New384, //DHE_RSA_WITH_AES_256_GCM_SHA384
		0x00A1: sha512.New384, //DH_RSA_WITH_AES_256_GCM_SHA384
		0x00A3: sha512.New384, //DHE_DSS_WITH_AES_256_GCM_SHA384
		0x00A5: sha512.New384, //DH_DSS_WITH_AES_256_GCM_SHA384
		0x00A7: sha512.New384, //DH_anon_WITH_AES_256_GCM_SHA384
		0x00A9: sha512.New384, //PSK_WITH_AES_256_GCM_SHA384
		0x00AB: sha512.New384, //DHE_PSK_WITH_AES_256_GCM_SHA384
		0x00AD: sha512.New384, //RSA_PSK_WITH_AES_256_GCM_SHA384
		0x00AF: sha512.New384, //PSK_WITH_AES_256_CBC_SHA384
		0x00B1: sha512.New384, //PSK_WITH_NULL_SHA384
		0x00B3: sha512.New384, //DHE_PSK_WITH_AES_256_CBC_SHA384
		0x00B5: sha512.New384, //DHE_PSK_WITH_NULL_SHA384
		0x00B7: sha512.New384, //RSA_PSK_WITH_AES_256_CBC_SHA384
		0x00B9: sha512.New384, //RSA_PSK_WITH_NULL_SHA384
		0x1302: sha512.New384, //AES_256_GCM_SHA384
		0xC024: sha512.New384, //ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
		0xC026: sha512.New384, //ECDH_ECDSA_WITH_AES_256_CBC_SHA384
		0xC028: sha512.New384, //ECDHE_RSA_WITH_AES_256_CBC_SHA384
		0xC02A: sha512.New384, //ECDH_RSA_WITH_AES_256_CBC_SHA384
		0xC02C: sha512.New384, //ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC02E: sha512.New384, //ECDH_ECDSA_WITH_AES_256_GCM_SHA384
		0xC030: sha512.New384, //ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xC032: sha512.New384, //ECDH_RSA_WITH_AES_256_GCM_SHA384
		0xC038: sha512.New384, //ECDHE_PSK_WITH_AES_256_CBC_SHA384
		0xC03B: sha512.New384, //ECDHE_PSK_WITH_NULL_SHA384
		0xC03D: sha512.New384, //RSA_WITH_ARIA_256_CBC_SHA384
		0xC03F: sha512.New384, //DH_DSS_WITH_ARIA_256_CBC_SHA384
		0xC041: sha512.New384, //DH_RSA_WITH_ARIA_256_CBC_SHA384
		0xC043: sha512.New384, //DHE_DSS_WITH_ARIA_256_CBC_SHA384
		0xC045: sha512.New384, //DHE_RSA_WITH_ARIA_256_CBC_SHA384
		0xC047: sha512.New384, //DH_anon_WITH_ARIA_256_CBC_SHA384
		0xC049: sha512.New384, //ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
		0xC04B: sha512.New384, //ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
		0xC04D: sha512.New384, //ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
		0xC04F: sha512.New384, //ECDH_RSA_WITH_ARIA_256_CBC_SHA384
		0xC051: sha512.New384, //RSA_WITH_ARIA_256_GCM_SHA384
		0xC053: sha512.New384, //DHE_RSA_WITH_ARIA_256_GCM_SHA384
		0xC055: sha512.New384, //DH_RSA_WITH_ARIA_256_GCM_SHA384
		0xC057: sha512.New384, //DHE_DSS_WITH_ARIA_256_GCM_SHA384
		0xC059: sha512.New384, //DH_DSS_WITH_ARIA_256_GCM_SHA384
		0xC05B: sha512.New384, //DH_anon_WITH_ARIA_256_GCM_SHA384
		0xC05D: sha512.New384, //ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
		0xC05F: sha512.New384, //ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
		0xC061: sha512.New384, //ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
		0xC063: sha512.New384, //ECDH_RSA_WITH_ARIA_256_GCM_SHA384
		0xC065: sha512.New384, //PSK_WITH_ARIA_256_CBC_SHA384
		0xC067: sha512.New384, //DHE_PSK_WITH_ARIA_256_CBC_SHA384
		0xC069: sha512.New384, //RSA_PSK_WITH_ARIA_256_CBC_SHA384
		0xC06B: sha512.New384, //PSK_WITH_ARIA_256_GCM_SHA384
		0xC06D: sha512.New384, //DHE_PSK_WITH_ARIA_256_GCM_SHA384
		0xC06F: sha512.New384, //RSA_PSK_WITH_ARIA_256_GCM_SHA384
		0xC071: sha512.New384, //ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
		0xC073: sha512.New384, //ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
		0xC075: sha512.New384, //ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
		0xC077: sha512.New384, //ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
		0xC079: sha512.New384, //ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
		0xC07B: sha512.New384, //RSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC07D: sha512.New384, //DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC07F: sha512.New384, //DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC081: sha512.New384, //DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
		0xC083: sha512.New384, //DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
		0xC085: sha512.New384, //DH_anon_WITH_CAMELLIA_256_GCM_SHA384
		0xC087: sha512.New384, //ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC089: sha512.New384, //ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC08B: sha512.New384, //ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC08D: sha512.New384, //ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
		0xC08F: sha512.New384, //PSK_WITH_CAMELLIA_256_GCM_SHA384
		0xC091: sha512.New384, //DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
		0xC093: sha512.New384, //RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
		0xC095: sha512.New384, //PSK_WITH_CAMELLIA_256_CBC_SHA384
		0xC097: sha512.New384, //DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
		0xC099: sha512.New384, //RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
		0xC09B: sha512.New384, //ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
		0xC0B1: sha512.New384, //ECCPWD_WITH_AES_256_GCM_SHA384
		0xC0B3: sha512.New384, //ECCPWD_WITH_AES_256_CCM_SHA384
		0xD002: sha512.New384, //ECDHE_PSK_WITH_AES_256_GCM_SHA384
	}
)

// New -
func New(version int, ciphersuite uint16) (fn func(result, secret, label, seed []byte)) {
	switch version {
	case tls.VersionTLS10, tls.VersionTLS11:
		fn = prf10

	case tls.VersionTLS12:
		if hashfn := tls12hash[ciphersuite]; hashfn != nil {
			fn = prf12(hashfn)
		} else {
			fn = prf12(sha256.New)
		}
	}
	return
}
