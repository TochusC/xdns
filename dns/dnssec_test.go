// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// dnssec_test.go 文件定义了 DNSSEC 的单元测试

package dns

import (
	"net"
	"testing"
)

func TestGenerateDNSKEY(t *testing.T) {
	pubKey, _ := GenerateDNSKEY(DNSSECAlgorithmRSASHA256, DNSKEYFlagZoneKey)
	if pubKey.Flags != DNSKEYFlagZoneKey {
		t.Errorf("Flag not match")
	}
	if pubKey.Protocol != 3 {
		t.Errorf("Protocol not match")
	}
	if pubKey.Algorithm != DNSSECAlgorithmRSASHA256 {
		t.Errorf("Algorithm not match")
	}
	t.Logf("Public Key: %s", pubKey.String())
}

func TestCalculateKeyTag(t *testing.T) {
	key := DNSRDATADNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: []byte{
			0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc7, 0x7f, 0x6d, 0x0b, 0x7b, 0x4e, 0x6d,
			0x4f, 0x6c, 0x1c, 0x1c, 0x4d, 0x7c, 0x1a, 0x3b, 0x3d, 0x6e, 0x7e, 0x1c, 0x5c, 0x4c, 0x0e, 0x4d,
		},
	}
	keyTag := CalculateKeyTag(key)
	t.Logf("Key Tag: %d", keyTag)
}

func TestGenerateRRSIG(t *testing.T) {
	rrSet := []DNSResourceRecord{
		{
			Name:  "example.com.",
			Type:  DNSRRTypeA,
			Class: DNSClassIN,
			TTL:   7200,
			RData: &DNSRDATAA{
				Address: net.ParseIP("10.10.3.3"),
			},
		},
	}
	pubKey, privKey := GenerateDNSKEY(DNSSECAlgorithmRSASHA256, DNSKEYFlagZoneKey)
	rrsig := GenerateRRSIG(
		rrSet,
		DNSSECAlgorithmRSASHA256,
		7200,
		3600,
		CalculateKeyTag(pubKey),
		"example.com.",
		privKey,
	)
	t.Logf("RRSIG: %s", rrsig.String())
}

// Flag: SEP, KeyTag: 30130, Algo: ECDSAP384SHA384
var testedKeyBase64 = "MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY"

func TestParseKeyBase64(t *testing.T) {
	key := ParseKeyBase64(testedKeyBase64)
	t.Logf("Key Length:%d, Key: %v", len(key), key)
}

func TestCalculateKeyTagFromBase64(t *testing.T) {
	key := ParseKeyBase64(testedKeyBase64)
	kRDATA := DNSRDATADNSKEY{
		Flags:     DNSKEYFlagSecureEntryPoint,
		Protocol:  DNSKEYProtocolValue,
		Algorithm: DNSSECAlgorithmECDSAP384SHA384,
		PublicKey: key,
	}
	keyTag := CalculateKeyTag(kRDATA)
	if keyTag != 30130 {
		t.Errorf("Key Tag not match")
	}
}
