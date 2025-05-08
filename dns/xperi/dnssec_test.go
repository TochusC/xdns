// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dnssec_test.go 文件定义了对 dnssec.go 的单元测试

package xperi

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"

	"github.com/tochusc/xdns/dns"
)

func TestMyTest(t *testing.T) {
	nsrdata := dns.DNSRDATANS{
		NSDNAME: "ns.test.",
	}
	t.Logf("NSRR: %s", nsrdata.Encode())

}

func TestGenerateKSKDS(t *testing.T) {
	kskPublic := ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	ksk := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  3,
		Algorithm: dns.DNSSECAlgorithmECDSAP384SHA384,
		PublicKey: kskPublic,
	}
	ds := GenerateRDATADS("test.", ksk, dns.DNSSECDigestTypeSHA256)
	t.Logf("DS: %s\n, Digest: %s\n", ds.String(), hex.EncodeToString(ds.Digest))
}

// TestGenerateRandomKeyWithTag 测试 GenerateRandomKeyWithTag 函数
func TestGenerateCollidedDNSKEY(t *testing.T) {
	for i := 0; i < 200; i++ {
		key1, _ := GenerateRDATADNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
		key2 := GenerateCollidedDNSKEY(key1)
		if CalculateKeyTag(key1) != CalculateKeyTag(key2) {
			t.Errorf("Key Tag not match: %d != %d", CalculateKeyTag(key1), CalculateKeyTag(key2))
		}
	}
}

// TestGenerateRDATADNSKEY 测试 GenerateRDATADNSKEY 函数
func TestGenerateRDATADNSKEY(t *testing.T) {
	pubKey, privKey := GenerateRDATADNSKEY(dns.DNSSECAlgorithmED25519, dns.DNSKEYFlagSecureEntryPoint)
	// if pubKey.Flags != dns.DNSKEYFlagZoneKey {
	// 	t.Errorf("Flag not match")
	// }
	// if pubKey.Protocol != 3 {
	// 	t.Errorf("Protocol not match")
	// }
	// if pubKey.Algorithm != dns.DNSSECAlgorithmECDSAP384SHA384 {
	// 	t.Errorf("Algorithm not match")
	// }
	t.Logf("Public Key: %s", base64.StdEncoding.EncodeToString(pubKey.PublicKey))
	t.Logf("Private Key: %s", base64.StdEncoding.EncodeToString(privKey))
}

// TestGenKeyWithTag 测试 GenKeyWithTag 函数
func TestGenenrateDNSKEYWithTag(t *testing.T) {
	ksk, _ := GenerateRDATADNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
	keytag := CalculateKeyTag(ksk)
	key := GenerateDNSKEYWithTag(ksk, 1)
	if keytag != CalculateKeyTag(key)+1 {
		t.Errorf("Key Tag not match: %d != %d", keytag, CalculateKeyTag(key)+1)
	}
}

// TestGenRandomRRSIG 测试 GenRandomRRSIG 函数
func TestGenerateRandomRRSIG(t *testing.T) {
	rrSet := []dns.DNSResourceRecord{
		{
			Name:  *dns.NewDNSName("example.com."),
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   7200,
			RData: &dns.DNSRDATAA{
				Address: net.IPv4(10, 10, 3, 3),
			},
		},
	}
	rrsig := GenerateRandomRDATARRSIG(rrSet, dns.DNSSECAlgorithmRSASHA256,
		7200, 3600, 12345, "example.com.")

	t.Logf("RRSIG: %s", rrsig.String())
}

// TestGenRandomDNSKEY 测试 GenRandomDNSKEY 函数
func TestGenerateDNSKEY(t *testing.T) {
	pubKey, _ := GenerateRDATADNSKEY(dns.DNSSECAlgorithmRSASHA256, dns.DNSKEYFlagZoneKey)
	if pubKey.Flags != dns.DNSKEYFlagZoneKey {
		t.Errorf("Flag not match")
	}
	if pubKey.Protocol != 3 {
		t.Errorf("Protocol not match")
	}
	if pubKey.Algorithm != dns.DNSSECAlgorithmRSASHA256 {
		t.Errorf("Algorithm not match")
	}
	t.Logf("Public Key: %s", pubKey.String())
}

// TestCalculateKeyTag 测试计算 Key Tag
func TestCalculateKeyTag(t *testing.T) {
	key := dns.DNSRDATADNSKEY{
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

// TestGenerateRRSIG 测试生成 RRSIG 记录
func TestGenerateRRSIG(t *testing.T) {
	rrSet := []dns.DNSResourceRecord{
		{
			Name:  *dns.NewDNSName("example.com."),
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   7200,
			RData: &dns.DNSRDATAA{
				Address: net.ParseIP("10.10.3.3"),
			},
		},
	}
	pubKey, privKey := GenerateRDATADNSKEY(dns.DNSSECAlgorithmRSASHA256, dns.DNSKEYFlagZoneKey)
	rrsig := GenerateRDATARRSIG(
		rrSet,
		dns.DNSSECAlgorithmRSASHA256,
		7200,
		3600,
		CalculateKeyTag(pubKey),
		"example.com.",
		privKey,
	)
	t.Logf("RRSIG: %s", rrsig.String())
}

// TestGenerateDS 测试生成 DS 记录
func TestGenerateDS(t *testing.T) {
	pubKey, _ := GenerateRDATADNSKEY(dns.DNSSECAlgorithmRSASHA256, dns.DNSKEYFlagZoneKey)
	ds := GenerateRDATADS("test", pubKey, dns.DNSSECDigestTypeSHA1)
	t.Logf("DS: %s", ds.String())
}

// Flag: SEP, KeyTag: 30130, Algo: ECDSAP384SHA384
var testedKeyBase64 = "MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY"

// TestParseKeyBase64 测试解析 Base64 编码的密钥
func TestParseKeyBase64(t *testing.T) {
	key := ParseKeyBase64(testedKeyBase64)
	t.Logf("Key Length:%d, Key: %v", len(key), key)
}

// TestCalculateKeyTagFromBase64 测试从 Base64 编码的密钥计算 Key Tag
func TestCalculateKeyTagFromBase64(t *testing.T) {
	key := ParseKeyBase64(testedKeyBase64)
	kRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: dns.DNSSECAlgorithmECDSAP384SHA384,
		PublicKey: key,
	}
	keyTag := CalculateKeyTag(kRDATA)
	if keyTag != 30130 {
		t.Errorf("Key Tag not match")
	}
}
