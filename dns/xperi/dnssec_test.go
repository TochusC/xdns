// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dnssec_test.go 文件定义了对 dnssec.go 的单元测试

package xperi

import (
	"net"
	"testing"

	"github.com/tochusc/godns/dns"
)

// TestGenWrongKeyWithTag 测试 GenWrongKeyWithTag 函数
func TestGenWrongKeyWithTag(t *testing.T) {
	key := GenWrongKeyWithTag(dns.DNSSECAlgorithmRSASHA256, dns.DNSKEYFlagZoneKey, 12345)
	if dns.CalculateKeyTag(key) != 12345 {
		t.Errorf("Key Tag not match, got: %d, expected: %d", dns.CalculateKeyTag(key), 12345)
	}
}

// TestGenKeyWithTag 测试 GenKeyWithTag 函数
// func TestGenKeyWithTag(t *testing.T) {
// 	key := GenKeyWithTag(dns.DNSSECAlgorithmRSASHA256, dns.DNSKEYFlagZoneKey, 12345)
// 	if dns.CalculateKeyTag(key) != 12345 {
// 		t.Errorf("Key Tag not match, got: %d, expected: %d", dns.CalculateKeyTag(key), 12345)
// 	}
// }

// TestGenRandomRRSIG 测试 GenRandomRRSIG 函数
func TestGenRandomRRSIG(t *testing.T) {
	rrSet := []dns.DNSResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   7200,
			RData: &dns.DNSRDATAA{
				Address: net.IPv4(10, 10, 3, 3),
			},
		},
	}
	rrsig := GenRandomRRSIG(rrSet, dns.DNSSECAlgorithmRSASHA256,
		7200, 3600, 12345, "example.com.")

	t.Logf("RRSIG: %s", rrsig.String())
}
