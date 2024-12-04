// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// standard_test.go

package dns

import (
	"bytes"
	"net"
	"testing"
)

// 测试域名 www.example.com
var testedDomainName = "www.example.com"     // 相对域名
var testedAbsDomainName = "www.example.com." // 绝对域名

// www.example.com. 的域名编码结果
// 3, www, 7, example, 3, com, 0
var expectedEncodedName = []byte{
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
}

// 测试GetDomainNameWireLen函数
func TestGetDomainNameWireLen(t *testing.T) {
	// 测试相对域名
	nameLength := GetDomainNameWireLen(&testedDomainName)
	expectedLength := len(expectedEncodedName)
	if nameLength != expectedLength {
		t.Errorf("function GetDomainNameWireLen() failed:\ngot:%d\nexpected: %d",
			nameLength, expectedLength)
	}

	// 测试绝对域名
	nameLength = GetDomainNameWireLen(&testedAbsDomainName)
	if nameLength != expectedLength {
		t.Errorf("function GetDomainNameWireLen() failed:\ngot:%d\nexpected: %d",
			nameLength, expectedLength)
	}
}

// 测试EncodeDomainName函数
func TestEncodeDomainName(t *testing.T) {
	// 测试相对域名
	encodedName := EncodeDomainName(&testedDomainName)
	if !bytes.Equal(encodedName, expectedEncodedName) {
		t.Errorf(
			"EncodeDomainName() failed:\ngot:\n%v\n expected:\n%v",
			encodedName, expectedEncodedName)
	}

	// 测试绝对域名
	encodedName = EncodeDomainName(&testedAbsDomainName)
	if !bytes.Equal(encodedName, expectedEncodedName) {
		t.Errorf("function EncodeDomainName() failed:\ngot:\n%v\nexpected:\n%v",
			encodedName, expectedEncodedName)
	}
}

// 测试DecodeDomainName函数
func TestDecodeDomainName(t *testing.T) {
	decodedName := DecodeDomainName(expectedEncodedName)
	if decodedName != testedDomainName {
		t.Errorf("function DecodeDomainName() failed:\ngot: %s\nexpected: %s",
			decodedName, testedDomainName)
	}
}

// 测试EncodeDomainNameToBuffer函数
func TestEncodeDomainNameToBuffer(t *testing.T) {
	// 测试能否正确编码
	buffer := make([]byte, len(expectedEncodedName))
	_, err := EncodeDomainNameToBuffer(&testedDomainName, buffer)
	if err != nil {
		t.Errorf("function EncodeDomainNameToBuffer() failed:\ngot: %s\nexpected: nil", err)
	}
	if !bytes.Equal(buffer, expectedEncodedName) {
		t.Errorf("function EncodeDomainNameToBuffer() failed:\ngot: %v\nexpected: %v", buffer, expectedEncodedName)
	}

	// 测试能否处理缓冲区过小的情况
	buffer = make([]byte, len(expectedEncodedName)-1)
	_, err = EncodeDomainNameToBuffer(&testedDomainName, buffer)
	if err == nil {
		t.Errorf("function EncodeDomainNameToBuffer() failed:\ngot: nil\nexpected: error")
	}
}

func TestCanonicalSortRRSet(t *testing.T) {
	rrSet := []DNSResourceRecord{
		{
			Name:  "example.com.",
			Type:  DNSRRTypeA,
			Class: DNSClassIN,
			TTL:   7200,
			RData: &DNSRDATAA{
				Address: net.IPv4(10, 10, 3, 6),
			},
		},
		{
			Name:  "example.com.",
			Type:  DNSRRTypeA,
			Class: DNSClassIN,
			TTL:   7200,
			RData: &DNSRDATAA{
				Address: net.IPv4(10, 10, 3, 4),
			},
		},
		{
			Name:  "example.com.",
			Type:  DNSRRTypeA,
			Class: DNSClassIN,
			TTL:   7200,
			RData: &DNSRDATAA{
				Address: net.IPv4(10, 10, 3, 5),
			},
		},
	}
	CanonicalSortRRSet(rrSet)
	t.Logf("CanonicalSortRRSet: %v", rrSet)
}

func TestCompressDNSMessage(t *testing.T) {
	msg := DNSMessage{
		Header: DNSHeader{
			ID:      0x1234,
			QR:      true,
			OpCode:  DNSOpCodeQuery,
			AA:      false,
			TC:      false,
			RD:      true,
			RA:      false,
			Z:       0,
			RCode:   DNSResponseCodeNoErr,
			QDCount: 1,
			ANCount: 3,
			NSCount: 0,
		},
		Question: []DNSQuestion{
			{
				Name:  "example.com",
				Type:  DNSRRTypeA,
				Class: DNSClassIN,
			},
		},
		Answer: []DNSResourceRecord{
			{
				Name:  "example.com",
				Type:  DNSRRTypeA,
				Class: DNSClassIN,
				TTL:   7200,
				RData: &DNSRDATAA{
					Address: net.IPv4(10, 10, 3, 6),
				},
			},
			{
				Name:  "example.com",
				Type:  DNSRRTypeA,
				Class: DNSClassIN,
				TTL:   7200,
				RData: &DNSRDATAA{
					Address: net.IPv4(10, 10, 3, 4),
				},
			},
			{
				Name:  "example.com",
				Type:  DNSRRTypeA,
				Class: DNSClassIN,
				TTL:   7200,
				RData: &DNSRDATAA{
					Address: net.IPv4(10, 10, 3, 5),
				},
			},
		},
	}
	t.Logf("Original DNS Message: %v", msg)
	msgBytes := msg.Encode()
	cMsg, err := CompressDNSMessage(msgBytes)
	if err != nil {
		t.Errorf("CompressDNSMessage() failed: %s", err)
	}

	nrMsg := DNSMessage{}
	nrMsg.DecodeFromBuffer(msgBytes, 0)
	t.Logf("Decoded Originial DNS Message: %v", nrMsg)

	rMsg := DNSMessage{}
	rMsg.DecodeFromBuffer(cMsg, 0)
	t.Logf("Decoded Compressed DNS Message: %v", rMsg)
}
