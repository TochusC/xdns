// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// rdata_test.go 文件用于对 rdata.go 中所实现的 DNS 资源记录 RDATA 进行测试。

package dns

import (
	"bytes"
	"net"
	"testing"
)

// 待测试的 A 记录 RDATA 对象。
var testedDNSRDATAA = DNSRDATAA{
	Address: net.ParseIP("10.10.0.3"),
}

// 待测试的 A 记录 RDATA 编码后结果。
var testedDNSRDATAAEncoded = []byte{10, 10, 0, 3}

// TestDNSRDATAASize 测试 A 记录 RDATA 的 Size 方法。
func TestDNSRDATAASize(t *testing.T) {
	size := testedDNSRDATAA.Size()
	if size != 4 {
		t.Errorf("function Size() = %d, want 4", size)
	}
}

// 测试 A 记录 RDATA 的 String 方法。
func TestDNSRDATAAString(t *testing.T) {
	t.Logf("A RDATA String():\n%s", testedDNSRDATAA.String())
}

// 测试 A 记录 RDATA 的 Encode 方法。
func TestDNSRDATAAEncode(t *testing.T) {
	encodedDNSRDATAA := testedDNSRDATAA.Encode()
	if !bytes.Equal(encodedDNSRDATAA, testedDNSRDATAAEncoded) {
		t.Errorf("function Encode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATAA, testedDNSRDATAAEncoded)
	}
}

// 测试 A 记录 RDATA 的 EncodeToBuffer 方法。
func TestDNSRDATAAEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, 4)
	_, err := testedDNSRDATAA.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function EncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATAAEncoded) {
		t.Errorf("function EncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATAAEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATAA.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("function EncodeToBuffer() failed:\n%s", "expected an error but got nil")
	}
}

// 测试 A 记录 RDATA 的 DecodeFromBuffer 方法。
func TestDNSRDATAADecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATAA := DNSRDATAA{}
	offset, err := decodedDNSRDATAA.DecodeFromBuffer(testedDNSRDATAAEncoded, 0, 0)
	if err != nil {
		t.Errorf("function DecodeFromBuffer() failed:\n%s", err)
	}
	if offset != 4 {
		t.Errorf("function DecodeFromBuffer() failed:\ngot:%d\nexpected: %d", offset, 4)
	}
	if !decodedDNSRDATAA.Address.Equal(testedDNSRDATAA.Address) {
		t.Errorf("function DecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATAA.Address, testedDNSRDATAA.Address)
	}

	// 缓冲区长度不足
	decodedDNSRDATAA = DNSRDATAA{}
	_, err = decodedDNSRDATAA.DecodeFromBuffer(testedDNSRDATAAEncoded, 1, 0)
	if err == nil {
		t.Errorf("function DecodeFromBuffer() failed:\n%s", "expected an error but got nil")
	}
}

// 待测试的 NS RDATA 对象。
var testedDNSRDATANS = DNSRDATANS{
	NSDNAME: "ns.example.com",
}

// NS RDATA 的期望编码结果。
var testedDNSRDATANSEncoded = []byte{
	0x02, 'n', 's',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
}

// 测试 NS RDATA 的 Size 方法
func TestDNSRDATANSSize(t *testing.T) {
	size := testedDNSRDATANS.Size()
	expectedSize := len(testedDNSRDATANSEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATANSSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 NS RDATA 的 String 方法
func TestDNSRDATANSString(t *testing.T) {
	t.Logf("NS RDATA String():\n%s", testedDNSRDATANS.String())
}

// 测试 NS RDATA 的 Encode 方法
func TestDNSRDATANSEncode(t *testing.T) {
	encodedDNSRDATANS := testedDNSRDATANS.Encode()
	if !bytes.Equal(encodedDNSRDATANS, testedDNSRDATANSEncoded) {
		t.Errorf("function DNSRDATANSEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATANS, testedDNSRDATANSEncoded)
	}
}

// 测试 NS RDATA 的 EncodeToBuffer 方法
func TestDNSRDATANSEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATANSEncoded))
	_, err := testedDNSRDATANS.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATANSEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATANSEncoded) {
		t.Errorf("function DNSRDATANSEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATANSEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATANS.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("function DNSRDATANSEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 NS RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATANSDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATANS := DNSRDATANS{}
	offset, err := decodedDNSRDATANS.DecodeFromBuffer(testedDNSRDATANSEncoded, 0, 0)
	if err != nil {
		t.Errorf("function DNSRDATANSDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATANSEncoded) {
		t.Errorf("function DNSRDATANSDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATANSEncoded))
	}
	if decodedDNSRDATANS != testedDNSRDATANS {
		t.Errorf("function DNSRDATANSDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATANS, testedDNSRDATANS)
	}

	// 缓冲区长度不足
	decodedDNSRDATANS = DNSRDATANS{}
	_, err = decodedDNSRDATANS.DecodeFromBuffer(testedDNSRDATANSEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATANSDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 待测试CNAME记录RDATA对象。
var testedDNSRDATACNAME = DNSRDATACNAME{
	CNAME: "www.example.com",
}

// 待测试CNAME记录RDATA编码后结果。
var testedDNSRDATACNAMEEncoded = []byte{
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
}

// 测试 CNAME RDATA 的 Size 方法
func TestDNSRDATACNAMESize(t *testing.T) {
	size := testedDNSRDATACNAME.Size()
	expectedSize := len(testedDNSRDATACNAMEEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATACNAMESize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 CNAME RDATA 的 String 方法
func TestDNSRDATACNAMEString(t *testing.T) {
	t.Logf("CNAME RDATA String():\n%s", testedDNSRDATACNAME.String())
}

// 测试 CNAME RDATA 的 EncodeToBuffer 方法
func TestDNSRDATACNAMEEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATACNAMEEncoded))
	_, err := testedDNSRDATACNAME.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATACNAMEEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATACNAMEEncoded) {
		t.Errorf("function DNSRDATACNAMEEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATACNAMEEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATACNAME.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATACNAMEEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 CNAME RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATACNAMEDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATACNAME := DNSRDATACNAME{}
	offset, err := decodedDNSRDATACNAME.DecodeFromBuffer(testedDNSRDATACNAMEEncoded, 0, 0)
	if err != nil {
		t.Errorf("function DNSRDATACNAMEDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATACNAMEEncoded) {
		t.Errorf("function DNSRDATACNAMEDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATACNAMEEncoded))
	}
	if decodedDNSRDATACNAME != testedDNSRDATACNAME {
		t.Errorf("function DNSRDATACNAMEDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATACNAME, testedDNSRDATACNAME)
	}

	// 缓冲区长度不足
	decodedDNSRDATACNAME = DNSRDATACNAME{}
	_, err = decodedDNSRDATACNAME.DecodeFromBuffer(testedDNSRDATACNAMEEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATACNAMEDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 待测试TXT记录RDATA对象。
var testedDNSRDATATXT = DNSRDATATXT{
	TXT: "TXT",
}
var testedDNSRDATATXTEncoded = []byte{
	0x03, 'T', 'X', 'T',
}

// 测试 TXT RDATA 的 Size 方法
func TestDNSRDATATXTSize(t *testing.T) {
	size := testedDNSRDATATXT.Size()
	expectedSize := len(testedDNSRDATATXTEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATATXTSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 TXT RDATA 的 String 方法
func TestDNSRDATATXTString(t *testing.T) {
	t.Logf("TXT RDATA String():\n%s", testedDNSRDATATXT.String())
}

// 测试 TXT RDATA 的 Encode 方法
func TestDNSRDATATXTEncode(t *testing.T) {
	encodedDNSRDATATXT := testedDNSRDATATXT.Encode()
	if !bytes.Equal(encodedDNSRDATATXT, testedDNSRDATATXTEncoded) {
		t.Errorf("function DNSRDATATXTEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATATXT, testedDNSRDATATXTEncoded)
	}
}

// 测试 TXT RDATA 的 EncodeToBuffer 方法
func TestDNSRDATATXTEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATATXTEncoded))
	_, err := testedDNSRDATATXT.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATATXTEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATATXTEncoded) {
		t.Errorf("function DNSRDATATXTEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATATXTEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATATXT.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATATXTEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 RRSIG RDATA

// 待测试的 RRSIG 记录 RDATA 对象。
var testedDNSRDATARRSIG = DNSRDATARRSIG{
	TypeCovered: 1,
	Algorithm:   DNSSECAlgorithmRSASHA256,
	Labels:      3,
	OriginalTTL: 0x12345678,
	Expiration:  0x5f5e0d00,
	Inception:   0x5f5e0d00,
	KeyTag:      0x5f5e,
	SignerName:  "example.com",
	Signature:   []byte{0x01, 0x02, 0x03, 0x04},
}

// 待测试的 RRSIG 记录 RDATA 编码后结果。
var testedDNSRDATARRSIGEncoded = []byte{
	0x00, 0x01,
	0x08, 0x03,
	0x12, 0x34, 0x56, 0x78,
	0x5f, 0x5e, 0x0d, 0x00,
	0x5f, 0x5e, 0x0d, 0x00,
	0x5f, 0x5e,
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x01, 0x02, 0x03, 0x04,
}

// 测试 RRSIG RDATA 的 Size 方法
func TestDNSRDATARRSIGSize(t *testing.T) {
	size := testedDNSRDATARRSIG.Size()
	expectedSize := len(testedDNSRDATARRSIGEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATARRSIGSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 RRSIG RDATA 的 String 方法
func TestDNSRDATARRSIGString(t *testing.T) {
	t.Logf("RRSIG RDATA String():\n%s", testedDNSRDATARRSIG.String())
}

// 测试 RRSIG RDATA 的 Encode 方法
func TestDNSRDATARRSIGEncode(t *testing.T) {
	encodedDNSRDATARRSIG := testedDNSRDATARRSIG.Encode()
	if !bytes.Equal(encodedDNSRDATARRSIG, testedDNSRDATARRSIGEncoded) {
		t.Errorf("function DNSRDATARRSIGEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATARRSIG, testedDNSRDATARRSIGEncoded)
	}
}

// 测试 RRSIG RDATA 的 EncodeToBuffer 方法
func TestDNSRDATARRSIGEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATARRSIGEncoded))
	_, err := testedDNSRDATARRSIG.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATARRSIGEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATARRSIGEncoded) {
		t.Errorf("function DNSRDATARRSIGEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATARRSIGEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATARRSIG.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATARRSIGEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 RRSIG RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATARRSIGDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATARRSIG := DNSRDATARRSIG{}
	offset, err := decodedDNSRDATARRSIG.DecodeFromBuffer(testedDNSRDATARRSIGEncoded, 0, len(testedDNSRDATARRSIGEncoded))
	if err != nil {
		t.Errorf("function DNSRDATARRSIGDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATARRSIGEncoded) {
		t.Errorf("function DNSRDATARRSIGDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATARRSIGEncoded))
	}
	if decodedDNSRDATARRSIG.Equal(&testedDNSRDATARRSIG) {
		t.Errorf("function DNSRDATARRSIGDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATARRSIG.String(), testedDNSRDATARRSIG.String())
	}

	// 缓冲区长度不足
	decodedDNSRDATARRSIG = DNSRDATARRSIG{}
	_, err = decodedDNSRDATARRSIG.DecodeFromBuffer(testedDNSRDATARRSIGEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATARRSIGDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 测试 DNSKEY RDATA

// 待测试的 DNSKEY 记录 RDATA 对象。
var testedDNSRDATADNSKEY = DNSRDATADNSKEY{
	Flags:     DNSKEYFlagZoneKey,
	Protocol:  DNSKEYProtocolValue,
	Algorithm: DNSSECAlgorithmRSASHA256,
	PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
}

// 待测试的 DNSKEY 记录 RDATA 编码后结果。
var testedDNSRDATADNSKEYEncoded = []byte{
	0x01, 0x00,
	0x03,
	0x08,
	0x01, 0x02, 0x03, 0x04,
}

// 测试 DNSKEY RDATA 的 Size 方法
func TestDNSRDATADNSKEYSize(t *testing.T) {
	size := testedDNSRDATADNSKEY.Size()
	expectedSize := len(testedDNSRDATADNSKEYEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATADNSKEYSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 DNSKEY RDATA 的 String 方法
func TestDNSRDATADNSKEYString(t *testing.T) {
	t.Logf("DNSKEY RDATA String():\n%s", testedDNSRDATADNSKEY.String())
}

// 测试 DNSKEY RDATA 的 Encode 方法
func TestDNSRDATADNSKEYEncode(t *testing.T) {
	encodedDNSRDATADNSKEY := testedDNSRDATADNSKEY.Encode()
	if !bytes.Equal(encodedDNSRDATADNSKEY, testedDNSRDATADNSKEYEncoded) {
		t.Errorf("function DNSRDATADNSKEYEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATADNSKEY, testedDNSRDATADNSKEYEncoded)
	}
}

// 测试 DNSKEY RDATA 的 EncodeToBuffer 方法
func TestDNSRDATADNSKEYEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATADNSKEYEncoded))
	_, err := testedDNSRDATADNSKEY.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATADNSKEYEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATADNSKEYEncoded) {
		t.Errorf("function DNSRDATADNSKEYEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATADNSKEYEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATADNSKEY.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATADNSKEYEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 DNSKEY RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATADNSKEYDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATADNSKEY := DNSRDATADNSKEY{}
	offset, err := decodedDNSRDATADNSKEY.DecodeFromBuffer(testedDNSRDATADNSKEYEncoded, 0, len(testedDNSRDATADNSKEYEncoded))
	if err != nil {
		t.Errorf("function DNSRDATADNSKEYDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATADNSKEYEncoded) {
		t.Errorf("function DNSRDATADNSKEYDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATADNSKEYEncoded))
	}
	if decodedDNSRDATADNSKEY.Equal(&testedDNSRDATADNSKEY) {
		t.Errorf("function DNSRDATADNSKEYDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATADNSKEY.String(), testedDNSRDATADNSKEY.String())
	}

	// 缓冲区长度不足
	decodedDNSRDATADNSKEY = DNSRDATADNSKEY{}
	_, err = decodedDNSRDATADNSKEY.DecodeFromBuffer(testedDNSRDATADNSKEYEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATADNSKEYDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 测试 NSEC RDATA
// 待测试的 NSEC 记录 RDATA 对象。
var testedDNSRDATANSEC = DNSRDATANSEC{
	NextDomainName: "example.com",
	TypeBitMaps:    []byte{0x01, 0x02, 0x03, 0x04},
}

// 待测试的 NSEC 记录 RDATA 编码后结果。
var testedDNSRDATANSECEncoded = []byte{
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x01, 0x02, 0x03, 0x04,
}

// 测试 NSEC RDATA 的 Size 方法
func TestDNSRDATANSECSize(t *testing.T) {
	size := testedDNSRDATANSEC.Size()
	expectedSize := len(testedDNSRDATANSECEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATANSECSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 NSEC RDATA 的 String 方法
func TestDNSRDATANSECString(t *testing.T) {
	t.Logf("NSEC RDATA String():\n%s", testedDNSRDATANSEC.String())
}

// 测试 NSEC RDATA 的 Encode 方法
func TestDNSRDATANSECEncode(t *testing.T) {
	encodedDNSRDATANSEC := testedDNSRDATANSEC.Encode()
	if !bytes.Equal(encodedDNSRDATANSEC, testedDNSRDATANSECEncoded) {
		t.Errorf("function DNSRDATANSECEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATANSEC, testedDNSRDATANSECEncoded)
	}
}

// 测试 NSEC RDATA 的 EncodeToBuffer 方法
func TestDNSRDATANSECEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATANSECEncoded))
	_, err := testedDNSRDATANSEC.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATANSECEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATANSECEncoded) {
		t.Errorf("function DNSRDATANSECEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATANSECEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATANSEC.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATANSECEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 NSEC RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATANSECDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATANSEC := DNSRDATANSEC{}
	offset, err := decodedDNSRDATANSEC.DecodeFromBuffer(testedDNSRDATANSECEncoded, 0, len(testedDNSRDATANSECEncoded))
	if err != nil {
		t.Errorf("function DNSRDATANSECDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATANSECEncoded) {
		t.Errorf("function DNSRDATANSECDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATANSECEncoded))
	}
	if decodedDNSRDATANSEC.Equal(&testedDNSRDATANSEC) {
		t.Errorf("function DNSRDATANSECDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATANSEC.String(), testedDNSRDATANSEC.String())
	}

	// 缓冲区长度不足
	decodedDNSRDATANSEC = DNSRDATANSEC{}
	_, err = decodedDNSRDATANSEC.DecodeFromBuffer(testedDNSRDATANSECEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATANSECDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 测试 DS RDATA

// 待测试的 DS 记录 RDATA 对象。
var testedDNSRDATADS = DNSRDATADS{
	KeyTag:     0x1234,
	Algorithm:  DNSSECAlgorithmRSASHA256,
	DigestType: 1,
	Digest:     []byte{0x01, 0x02, 0x03, 0x04},
}

// 待测试的 DS 记录 RDATA 编码后结果。
var testedDNSRDATADSEncoded = []byte{
	0x12, 0x34,
	0x08,
	0x01,
	0x01, 0x02, 0x03, 0x04,
}

// 测试 DS RDATA 的 Size 方法
func TestDNSRDATADSSize(t *testing.T) {
	size := testedDNSRDATADS.Size()
	expectedSize := len(testedDNSRDATADSEncoded)
	if size != expectedSize {
		t.Errorf("function DNSRDATADSSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 DS RDATA 的 String 方法
func TestDNSRDATADSString(t *testing.T) {
	t.Logf("DS RDATA String():\n%s", testedDNSRDATADS.String())
}

// 测试 DS RDATA 的 Encode 方法
func TestDNSRDATADSEncode(t *testing.T) {
	encodedDNSRDATADS := testedDNSRDATADS.Encode()
	if !bytes.Equal(encodedDNSRDATADS, testedDNSRDATADSEncoded) {
		t.Errorf("function DNSRDATADSEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSRDATADS, testedDNSRDATADSEncoded)
	}
}

// 测试 DS RDATA 的 EncodeToBuffer 方法
func TestDNSRDATADSEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSRDATADSEncoded))
	_, err := testedDNSRDATADS.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSRDATADSEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSRDATADSEncoded) {
		t.Errorf("function DNSRDATADSEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSRDATADSEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNSRDATADS.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSRDATADSEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 DS RDATA 的 DecodeFromBuffer 方法
func TestDNSRDATADSDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSRDATADS := DNSRDATADS{}
	offset, err := decodedDNSRDATADS.DecodeFromBuffer(testedDNSRDATADSEncoded, 0, len(testedDNSRDATADSEncoded))
	if err != nil {
		t.Errorf("function DNSRDATADSDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSRDATADSEncoded) {
		t.Errorf("function DNSRDATADSDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSRDATADSEncoded))
	}
	if decodedDNSRDATADS.Equal(&testedDNSRDATADS) {
		t.Errorf("function DNSRDATADSDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSRDATADS.String(), testedDNSRDATADS.String())
	}

	// 缓冲区长度不足
	decodedDNSRDATADS = DNSRDATADS{}
	_, err = decodedDNSRDATADS.DecodeFromBuffer(testedDNSRDATADSEncoded, 1, 0)
	if err == nil {
		t.Error("function DNSRDATADSDecodeFromBuffer() failed: expected an error but got nil")
	}
}
