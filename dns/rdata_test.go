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
