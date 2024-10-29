// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dns_test.go 文件用于对 dns.go 文件所实现的 DNS 消息编解码进行的测试。

package dns

import (
	"bytes"
	"testing"
)

// 待测试的 DNSHeader 对象。
var testedDNSHeader = DNSHeader{
	ID:      0x1234,
	QR:      false,
	OpCode:  DNSOpCodeQuery,
	AA:      true,
	TC:      false,
	RD:      false,
	RA:      false,
	Z:       0,
	RCode:   DNSResponseCodeNoErr,
	QDCount: 2,
	ANCount: 0,
	NSCount: 0,
	ARCount: 0,
}

// DNSHeader 的期望编码结果。
var testedDNSHeaderEncoded = []byte{
	0x12, 0x34, 0x04, 0x00,
	0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// 测试 DNSHeader 的 Size 方法
func TestDNSHeaderSize(t *testing.T) {
	size := testedDNSHeader.Size()
	expectedSize := len(testedDNSHeaderEncoded)
	if size != expectedSize {
		t.Errorf(" function DNSHeaderSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 DNSHeader 的 String 方法
func TestDNSHeaderString(t *testing.T) {
	t.Logf("DNSHeader String():\n%s", testedDNSHeader.String())
}

// 测试 DNSHeader 的 Encode 方法
func TestDNSHeaderEncode(t *testing.T) {
	encodedDNSHeader := testedDNSHeader.Encode()
	if !bytes.Equal(encodedDNSHeader, testedDNSHeaderEncoded) {
		t.Errorf(" function DNSHeaderEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSHeader, testedDNSHeaderEncoded)
	}
}

// 测试 DNSHeader 的 EncodeToBuffer 方法
func TestDNSHeaderEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, 12)
	_, err := testedDNSHeader.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf(" function DNSHeaderEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSHeaderEncoded) {
		t.Errorf(" function DNSHeaderEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSHeaderEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 11)
	_, err = testedDNSHeader.EncodeToBuffer(buffer)
	if err == nil {
		t.Error("function DNSHeaderEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 DNSHeader 的 DecodeFromBuffer 方法
func TestDNSHeaderDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSHeader := DNSHeader{}
	offset, err := decodedDNSHeader.DecodeFromBuffer(testedDNSHeaderEncoded, 0)
	if err != nil {
		t.Errorf("function DNSHeaderDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != 12 {
		t.Errorf("function DNSHeaderDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, 12)
	}
	if decodedDNSHeader != testedDNSHeader {
		t.Errorf("function DNSHeaderDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSHeader, testedDNSHeader)
	}

	// 缓冲区长度不足
	decodedDNSHeader = DNSHeader{}
	offset, err = decodedDNSHeader.DecodeFromBuffer(testedDNSHeaderEncoded, 1)
	if err == nil {
		t.Error("function DNSHeaderDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 待测试的 DNSQuestion 对象。
var testedDNSQuestion = DNSQuestion{
	Name:  "www.example.com",
	Type:  DNSRRTypeA,
	Class: DNSClassIN,
}

// DNSQuestion 的期望编码结果。
var testedDNSQuestionEncoded = []byte{
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01, 0x00, 0x01,
}

// 测试 DNSQuestion 的 Size 方法
func TestDNSQuestionSize(t *testing.T) {
	size := testedDNSQuestion.Size()
	expectedSize := len(testedDNSQuestionEncoded)
	if size != expectedSize {
		t.Errorf("function DNSQuestionSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 DNSQuestion 的 String 方法
func TestDNSQuestionString(t *testing.T) {
	t.Logf("DNSQuestion String():\n%s", testedDNSQuestion.String())
}

// 测试 DNSQuestion的 Encode 方法
func TestDNSQuestionEncode(t *testing.T) {
	encodedDNSQuestion := testedDNSQuestion.Encode()
	if !bytes.Equal(encodedDNSQuestion, testedDNSQuestionEncoded) {
		t.Errorf("function DNSQuestionEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNSQuestion, testedDNSQuestionEncoded)
	}
}

// 测试 DNSQuestion 的 EncodeToBuffer 方法
func TestDNSQuestionEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSQuestionEncoded))
	_, err := testedDNSQuestion.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("function DNSQuestionEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSQuestionEncoded) {
		t.Errorf("function DNSQuestionEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSQuestionEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 19)
	_, err = testedDNSQuestion.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("function DNSQuestionEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 DNSQuestion 的 DecodeFromBuffer 方法
func TestDNSQuestionDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSQuestion := DNSQuestion{}
	offset, err := decodedDNSQuestion.DecodeFromBuffer(testedDNSQuestionEncoded, 0)
	if err != nil {
		t.Errorf(" function DNSQuestionDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSQuestionEncoded) {
		t.Errorf(" function DNSQuestionDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSQuestionEncoded))
	}
	if decodedDNSQuestion != testedDNSQuestion {
		t.Errorf(" function DNSQuestionDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNSQuestion, testedDNSQuestion)
	}

	// 缓冲区长度不足
	decodedDNSQuestion = DNSQuestion{}
	_, err = decodedDNSQuestion.DecodeFromBuffer(testedDNSQuestionEncoded, 1)
	if err == nil {
		t.Errorf(" function DNSQuestionDecodeFromBuffer() failed: expected an error but got nil")
	}
}

// 待测试的 DNS消息 对象。
var testedDNS = DNSMessage{
	Header: testedDNSHeader,
	Question: []DNSQuestion{
		testedDNSQuestion,
		testedDNSQuestion,
	},
	Answer:     nil,
	Authority:  nil,
	Additional: nil,
}

// DNS消息 的期望编码结果。
var testedDNSEncoded = []byte{
	// Header
	0x12, 0x34, 0x04, 0x00,
	0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	// Question 1
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01, 0x00, 0x01,
	// Question 2
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01, 0x00, 0x01,
}

// 测试 DNS 的 Size 方法
func TestDNSSize(t *testing.T) {
	size := testedDNS.Size()
	expectedSize := len(testedDNSEncoded)
	if size != expectedSize {
		t.Errorf(" function DNSSize() failed:\ngot:%d\nexpected: %d",
			size, expectedSize)
	}
}

// 测试 DNS 的 String 方法
func TestDNSString(t *testing.T) {
	t.Logf("DNS String():\n%s", testedDNS.String())
}

// 测试 DNS 的 Encode 方法
func TestDNSEncode(t *testing.T) {
	encodedDNS := testedDNS.Encode()
	if !bytes.Equal(encodedDNS, testedDNSEncoded) {
		t.Errorf(" function DNSEncode() failed:\ngot:\n%v\nexpected:\n%v",
			encodedDNS, testedDNSEncoded)
	}
}

// 测试 DNS 的 EncodeToBuffer 方法
func TestDNSEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSEncoded))
	_, err := testedDNS.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf(" function DNSEncodeToBuffer() failed:\n%s", err)
	}
	if !bytes.Equal(buffer, testedDNSEncoded) {
		t.Errorf(" function DNSEncodeToBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			buffer, testedDNSEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNS.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf(" function DNSEncodeToBuffer() failed: expected an error but got nil")
	}
}

// 测试 DNS 的 DecodeFromBuffer 方法
func TestDNSDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNS := DNSMessage{}
	offset, err := decodedDNS.DecodeFromBuffer(testedDNSEncoded, 0)
	if err != nil {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSEncoded) {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSEncoded))
	}
	if !decodedDNS.Equal(&testedDNS) {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\ngot:\n%v\nexpected:\n%v",
			decodedDNS.String(), testedDNS.String())
	}

	// 缓冲区长度不足
	decodedDNS = DNSMessage{}
	_, err = decodedDNS.DecodeFromBuffer(testedDNSEncoded, 1)
	if err == nil {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\n expected an error but got nil")
	}
}

var testedDNSPacket = []byte{
	0x12, 0x34, 0x85, 0x20, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
	0x77, 0x77, 0x07, 0x6b, 0x65, 0x79, 0x74, 0x72,
	0x61, 0x70, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
	0x07, 0x6b, 0x65, 0x79, 0x74, 0x72, 0x61, 0x70,
	0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x04,
	0x0a, 0x0a, 0x00, 0x03,
}

func TestDNSDecodeFromBuffer2(t *testing.T) {
	// 正常情况
	decodedDNS := DNSMessage{}
	offset, err := decodedDNS.DecodeFromBuffer(testedDNSPacket, 0)
	if err != nil {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\n%s", err)
	}
	if offset != len(testedDNSPacket) {
		t.Errorf(" function DNSDecodeFromBuffer() failed:\ngot:%d\nexpected: %d",
			offset, len(testedDNSPacket))
	}
	t.Logf("DNS DecodeFromBuffer2():\n%s", decodedDNS.String())
}
