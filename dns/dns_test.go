// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dns_test.go 文件定义了对 dns.go 文件的测试函数。
package dns

import (
	"bytes"
	"testing"

	"github.com/tochusc/godns/utils"
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
		t.Errorf("DNSHeaderSize() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, size, expectedSize)
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
		t.Errorf("DNSHeaderEncode() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, encodedDNSHeader, testedDNSHeaderEncoded)
	}
}

// 测试 DNSHeader 的 EncodeToBuffer 方法
func TestDNSHeaderEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, 12)
	_, err := testedDNSHeader.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("DNSHeaderEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if !bytes.Equal(buffer, testedDNSHeaderEncoded) {
		t.Errorf("DNSHeaderEncodeToBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, buffer, testedDNSHeaderEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 11)
	_, err = testedDNSHeader.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("DNSHeaderEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
	}
}

// 测试 DNSHeader 的 DecodeFromBuffer 方法
func TestDNSHeaderDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSHeader := DNSHeader{}
	offset, err := decodedDNSHeader.DecodeFromBuffer(testedDNSHeaderEncoded, 0)
	if err != nil {
		t.Errorf("DNSHeaderDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if offset != 12 {
		t.Errorf("DNSHeaderDecodeFromBuffer() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, offset, 12)
	}
	if decodedDNSHeader != testedDNSHeader {
		t.Errorf("DNSHeaderDecodeFromBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, decodedDNSHeader, testedDNSHeader)
	}

	// 缓冲区长度不足
	decodedDNSHeader = DNSHeader{}
	offset, err = decodedDNSHeader.DecodeFromBuffer(testedDNSHeaderEncoded, 1)
	if err == nil {
		t.Errorf("DNSHeaderDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
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
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x01, 0x00, 0x01,
}

// 测试 DNSQuestion 的 Size 方法
func TestDNSQuestionSize(t *testing.T) {
	size := testedDNSQuestion.Size()
	expectedSize := len(testedDNSQuestionEncoded)
	if size != expectedSize {
		t.Errorf("DNSQuestionSize() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, size, expectedSize)
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
		t.Errorf("DNSQuestionEncode() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, encodedDNSQuestion, testedDNSQuestionEncoded)
	}
}

// 测试 DNSQuestion 的 EncodeToBuffer 方法
func TestDNSQuestionEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSQuestionEncoded))
	_, err := testedDNSQuestion.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("DNSQuestionEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if !bytes.Equal(buffer, testedDNSQuestionEncoded) {
		t.Errorf("DNSQuestionEncodeToBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, buffer, testedDNSQuestionEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 19)
	_, err = testedDNSQuestion.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("DNSQuestionEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
	}
}

// 测试 DNSQuestion 的 DecodeFromBuffer 方法
func TestDNSQuestionDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNSQuestion := DNSQuestion{}
	offset, err := decodedDNSQuestion.DecodeFromBuffer(testedDNSQuestionEncoded, 0)
	if err != nil {
		t.Errorf("DNSQuestionDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if offset != len(testedDNSQuestionEncoded) {
		t.Errorf("DNSQuestionDecodeFromBuffer() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, offset, len(testedDNSQuestionEncoded))
	}
	if decodedDNSQuestion != testedDNSQuestion {
		t.Errorf("DNSQuestionDecodeFromBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, decodedDNSQuestion, testedDNSQuestion)
	}

	// 缓冲区长度不足
	decodedDNSQuestion = DNSQuestion{}
	_, err = decodedDNSQuestion.DecodeFromBuffer(testedDNSQuestionEncoded, 1)
	if err == nil {
		t.Errorf("DNSQuestionDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
	}
}

// 待测试的 DNS 对象。
var testedDNS = DNS{
	Header: testedDNSHeader,
	Question: []DNSQuestion{
		testedDNSQuestion,
		testedDNSQuestion,
	},
	Answer:     nil,
	Authority:  nil,
	Additional: nil,
}

// DNS 的期望编码结果。
var testedDNSEncoded = []byte{
	// Header
	0x12, 0x34, 0x04, 0x00,
	0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	// Question 1
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x01, 0x00, 0x01,
	// Question 2
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x01, 0x00, 0x01,
}

// 测试 DNS 的 Size 方法
func TestDNSSize(t *testing.T) {
	size := testedDNS.Size()
	expectedSize := len(testedDNSEncoded)
	if size != expectedSize {
		t.Errorf("DNSSize() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, size, expectedSize)
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
		t.Errorf("DNSEncode() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, encodedDNS, testedDNSEncoded)
	}
}

// 测试 DNS 的 EncodeToBuffer 方法
func TestDNSEncodeToBuffer(t *testing.T) {
	// 正常情况
	buffer := make([]byte, len(testedDNSEncoded))
	_, err := testedDNS.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("DNSEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if !bytes.Equal(buffer, testedDNSEncoded) {
		t.Errorf("DNSEncodeToBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, buffer, testedDNSEncoded)
	}

	// 缓冲区长度不足
	buffer = make([]byte, 1)
	_, err = testedDNS.EncodeToBuffer(buffer)
	if err == nil {
		t.Errorf("DNSEncodeToBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
	}
}

// 测试 DNS 的 DecodeFromBuffer 方法
func TestDNSDecodeFromBuffer(t *testing.T) {
	// 正常情况
	decodedDNS := DNS{}
	offset, err := decodedDNS.DecodeFromBuffer(testedDNSEncoded, 0)
	if err != nil {
		t.Errorf("DNSDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, err.Error())
	}
	if offset != len(testedDNSEncoded) {
		t.Errorf("DNSDecodeFromBuffer() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, offset, len(testedDNSEncoded))
	}
	if !decodedDNS.Equal(&testedDNS) {
		t.Errorf("DNSDecodeFromBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v\n",
			utils.ResultMismatch, decodedDNS.String(), testedDNS.String())
	}

	// 缓冲区长度不足
	decodedDNS = DNS{}
	_, err = decodedDNS.DecodeFromBuffer(testedDNSEncoded, 1)
	if err == nil {
		t.Errorf("DNSDecodeFromBuffer() failed:\n%s\n%s",
			utils.ErrorMismatch, "expected an error but got nil")
	}
}
