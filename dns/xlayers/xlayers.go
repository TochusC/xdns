// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// xlayers 包提供了实现 gopacket.Layer 接口的 DNS 封装结构。
// [xlayers.go]文件提供的 DNS 结构体可用于替换 gopacket.Layer 中原有的 DNS 结构体，
// 使 gopacket 使用dns包中的实现进行 DNS 消息的编解码。
//
//	 // DNS 结构体用于替换 gopacket.Layer 中原有的 DNS 结构体，
//		type DNS struct {
//			layers.BaseLayer
//			DNSMessage dns.DNSMessage
//		}
package xlayers

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tochusc/godns/dns"
)

// DNS 结构体用于替换 gopacket.Layer 中原有的 DNS 结构体，
type DNS struct {
	layers.BaseLayer
	DNSMessage dns.DNSMessage
}

// LayerType 返回DNS层类型，实现了gopacket.Layer接口。
func (dns DNS) LayerType() gopacket.LayerType { return layers.LayerTypeDNS }

// SerializeTo 序列化DNS层到序列化缓冲区，实现了gopacket.SerializableLayer接口。
//   - 其接收参数为 序列化缓冲区 和 序列化选项。
//   - 返回值为 错误信息。
func (dns DNS) SerializeTo(serializeBuffer gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// 预先分配缓冲区
	buffer, err := serializeBuffer.PrependBytes(dns.DNSMessage.Size())
	if err != nil {
		return errors.New("DNS SerializeTo Error:\n" + err.Error())
	}
	_, err = dns.DNSMessage.EncodeToBuffer(buffer)
	if err != nil {
		return errors.New("DNS SerializeTo Error:\n" + err.Error())
	}
	return nil
}

// DecodeFromBytes 从字节切片中解码DNS层，实现了gopacket.Layer接口。
//   - 其接收参数为 字节切片 和 解码选项。
//   - 返回值为 解码后的字节切片 和 错误信息。
func (dns *DNS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// 解码DNS层
	offset, err := dns.DNSMessage.DecodeFromBuffer(data, 0)
	if err != nil {
		return errors.New("DNS DecodeFromBytes Error:\n" + err.Error())
	}
	dns.BaseLayer.Payload = data[offset:]
	return nil
}

// CanDecode 返回是否可以解码DNS层，实现了gopacket.Layer接口。
//   - 其接收参数为 字节切片。
//   - 返回值为 是否可以解码 和 错误信息。
func (dns DNS) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeDNS
}

// NextLayerType 返回下一层的类型，实现了gopacket.Layer接口。
func (dns DNS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload 返回DNS层的有效载荷，实现了gopacket.Layer接口。
func (dns DNS) Payload() []byte {
	return dns.BaseLayer.Payload
}
