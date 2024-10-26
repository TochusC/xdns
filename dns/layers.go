// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// layers.go 文件实现了gopacket.Layer接口，用于实现DNS层的序列化。
package dns

import (
	"errors"

	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
)

// LayerType 返回DNS层类型，实现了gopacket.Layer接口。
func (dns *DNS) LayerType() gopacket.LayerType { return layers.LayerTypeDNS }

// SerializeTo 序列化DNS层到序列化缓冲区，实现了gopacket.SerializableLayer接口。
//   - 其接收参数为 序列化缓冲区 和 序列化选项。
//   - 返回值为 错误信息。
func (dns *DNS) SerializeTo(serializeBuffer gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// 预先分配缓冲区
	buffer, err := serializeBuffer.PrependBytes(dns.Size())
	if err != nil {
		return errors.New("DNS SerializeTo Error:\n" + err.Error())
	}
	_, err = dns.EncodeToBuffer(buffer)
	if err != nil {
		return errors.New("DNS SerializeTo Error:\n" + err.Error())
	}
	return nil
}
