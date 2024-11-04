// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// parser.go 文件实现了对 DNS 消息的解析功能。
// 该文件定义了 Parser 结构体，用于解析 DNS 消息。
// Parser使用 google/gopacket 库来进行 DNS 消息的解析。

package godns

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tochusc/godns/dns/xlayers"
)

// Parser 结构体用于解析 DNS 消息。
type Parser struct{}

func (parser Parser) Parse(pkt []byte) (QueryInfo, error) {
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns xlayers.DNS
	var decodedLayers []gopacket.LayerType

	layerParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ipv4, &udp, &dns)

	err := layerParser.DecodeLayers(pkt, &decodedLayers)
	if err != nil {
		return QueryInfo{}, err
	}

	queryInfo := QueryInfo{
		MAC:  eth.SrcMAC,
		IP:   ipv4.SrcIP,
		Port: int(udp.SrcPort),
		DNS:  &dns.DNSMessage,
	}

	return queryInfo, nil
}
