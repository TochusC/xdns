// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// xlayers_test.go 包含了对 xlayers.go 中 gopacket 接口实现的测试。

package xlayers

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tochusc/godns/dns"
)

var testedPacket = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11,
	0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x66, 0x96, 0x0a, 0x0a, 0x00, 0x03, 0x0a, 0x0a,
	0x00, 0x02, 0x00, 0x35, 0x63, 0xbf, 0x00, 0x2a,
	0xea, 0xec, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
	0x77, 0x77, 0x07, 0x6b, 0x65, 0x79, 0x74, 0x72,
	0x61, 0x70, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
	0x00, 0x01, 0x00, 0x01,
}

func TestSerializeTo(t *testing.T) {
	dns := DNS{
		DNSMessage: dns.DNSMessage{
			Header: dns.DNSHeader{
				ID:      0x1234,
				QR:      false,
				OpCode:  dns.DNSOpCodeQuery,
				AA:      true,
				TC:      false,
				RD:      false,
				RA:      false,
				Z:       0,
				RCode:   dns.DNSResponseCodeNoErr,
				QDCount: 1,
				ANCount: 0,
				NSCount: 0,
				ARCount: 0,
			},
			Question: []dns.DNSQuestion{
				{
					Name:  "www.example.com",
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
				},
			},
			Answer: dns.DNSResponseSection{
				dns.DNSResourceRecord{
					Name:  "www.example.com",
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   3600,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: net.IPv4(192, 0, 2, 1)},
				},
			},
			Authority:  dns.DNSResponseSection{},
			Additional: dns.DNSResponseSection{},
		},
	}
	serializeBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{192, 168, 1, 2},
	}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 25535,
	}

	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		t.Errorf("function SetNetworkLayerForChecksum() failed:\ngot:\n%v\nexpected:\n%v",
			err, nil)
	}
	err = gopacket.SerializeLayers(serializeBuffer, opts, eth, ip, udp, &dns)
	if err != nil {
		t.Errorf("function SerializeTo() failed:\ngot:\n%v\nexpected:\n%v",
			err, nil)
	}
}

func TestDecodeFromBytes(t *testing.T) {
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns DNS
	var decodedLayers []gopacket.LayerType

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ipv4, &udp, &dns)

	err := decoder.DecodeLayers(testedPacket, &decodedLayers)
	if err != nil {
		t.Errorf("function DecodeFromBytes() failed:\ngot:\n%v\nexpected:\n%v",
			err, nil)
	}
	t.Logf("dns message: %s", dns.DNSMessage.String())
}
