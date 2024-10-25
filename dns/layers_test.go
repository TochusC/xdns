// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// layers_test.go 包含了对 gopacket SerializableLayer 接口的测试。
package dns

import (
	"testing"

	"github.com/tochusc/godns/utils"
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
)

func TestSerializeTo(t *testing.T) {
	dns := DNS{
		Header: DNSHeader{
			ID:      0x1234,
			QR:      false,
			OpCode:  DNSOpCodeQuery,
			AA:      true,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCode:   DNSResponseCodeNoErr,
			QDCount: 1,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		Question: []DNSQuestion{
			{
				Name:  "www.example.com",
				Type:  DNSRRTypeA,
				Class: DNSClassIN,
			},
		},
		Answer:     []DNSResourceRecord{},
		Authority:  []DNSResourceRecord{},
		Additional: []DNSResourceRecord{},
	}
	serializeBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{192, 168, 1, 2},
	}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 53,
	}

	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		t.Errorf("SetNetworkLayerForChecksum() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ErrorMismatch, err, nil)
	}
	err = gopacket.SerializeLayers(serializeBuffer, opts, eth, ip, udp, &dns)
	if err != nil {
		t.Errorf("SerializeTo() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ErrorMismatch, err, nil)
	}
}
