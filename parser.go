package godns

import (
	dns "github.com/tochusc/godns/dns/gopacket"
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
)

func Parse(pkt gopacket.Packet) (QueryInfo, error) {
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns dns.DNS
	var decodedLayers []gopacket.LayerType

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns)

	err := parser.DecodeLayers(pkt.Data(), &decodedLayers)
	if err != nil {
		return QueryInfo{}, err
	}

	queryInfo := QueryInfo{
		MAC:  eth.SrcMAC,
		IP:   ipv4.SrcIP,
		Port: int(udp.SrcPort),
		DNS:  dns.GoDNS,
	}

	return queryInfo, nil
}
