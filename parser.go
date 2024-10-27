package godns

import (
	"github.com/tochusc/godns/dns/xlayers"
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
)

type Parser struct{}

func NewParser() Parser {
	return Parser{}
}

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
