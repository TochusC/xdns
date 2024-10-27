package godns

import (
	"fmt"
	"net"
	"os"

	"math/rand"

	"github.com/tochusc/godns/dns/xlayers"
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
	"github.com/tochusc/gopacket/pcap"
)

type Sender struct {
	Handle *pcap.Handle
	Config DNSServerConfig
}

func NewSender(conf DNSServerConfig) *Sender {
	return &Sender{Handle: func() *pcap.Handle {
		sender, err := pcap.OpenLive(conf.DNSSeverNetworkDevice, int32(conf.MTU), false, pcap.BlockForever)
		if err != nil {
			fmt.Println("function pcap.OpenLive Error: ", err)
			os.Exit(1)
		}
		return sender
	}(),
	}
}

func (sender Sender) Send(rInfo ResponseInfo, conf DNSServerConfig) error {
	// 序列化DNS层和UDP层
	udpPayload, err := serializeToUDP(rInfo, conf)
	if err != nil {
		return err
	}

	// 分片
	fragments, err := Fragment(udpPayload, 1500, 20)
	if err != nil {
		return err
	}

	// 生成数据包通道
	pktChan := make(chan []byte, len(fragments))
	// 生成数据包
	for i, fragment := range fragments {
		go fragmentToBytes(rInfo.MAC, rInfo.IP, 0, i*8, fragment, pktChan, conf)
	}

	totalSize := 0
	sentNum := 0
	pktNum := len(fragments)
	for pkt := range pktChan {
		totalSize += len(pkt)
		err = sender.Handle.WritePacketData(pkt)
		if err != nil {
			return err
		}
		if sentNum++; sentNum == pktNum {
			break
		}
	}
	println("DNS response send, total fragments: %d, total size: %d", pktNum, totalSize)
	return nil
}

func Fragment(payload []byte, mtu, ipHeaderLen int) ([][]byte, error) {
	if mtu <= 0 {
		return nil, fmt.Errorf("function Fragment failed: MTU must be greater than 0")
	}

	// 计算每个分片的载荷大小：MTU - IP头部长度
	payloadSize := mtu - ipHeaderLen
	// 确保每个分片的载荷大小是8的倍数
	payloadSize = payloadSize &^ 7

	// 计算分片数量，初始化分片数组
	fragNum := (len(payload) + payloadSize - 1) / payloadSize
	fragments := make([][]byte, 0, fragNum)

	// 分片
	for trvlr := 0; trvlr < len(payload); trvlr += payloadSize {
		end := trvlr + payloadSize
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[trvlr:end])
	}
	return fragments, nil
}

func fragmentToBytes(dstMac net.HardwareAddr, dstIP net.IP, ipFlags int, offset int, payload []byte, pktBytes chan []byte, conf DNSServerConfig) error {
	// 生成随机IP标识符
	ipID := uint16(rand.Intn(65536))

	// 以太网层
	eth := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       conf.DNSServerMAC,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	// IPv4层
	ipv4 := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         ipID,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      conf.DNSServerIP,
		DstIP:      dstIP,
		Options:    nil,
		Padding:    nil,
	}

	// 设置序列化选项
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// IPv4层序列化
	ipv4Buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		ipv4Buffer,
		options,
		ipv4,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}
	ipv4Payload := ipv4Buffer.Bytes()

	// 以太网层序列化
	ethernetBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		ethernetBuffer,
		options,
		eth,
		gopacket.Payload(ipv4Payload),
	)
	if err != nil {
		return err
	}
	pktBytes <- ethernetBuffer.Bytes()
	return nil
}

func serializeToUDP(rInfo ResponseInfo, conf DNSServerConfig) ([]byte, error) {
	udp := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(conf.DNSServerPort),
		DstPort:   layers.UDPPort(rInfo.Port),
	}
	dns := xlayers.DNS{
		BaseLayer:  layers.BaseLayer{},
		DNSMessage: *rInfo.DNS,
	}

	// DNS层序列化
	dnsBuffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := dns.SerializeTo(dnsBuffer, options)
	if err != nil {
		return nil, err
	}

	dnsPayload := dnsBuffer.Bytes()
	// UDP层序列化
	udpBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		udpBuffer,
		options,
		udp,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		return nil, err
	}
	udpPayload := udpBuffer.Bytes()

	return udpPayload, nil
}
