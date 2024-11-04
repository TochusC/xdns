// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// sender.go 文件定义了 Sender 结构体及其相关方法。

package godns

import (
	"fmt"
	"net"
	"os"

	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tochusc/godns/dns/xlayers"
)

// Sender 结构体用于发送 DNS 消息。
// 其包含有：
//   - Handle: *pcap.Handle，用于发送 DNS 消息的 pcap.Handle 实例
//   - sConf: DNSServerConfig，DNS 服务器的相关配置
type Sender struct {
	Handle *pcap.Handle
	sConf  DNSServerConfig
}

// NewSender 用于创建一个 Sender 实例。
func NewSender(sConf DNSServerConfig) Sender {
	return Sender{
		Handle: func() *pcap.Handle {
			handle, err := pcap.OpenLive(sConf.NetworkDevice, int32(sConf.MTU), false, pcap.BlockForever)
			if err != nil {
				fmt.Println("function pcap.OpenLive Error: ", err)
				os.Exit(1)
			}
			return handle
		}(),
		sConf: sConf,
	}
}

// Send 函数用于发送 DNS 消息。
func (sender Sender) Send(rInfo ResponseInfo) (SendInfo, error) {
	sInfo := SendInfo{
		MAC:          rInfo.MAC,
		IP:           rInfo.IP,
		Port:         rInfo.Port,
		FragmentsNum: 0,
		TotalSize:    0,
		Data:         nil,
	}

	// 序列化DNS及UDP层
	udpPayload, err := serializeToUDP(rInfo, sender.sConf)
	if err != nil {
		return sInfo, fmt.Errorf("function serializeToUDP failed: %s", err)
	}

	// 分片
	fragments, err := Fragment(udpPayload, sender.sConf.MTU, 20)
	if err != nil {
		return sInfo, fmt.Errorf("function Fragment failed: %s", err)
	}

	// 生成数据包通道
	pktChan := make(chan []byte, len(fragments))

	// 计算每个分片的载荷大小：MTU - IP头部长度
	payloadSize := sender.sConf.MTU - 20
	payloadSize = payloadSize &^ 7

	// 生成随机IP标识符
	ipId := rand.Intn(65536)

	// 生成数据包
	for i, fragment := range fragments {
		if i == len(fragments)-1 {
			// 最后一个分片
			go fragmentToBytes(ipId, rInfo.MAC, rInfo.IP, 0, i*payloadSize/8, fragment, pktChan, sender.sConf)
		} else {
			// 其他
			go fragmentToBytes(ipId, rInfo.MAC, rInfo.IP, 1, i*payloadSize/8, fragment, pktChan, sender.sConf)
		}
	}

	// 发送数据包
	pktNum := len(fragments)
	for pkt := range pktChan {
		err = sender.Handle.WritePacketData(pkt)
		if err != nil {
			return sInfo, fmt.Errorf("function pcap.Handle.WritePacketData failed: %s", err)
		}
		sInfo.FragmentsNum++
		sInfo.TotalSize += len(pkt)

		// 发送完毕
		if sInfo.FragmentsNum == pktNum {
			break
		}
	}
	return sInfo, nil
}

// Fragment 函数用于对数据包进行分片。
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

// fragmentToBytes 函数用于将分片数据包序列化为字节流。
func fragmentToBytes(ipId int, dstMac net.HardwareAddr, dstIP net.IP, ipFlags int, offset int, payload []byte, pktBytes chan []byte, sConf DNSServerConfig) error {
	// 以太网层
	eth := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       sConf.MAC,
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
		Id:         uint16(ipId),
		Flags:      layers.IPv4Flag(ipFlags),
		FragOffset: uint16(offset),
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      sConf.IP,
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

// serializeToUDP 函数用于序列化 DNS 消息到 UDP 层。
func serializeToUDP(rInfo ResponseInfo, sConf DNSServerConfig) ([]byte, error) {
	udp := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(sConf.Port),
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
	udp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    sConf.IP,
		DstIP:    rInfo.IP,
		Protocol: layers.IPProtocolUDP,
	})
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
