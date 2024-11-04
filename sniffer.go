// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// Sniffer.go 文件定义了对 Sniffer 的实现。

package godns

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffer 记录了 Sniffer 的相关信息
// 其包括有：
//   - Handle: pcap.Handle，Sniffer 的数据包处理器
//   - Config: SnifferConfig，Sniffer 的配置
type Sniffer struct {
	Handle *pcap.Handle
	Config SnifferConfig
}

// SnifferConfig 记录 Sniffer 的相关配置
type SnifferConfig struct {
	// Device 记录 Sniffer 所监听的网络设备
	Device string
	// Port 记录 Sniffer 所监听的端口
	Port int
	// PktMax 记录 Sniffer 所监听的数据包最大长度
	PktMax int
	// Protocol 记录 Sniffer 所监听的协议
	Protocol Protocol
}

// Protocol 记录 Sniffer 所监听的协议
type Protocol string

// Sniffer 的监听协议, 可选值为 "udp" 或 "tcp"
const (
	ProtocolUDP Protocol = "udp"
	ProtocolTCP Protocol = "tcp"
)

// NewSniffer 创建一个新的 Sniffer 实例
// 其接受参数为：
//   - conf: SnifferConfig，Sniffer 的配置
func NewSniffer(conf SnifferConfig) *Sniffer {
	return &Sniffer{Handle: func() *pcap.Handle {
		// 打开网络设备
		handle, err := pcap.OpenLive(conf.Device, int32(conf.PktMax), false, pcap.BlockForever)
		if err != nil {
			fmt.Println("function pcap.OpenLive Error: ", err)
			os.Exit(1)
		}

		// 设置过滤器
		filiter := fmt.Sprintf("ip and %s dst port %d", conf.Protocol, conf.Port)
		err = handle.SetBPFFilter(filiter)
		if err != nil {
			fmt.Println("function handle.SetBPFFilter Error: ", err)
			os.Exit(1)
		}

		// 设置Handler为接收方向
		err = handle.SetDirection(pcap.DirectionIn)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}
		return handle
	}(),
	}
}

func (sniffer Sniffer) Sniff(device string, pktMax int, port int) chan []byte {
	//	设置数据包源
	packetSource := gopacket.NewPacketSource(sniffer.Handle, sniffer.Handle.LinkType())

	// 生成数据包通道
	pktChan := make(chan []byte)
	go func() {
		for packet := range packetSource.Packets() {
			pktChan <- packet.Data()
		}
		close(pktChan)
	}()

	return pktChan
}
