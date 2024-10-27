// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// https://pkg.go.dev/github.com/tochusc/gopacket/pcap

package godns

import (
	"fmt"
	"os"

	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/pcap"
)

type Protocol string

const (
	ProtocolUDP Protocol = "udp"
	ProtocolTCP Protocol = "tcp"
)

type SnifferConfig struct {
	Device   string
	Port     int
	PktMax   int
	Protocol Protocol
}
type Sniffer struct {
	Handle *pcap.Handle
	Config SnifferConfig
}

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
