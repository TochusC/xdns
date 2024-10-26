// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// https://pkg.go.dev/github.com/tochusc/gopacket/pcap

package godns

import (
	"fmt"
	"os"

	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/pcap"
)

func Sniff(device string, pktMax int, port int) chan gopacket.Packet {
	handleSend, err := pcap.OpenLive(device, int32(pktMax), false, pcap.BlockForever)
	if err != nil {
		fmt.Println("function pcap.OpenLive Error: ", err)
		os.Exit(1)
	}
	defer handleSend.Close()

	handleRecv, err := pcap.OpenLive(device, int32(pktMax), false, pcap.BlockForever)
	if err != nil {
		fmt.Println("function pcap.OpenLive Error: ", err)
		os.Exit(1)
	}
	defer handleRecv.Close()

	// 设置过滤器
	var filter = fmt.Sprintf("ip and udp dst port %d", port)
	err = handleRecv.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	// 设置Handler为接收方向
	err = handleRecv.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//	设置数据包源
	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())

	return packetSource.Packets()
}
