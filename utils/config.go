// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// config.go 文件实现了 godns 的配置
package utils

import "net"

// DNS服务器配置

var (
	// DNSServerIP 是 DNS 服务器的 IP 地址
	DNSServerIP = net.IPv4(10, 10, 3, 3)
	// DNSServerPort 是 DNS 服务器的端口
	DNSServerPort = 53

	// NetworkDevice 是 DNS 服务器所用网络设备的名称
	DNSSeverNetworkDevice = "eth0"

	// MTU 是网络设备的最大传输单元
	MTU = 1500

	// DNSServerMAC 是 DNS 服务器的 MAC 地址
	DNSServerMAC = net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03}
)
