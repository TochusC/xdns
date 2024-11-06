// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// server.go 文件定义了 GoDNS 服务器的最顶层封装。
// GoDNS 服务器是一个易用、灵活的 DNS 服务器，
// 它可以监听指定的网络设备和端口，接收 DNS 请求并做出回复。
// GoStart 函数提供了一个一键启动 GoDNS 服务器的代码示例。

package godns

import (
	"fmt"
	"net"
	"time"
)

// GoDNSSever 表示 GoDNS 服务器
// 其包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Sniffer: 数据包嗅探器
//   - Handler: 数据包处理器
type GoDNSSever struct {
	ServerConfig DNSServerConfig
	Netter       Netter
	Responer     Responser
}

// Start 启动 GoDNS 服务器
func (s *GoDNSSever) Start() {
	// GoDNS 启动！
	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "GoDNS Starts!")

	connChan := s.Netter.Sniff()
	for connInfo := range connChan {
		resp, err := s.Responer.Response(connInfo)
		if err != nil {
			fmt.Println("GoDNS: Error generating response: ", err)
			continue
		}
		s.Netter.Send(connInfo, resp.Encode())
	}
	for {
		time.Sleep(1 * time.Second)
	}
}

// GoStart为示例函数，其将会一键式创建一个基础 GoDNS 并启动它。
// 这个 GoDNS 将有一个DullResponser，它将对DNS请求做出简单的回复...
// 参数：
//   - DNSServerConfig: DNS 服务器配置
//   - Responser: DNS 回复生成器
func GoStart(serverConf DNSServerConfig) {
	// 创建一个 DNS 服务器
	server := &GoDNSSever{
		ServerConfig: serverConf,
		Netter: Netter{
			Config: NetterConfig{
				Port:     serverConf.Port,
				MTU:      serverConf.MTU,
				Protocol: ProtocolUDP,
			},
		},
		Responer: &DullResponser{
			ServerConf: serverConf,
		},
	}

	// 启动 DNS 服务器
	server.Start()
}

// DNSServerConfig 记录 DNS 服务器的相关配置
type DNSServerConfig struct {
	// DNS 服务器的 IP 地址
	IP net.IP
	// DNS 服务器的端口
	Port int
	// DNS 服务器所用网络设备的名称
	NetworkDevice string
	// DNS 服务器的 MAC 地址
	MAC net.HardwareAddr
	// 网络设备的最大传输单元
	MTU int
}
