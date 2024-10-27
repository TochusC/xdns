// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// server.go 文件实现了 DNS 服务器的启动。

package godns

import (
	"fmt"
	"time"
)

// GoDNSSever
type GoDNSSever struct {
	ServerConfig DNSServerConfig
	Sniffer      []*Sniffer
	Handler      *Handler
}

// Start 启动 GoDNS 服务器
func (s *GoDNSSever) Start() {
	// GoDNS 启动！
	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "GoDNS Starts!")

	// 启动 Sniffer
	for _, sniffer := range s.Sniffer {
		pktChan := sniffer.Sniff(s.ServerConfig.DNSSeverNetworkDevice, s.ServerConfig.MTU, s.ServerConfig.DNSServerPort)
		go func() {
			for pkt := range pktChan {
				s.Handler.Handle(pkt)
			}
		}()
	}
}

// GoStart一键式创建一个基础 GoDNS 并启动它。
// 这个 GoDNS 将有一个DullResponser，将不会对DNS请求做出任何回复...
// 但您应该可以随意微调它，以满足您的各种需求。
// 参数：
//   - DNSServerConfig: DNS 服务器配置
//   - Responser: DNS 回复生成器
//
// 返回值：
//   - GoDNSSever: 创建的 GoDNS 服务器实例
func GoStart(serverConf DNSServerConfig) *GoDNSSever {
	// 创建一个 DNS 服务器
	server := &GoDNSSever{
		ServerConfig: serverConf,
		Sniffer: []*Sniffer{
			NewSniffer(SnifferConfig{
				Device:   serverConf.DNSSeverNetworkDevice,
				Port:     serverConf.DNSServerPort,
				PktMax:   65535,
				Protocol: ProtocolUDP,
			}),
		},
		Handler: NewHandler(serverConf, &DullResponser{}),
	}

	// 启动 DNS 服务器
	server.Start()
	return server
}
