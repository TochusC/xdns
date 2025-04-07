// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// server.go 文件定义了 xdns 服务器的最顶层封装。
// xdns 服务器是一个易用、灵活的 DNS 服务器，
// 它可以监听指定的网络设备和端口，接收 DNS 请求并做出回复。
// GoStart 函数提供了一个一键启动 xdns 服务器的代码示例。

package xdns

import (
	"io"
	"log"
	"net"
)

// xdnsServer 表示 xdns 服务器
// 其包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Sniffer: 数据包嗅探器
//   - Handler: 数据包处理器
type xdnsServer struct {
	SeverConfig DNSServerConfig
	// xdns 服务器的日志
	xdnsLogger *log.Logger

	Netter   Netter
	Cacher   Cacher
	Responer Responser
}

func NewxdnsServer(serverConf DNSServerConfig, responser Responser) *xdnsServer {
	xdnsLogger := log.New(serverConf.LogWriter, "xdns: ", log.LstdFlags)

	netter := NewNetter(NetterConfig{
		Port:      serverConf.Port,
		LogWriter: serverConf.LogWriter,
	})

	cacher := NewCacher(CacherConfig{
		CacheLocation: serverConf.CacheLocation,
		LogWriter:     serverConf.LogWriter,
	})

	return &xdnsServer{
		SeverConfig: serverConf,
		xdnsLogger:  xdnsLogger,

		Netter:   *netter,
		Cacher:   *cacher,
		Responer: responser,
	}
}

func (s *xdnsServer) HandleConnection(connInfo ConnectionInfo) {
	// 从缓存中查找响应
	if s.SeverConfig.EnebleCache {
		cache, err := s.Cacher.FetchCache(connInfo)
		if err == nil {
			s.Netter.Send(connInfo, cache)
			return
		}
	}
	resp, err := s.Responer.Response(connInfo)
	if err != nil {
		s.xdnsLogger.Printf("Error generating response: %v", err)
		return
	}

	s.Netter.Send(connInfo, resp)
	if s.SeverConfig.EnebleCache {
		s.Cacher.CacheResponse(resp)
	}
}

// Start 启动 xdns 服务器
func (s *xdnsServer) Start() {
	// xdns 启动！
	s.xdnsLogger.Printf("xdns Starts!")

	connChan := s.Netter.Sniff()
	for connInfo := range connChan {
		go s.HandleConnection(connInfo)
	}
}

// DNSServerConfig 记录 DNS 服务器的相关配置
type DNSServerConfig struct {
	// DNS 服务器的 IP 地址
	IP net.IP
	// DNS 服务器的端口
	Port int

	// 日志输出
	LogWriter io.Writer

	// 线程池容量
	PoolCapcity int

	// 缓存功能
	EnebleCache   bool
	CacheLocation string
}
