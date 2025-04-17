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

// XdnsServer 表示 xdns 服务器
// 其包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Sniffer: 数据包嗅探器
//   - Handler: 数据包处理器
type XdnsServer struct {
	Config ServerConfig
	// xdns 服务器的日志
	Logger *log.Logger

	Netter   Netter
	Cacher   Cacher
	Responer Responser
}

// NewXdnsServer 创建一个新的 xdns 服务器实例
// 该函数接受一个 ServerConfig 和一个 Responser 实例作为参数，
// 并返回一个新的 XdnsServer 实例。
// 该函数会初始化一个新的日志记录器、数据包嗅探器和缓存器。
func NewXdnsServer(serverConf ServerConfig, responser Responser) *XdnsServer {
	Logger := log.New(serverConf.LogWriter, "xdns: ", log.LstdFlags)

	netter := NewNetter(NetterConfig{
		Port:      serverConf.Port,
		LogWriter: serverConf.LogWriter,
	})

	cacher := NewCacher(CacherConfig{
		CacheLocation: serverConf.CacheLocation,
		LogWriter:     serverConf.LogWriter,
	})

	return &XdnsServer{
		Config: serverConf,
		Logger: Logger,

		Netter:   *netter,
		Cacher:   *cacher,
		Responer: responser,
	}
}

// HandleConnection 处理连接信息
// 该函数接受一个 ConnectionInfo 实例作为参数，
// 并根据该连接的信息回复 DNS 响应。
func (s *XdnsServer) HandleConnection(connInfo ConnectionInfo) {
	// 从缓存中查找响应
	if s.Config.EnableCache {
		cache, err := s.Cacher.FetchCache(connInfo)
		if err == nil {
			s.Netter.Send(connInfo, cache)
			return
		}
	}

	// 如果缓存未命中，则生成响应
	resp, err := s.Responer.Response(connInfo)
	if err != nil {
		s.Logger.Printf("Error generating response: %v", err)
		return
	}

	// 如果启用 TCP 且响应长度超过阈值，则截断响应
	if s.Config.EnableTCP && len(resp) > s.Config.TCPThreshold && connInfo.Protocol != "tcp" {
		resp = InitTruncatedResponse(connInfo.Packet)
		s.Logger.Printf("Truncated response to: %s, length: %d.", connInfo.Address, len(resp))
	}

	// 发送响应
	s.Netter.Send(connInfo, resp)

	// 如果启用缓存，则将响应存储到缓存中
	if s.Config.EnableCache {
		s.Cacher.CacheResponse(resp)
	}
}

// Start 启动 xdns 服务器
func (s *XdnsServer) Start() {
	// xdns 启动！

	s.Logger.Printf("xdns Starts!")

	connChan := s.Netter.Sniff()
	for connInfo := range connChan {
		go s.HandleConnection(connInfo)
	}
}

// ServerConfig 记录 DNS 服务器的相关配置。
type ServerConfig struct {
	// DNS 服务器的 IP 地址
	IP net.IP
	// DNS 服务器的端口
	Port int

	// 日志输出
	LogWriter io.Writer

	// 缓存功能
	EnableCache   bool
	CacheLocation string

	// TCP 传输
	EnableTCP    bool
	TCPThreshold int
}
