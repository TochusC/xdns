// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// server.go 文件定义了 GoDNS 服务器的最顶层封装。
// GoDNS 服务器是一个易用、灵活的 DNS 服务器，
// 它可以监听指定的网络设备和端口，接收 DNS 请求并做出回复。
// GoStart 函数提供了一个一键启动 GoDNS 服务器的代码示例。

package godns

import (
	"io"
	"log"
	"net"

	"github.com/panjf2000/ants/v2"
)

// GoDNSServer 表示 GoDNS 服务器
// 其包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Sniffer: 数据包嗅探器
//   - Handler: 数据包处理器
type GoDNSServer struct {
	SeverConfig DNSServerConfig
	// GoDNS 服务器的日志
	GoDNSLogger *log.Logger

	ThreadPool *ants.Pool

	Netter   Netter
	Cacher   Cacher
	Responer Responser
}

func NewGoDNSServer(serverConf DNSServerConfig, responser Responser) *GoDNSServer {
	godnsLogger := log.New(serverConf.LogWriter, "GoDNS: ", log.LstdFlags)
	pool, err := ants.NewPool(serverConf.PoolCapcity)
	if err != nil {
		godnsLogger.Panicf("Error creating ants pool: %v", err)
	}

	netter := NewNetter(NetterConfig{
		Port:      serverConf.Port,
		LogWriter: serverConf.LogWriter,
	}, pool)

	cacher := NewCacher(CacherConfig{
		CacheLocation: serverConf.CacheLocation,
		LogWriter:     serverConf.LogWriter,
	}, pool)

	return &GoDNSServer{
		SeverConfig: serverConf,
		GoDNSLogger: godnsLogger,

		ThreadPool: pool,

		Netter:   *netter,
		Cacher:   *cacher,
		Responer: responser,
	}
}

func (s *GoDNSServer) HandleConnection(connInfo ConnectionInfo) {
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
		s.GoDNSLogger.Printf("Error generating response: %v", err)
		return
	}

	s.Netter.Send(connInfo, resp)
	if s.SeverConfig.EnebleCache {
		s.Cacher.CacheResponse(resp)
	}
}

// Start 启动 GoDNS 服务器
func (s *GoDNSServer) Start() {
	// GoDNS 启动！
	s.GoDNSLogger.Printf("GoDNS Starts!")

	connChan := s.Netter.Sniff()
	for connInfo := range connChan {
		s.ThreadPool.Submit(func() { s.HandleConnection(connInfo) })
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
