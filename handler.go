// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// handler.go 实现了Handler结构体，用于响应、处理 DNS 请求并回复
// 其包含以下四部分：
//   - Parser 解析DNS请求 [parser.go]
//   - Responser 生成DNS回复 [responser.go]
//   - Sender 发送DNS回复 [sender.go]
//   - DNSServerConfig 记录DNS服务器配置

package godns

import (
	"fmt"
	"net"
	"time"

	"github.com/tochusc/godns/dns"
)

// Handler 结构体用于响应、处理 DNS 请求并回复
// 其包含以下四部分：
//   - Parser 解析DNS请求
//   - Responser 生成DNS回复
//   - Sender 发送DNS回复
//   - DNSServerConfig 记录DNS服务器配置
type Handler struct {
	Parser    Parser
	Responser Responser
	Sender    Sender
	sConf     DNSServerConfig
}

// NewHandler 创建一个新的Handler对象
func NewHandler(sConf DNSServerConfig, responser Responser) *Handler {
	return &Handler{
		Parser:    Parser{},
		Responser: responser,
		Sender:    NewSender(sConf),
		sConf:     sConf,
	}
}

// Handle 函数分别调用Parser、Responser和Sender来解析、生成和发送DNS请求及回复
//   - pkt: []byte，嗅探到的数据包
func (handler Handler) Handle(pkt []byte) {
	// Parser 解析数据包
	qInfo, err := handler.Parser.Parse(pkt)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 输出QueryInfo
	// fmt.Println(qInfo.String())
	fmt.Printf("[%s]Receive query from IP:%s, QName: %s, QType: %s\n",
		time.Now().Format(time.ANSIC), qInfo.IP, qInfo.DNS.Question[0].Name, qInfo.DNS.Question[0].Type)

	// Responser 生成DNS回复
	rInfo, err := handler.Responser.Response(qInfo)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 输出ResponseInfo
	// fmt.Println(rInfo.String())
	fmt.Printf("[%s]Response to IP: %s, QName: %s, QType: %s\n",
		time.Now().Format(time.ANSIC), rInfo.IP, rInfo.DNS.Question[0].Name, rInfo.DNS.Question[0].Type)

	// Sender 发送DNS回复
	sInfo, err := handler.Sender.Send(rInfo)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 输出SendInfo
	// fmt.Println(sInfo.String())
	fmt.Printf("[%s]Send response to IP: %s, FragmentsNum: %d, TotalSize: %d\n",
		time.Now().Format(time.ANSIC), sInfo.IP, sInfo.FragmentsNum, sInfo.TotalSize)
}

// QueryInfo 记录 DNS 查询相关信息
// 其包括有：：
//   - MAC: net.HardwareAddr，接收 DNS 请求的 MAC 地址
//   - IP: net.IP，接收 DNS 请求的 IP 地址
//   - Port: int，接收 DNS 请求的端口
//   - DNS: *dns.DNSMessage，接收 DNS 请求的 DNS 消息
type QueryInfo struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port int
	DNS  *dns.DNSMessage
}

func (q *QueryInfo) String() string {
	return fmt.Sprintf("Receive query from IP: %s, Port: %d, DNS Message:\n%s", q.IP, q.Port, q.DNS.String())
}

// ResponseInfo 记录 DNS 回复相关信息
// 其包括有：：
//   - MAC: net.HardwareAddr，接收 DNS 请求的 MAC 地址
//   - IP: net.IP，接收 DNS 请求的 IP 地址
//   - Port: int，接收 DNS 请求的端口
//   - DNS: *dns.DNSMessage，接收 DNS 请求的 DNS 消息
type ResponseInfo struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port int
	DNS  *dns.DNSMessage
}

func (s *ResponseInfo) String() string {
	return fmt.Sprintf("Response to IP: %s, Port: %d, DNS Message:\n%s", s.IP, s.Port, s.DNS.String())
}

// SendInfo 记录 发送 DNS 回复相关信息
// 其包括有：：
//   - MAC: net.HardwareAddr，发送 DNS 回复的 MAC 地址
//   - IP: net.IP，发送 DNS 回复的 IP 地址
//   - Port: int，发送 DNS 回复的端口
//   - FragmentsNum: int，发送 DNS 回复的分片数量
//   - TotalSize: int，发送 DNS 回复的总大小
//   - Data: []byte，发送 DNS 回复的数据
type SendInfo struct {
	MAC          net.HardwareAddr
	IP           net.IP
	Port         int
	FragmentsNum int
	TotalSize    int
	Data         []byte
}

func (s *SendInfo) String() string {
	return fmt.Sprintf("Send response to IP: %s, Port: %d, FragmentsNum: %d, TotalSize: %d", s.IP, s.Port, s.FragmentsNum, s.TotalSize)
}
