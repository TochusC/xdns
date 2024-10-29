package godns

import (
	"fmt"
	"net"

	"github.com/tochusc/godns/dns"
)

// DNS服务器配置

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

// QueryInfo 记录 DNS 查询相关信息
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
