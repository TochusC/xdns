package godns

import (
	"fmt"
	"net"

	"github.com/tochusc/godns/dns"
)

// DNS服务器配置

type DNSServerConfig struct {
	// DNSServerIP 是 DNS 服务器的 IP 地址
	DNSServerIP net.IP
	// DNSServerPort 是 DNS 服务器的端口
	DNSServerPort int
	// DNSSeverNetworkDevice 是 DNS 服务器所用网络设备的名称
	DNSSeverNetworkDevice string
	// MTU 是网络设备的最大传输单元
	MTU int
	// DNSServerMAC 是 DNS 服务器的 MAC 地址
	DNSServerMAC net.HardwareAddr
}

// QueryInfo 记录 DNS 查询相关信息
type QueryInfo struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port int
	DNS  *dns.DNSMessage
}

func (q *QueryInfo) String() string {
	return fmt.Sprintf("Received DNS query from IP: %s, Port: %d, DNS Message:\n%s", q.IP, q.Port, q.DNS.String())
}

type ResponseInfo struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port int
	DNS  *dns.DNSMessage
}

func (s *ResponseInfo) String() string {
	return fmt.Sprintf("Send DNS response to IP: %s, Port: %d, DNS Message:\n%s", s.IP, s.Port, s.DNS.String())
}
