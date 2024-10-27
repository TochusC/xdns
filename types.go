package godns

import (
	"fmt"
	"net"

	"github.com/tochusc/godns/dns"
)

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
