package godns

import (
	"net"

	"github.com/tochusc/godns/dns"
)

type QueryInfo struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port int
	DNS  dns.DNS
}
