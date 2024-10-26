// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// server.go 文件实现了 DNS 服务器的启动。

package godns

import (
	"fmt"
	"time"
)

func main() {
	// GoDNS 启动！
	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "GoDNS Starts!")

	pktChan := Sniff(DNSSeverNetworkDevice, MTU, DNSServerPort)
	for {
		select {
		case pkt := <-pktChan:
			go HandlePkt(pkt)
		}
	}
}
