package godns

import "github.com/tochusc/gopacket"

func HandlePkt(pkt gopacket.Packet) {
	qInfo, _ := Parse(pkt)
	// 根据qInfo的内容做一些什么东西
	// ...
	response, err := Response(qInfo.DNS)
	if err != nil {
		// 处理错误
	}

	// 发送response
	send, err := Send(response)
	if err != nil {
		// 处理错误
	}

	return
}
