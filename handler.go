package godns

import "fmt"

func HandlePkt(pkt []byte) {
	qInfo, _ := Parse(pkt)
	// 根据qInfo的内容做一些什么东西
	// ...
	// 输出QueryInfo
	fmt.Println(qInfo.String())

	rInfo, err := Response(qInfo)
	if err != nil {
		// 处理错误
	}

	// // 发送response
	err = Send(rInfo)
	if err != nil {
		// 处理错误
	}

	return
}
