package godns

import "fmt"

type Handler struct {
	Parser    Parser
	Responser Responser
	Sender    Sender
}

func NewHandler(conf DNSServerConfig, responser Responser) *Handler {
	return &Handler{
		Parser:    NewParser(),
		Responser: responser,
		Sender:    NewSender(conf),
	}
}

func (Handler) Handle(pkt []byte) {
	// Parser 解析数据包
	qInfo, _ := parser.Parse(pkt)

	// 输出QueryInfo
	fmt.Println(qInfo.String())

	// Responser 生成DNS回复
	rInfo, err := responser.Response(qInfo)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Sender 发送DNS回复
	err = sender.Send(rInfo)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return
}
