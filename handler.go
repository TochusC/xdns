package godns

import (
	"fmt"
	"time"
)

type Handler struct {
	Parser    Parser
	Responser Responser
	Sender    Sender
	sConf     DNSServerConfig
}

func NewHandler(sConf DNSServerConfig, responser Responser) *Handler {
	return &Handler{
		Parser:    NewParser(),
		Responser: responser,
		Sender:    NewSender(sConf),
		sConf:     sConf,
	}
}

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
