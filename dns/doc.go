// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

/*
dns 使用Go的内置实现，提供了 DNS消息 的编解码功能，可以用于任意构造和解析 DNS消息。

// DNSMessage 表示 DNS协议 的消息结构。

	type DNSMessage struct {
		// DNS消息 头部
		Header DNSHeader // DNS 头部（Header）
		// DNS消息的各个部分（Section）
		Question   DNSQuestionSection // DNS 查询部分（Questions Section）
		Answer     DNSResponseSection // DNS 回答部分（Answers Section）
		Authority  DNSResponseSection // DNS 权威部分（Authority Section）
		Additional DNSResponseSection // DNS 附加部分（Additional Section）
	}

子模块dns/xlayers则提供了实现gopacket接口的DNS封装结构，

可以把dns包看作是 gopacket 中 DNS 相关部分的重新实现，目的是使其更加易用。
也可以将其单独作为一个独立的DNS消息编解码库来使用。
*/
package dns
