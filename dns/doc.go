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

子模块dns/xlayers提供了实现gopacket接口的DNS封装结构，

您可以把dns看作是gopacket中DNS相关部分的重新实现，目的是使其更加易用。
*/
package dns
