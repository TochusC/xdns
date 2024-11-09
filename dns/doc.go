// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

/*
dns 使用Go的内置实现，提供了 DNS消息 的编解码功能，可以用于任意构造和解析 DNS消息。

[DNSMessage] 表示 DNS协议 的消息结构。

	type DNSMessage struct {
		// DNS消息 头
		Header DNSHeader // DNS 头部（Header）
		// DNS消息的各个部分（Section）
		Question   DNSQuestionSection // DNS 查询部分（Questions Section）
		Answer     DNSResponseSection // DNS 回答部分（Answers Section）
		Authority  DNSResponseSection // DNS 权威部分（Authority Section）
		Additional DNSResponseSection // DNS 附加部分（Additional Section）
	}

dns包中的每个结构体基本都实现了以下方法：
  - func (s *struct) DecodeFromBuffer(buffer []byte, offset int) (int, error)
  - func (s *struct) Encode() []byte
  - func (s *struct) EncodeToBuffer(buffer []byte) (int, error)
  - func (s *struct) Size() int
  - func (s *struct) String() string
  - [少部分实现]func (s *struct) Equal(other *struct) bool

这些方法使得可以方便地对 DNS 消息进行编解码。

dns包对 DNS 消息的格式没有强制限制，并且支持对 未知类型的资源记录 进行编解码，
这使得其可以随意构造和解析 DNS 消息，来满足实验需求。
*/
package dns
