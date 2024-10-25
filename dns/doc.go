// Copyright 2024 TochusC, AOSP Lab. All rights reserved.
/*
dns 包是gopacket/layers包中DNS编码部分的重新实现
目的是使其更加可用，同时也与gopacket框架兼容。

dns 主要专注于生成DNS数据包，目前还不具备从字节数据中解析DNS数据包的功能。
*/
package dns
