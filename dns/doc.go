// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

/*
dns 使用Go的内置实现，提供了 DNS消息 的编解码功能，可以用于任意构造和解析 DNS消息。

子模块dns/gopacket实现了gopacket的DecodingLayer, SerializeLayer等相应接口使其可以与gopacket无缝衔接。
您可以把dns看作是gopacket中DNS相关部分的重新实现，目的是使其更加易用。
*/
package dns
