# GoDNS

[![madewithlove](https://img.shields.io/badge/made_with-%E2%9D%A4-red?style=for-the-badge&labelColor=orange&style=flat-square)](https://github.com/TochusC/godns)
![Go Version](https://img.shields.io/github/go-mod/go-version/tochusc/godns/master?filename=go.mod&style=flat-square)
![Latest Version](https://img.shields.io/github/v/tag/tochusc/godns?label=latest&style=flat-square)
![License](https://img.shields.io/github/license/tochusc/godns?style=flat-square)
[![GoDoc](https://godoc.org/github.com/tochusc/godns?status.svg)](https://godoc.org/github.com/tochusc/godns)

GoDNS is a fast and flexible **experimental** DNS server designed to help developers and researchers explore and experiment with various features of the DNS protocol.

## Table of Contents

- [Overview](#overview)
- [GoDNSServer](#gondnserver)
- [Example](#example)
- [Constructing and Generating DNS Responses](#constructing-and-generating-dns-responses)
- [dns Package](#dns-package)
- [xlayers Subpackage](#xlayers-subpackage)
- [xperi Subpackage](#xperi-subpackage)

## Overview

`GoDNSServer` consists of three main components:

1. **ServerConfig**: Configuration for the DNS server.
2. **Sniffer**: A packet sniffer that listens on specified network devices and ports.
3. **Handler**: A packet handler responsible for processing DNS requests and generating responses.

## GoDNSServer

`GoDNSServer` is a top-level encapsulation of the DNS server, providing flexible interfaces and functionalities.

### Sniffer

`Sniffer` listens on specified network devices and ports to sniff DNS requests.

### Handler

`Handler` is responsible for processing DNS requests and generating replies, consisting of the following four parts:

- **Parser**: Parses DNS requests.
- **Responser**: Generates DNS replies.
- **Sender**: Sends DNS replies.
- **DNSServerConfig**: Records the configuration of the DNS server.

## Example

You can start a basic GoDNS server with just a few lines of code:

```go
// Create a DNS server
server := &GoDNSServer{
    ServerConfig: serverConf,
    Sniffer: []*Sniffer{
        NewSniffer(SnifferConfig{
            Device:   serverConf.NetworkDevice,
            Port:     serverConf.Port,
            PktMax:   65535,
            Protocol: ProtocolUDP,
        }),
    },
    Handler: NewHandler(serverConf, &DullResponser{}),
}
server.Start()
```

## Constructing and Generating DNS Responses

`Handler` is used to respond to and process DNS requests. By implementing the `Responser` interface, you can customize the generation of DNS replies.

The `responser.go` file contains several examples of `Responser` implementations for reference.

## dns Package

The `dns` package uses Go's built-in functions to provide encoding and decoding implementations for DNS messages.

### DNSMessage

The `DNSMessage` structure represents the message of the DNS protocol, including:

- **Header**: The DNS header.
- **Question**: The DNS query section.
- **Answer**: The DNS answer section.
- **Authority**: The authority section.
- **Additional**: The additional section.

The `dns` package supports encoding and decoding of resource records of unknown types, providing flexibility to meet experimental needs.

## xlayers Subpackage

The `xlayers` package provides DNS encapsulation structures that implement the `gopacket.Layer` interface, allowing replacement of the original DNS implementation in `gopacket.Layer`.

```go
// DNS structure can be used to replace the original DNS implementation in gopacket.Layer
type DNS struct {
    layers.BaseLayer
    DNSMessage dns.DNSMessage
}
```

## xperi Subpackage

The `xperi` package implements various experimental functions, particularly auxiliary functions related to DNSSEC, including:

- `ParseKeyBase64`: Parses Base64-encoded DNSKEY.
- `CalculateKeyTag`: Calculates the Key Tag of a DNSKEY.
- `GenerateDNSKEY`: Generates DNSKEY RDATA.
- `GenerateRRSIG`: Signs an RRSET to generate RRSIG RDATA.
- `GenerateDS`: Generates DS RDATA for a DNSKEY.
- `GenRandomRRSIG`: Generates random RRSIG RDATA.
- `GenWrongKeyWithTag`: Generates an incorrect DNSKEY RDATA with a specified Key Tag.
- `GenKeyWithTag`: Generates a DNSKEY with a specified Key Tag (this function is time-consuming).

## License

This project is licensed under the [GPL-3.0 License](LICENSE).

---

For more information or support, please visit our [GitHub page](https://github.com/TochusC/godns).