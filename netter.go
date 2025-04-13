package xdns

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// NetterConfig 结构体用于记录网络监听器的配置
type NetterConfig struct {
	Port      int
	LogWriter io.Writer
}

// Netter 数据包监听器：接收、解析、发送数据包，并维护连接状态。
type Netter struct {
	NetterPort   int
	NetterLogger *log.Logger
}

func NewNetter(nConf NetterConfig) *Netter {
	netterLogger := log.New(nConf.LogWriter, "Netter: ", log.LstdFlags)

	return &Netter{
		NetterPort:   nConf.Port,
		NetterLogger: netterLogger,
	}
}

// Sniff 函数用于监听指定端口，并返回链接信息通道
// 其返回值为：chan ConnectionInfo，链接信息通道
func (n *Netter) Sniff() chan ConnectionInfo {
	connChan := make(chan ConnectionInfo, 16)

	// udp
	pktConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", n.NetterPort))
	if err != nil {
		n.NetterLogger.Panicf("Error listening on udp port: %v", err)
	}
	conn := pktConn.(*net.UDPConn)
	conn.SetReadBuffer(104857600)
	conn.SetWriteBuffer(104857600)
	if err != nil {
		n.NetterLogger.Panicf("Error listening on udp port: %v", err)
	}
	go n.handlePktConn(pktConn, connChan)

	// tcp
	lstr, err := net.Listen("tcp", fmt.Sprintf(":%d", n.NetterPort))
	if err != nil {
		n.NetterLogger.Panicf("Error listening on tcp port: %v", err)
	}
	go n.handleListener(lstr, connChan)

	return connChan
}

// handleListener 函数用于处理 TCP 链接
// 其接收参数为：
//   - lstr: net.Listener，TCP 监听器
//   - connChan: chan ConnectionInfo，链接信息通道
//
// 该函数将会接受 TCP 链接，并将其发送到链接信息通道中
func (n *Netter) handleListener(lstr net.Listener, connChan chan ConnectionInfo) {
	for {
		conn, err := lstr.Accept()
		if err != nil {
			n.NetterLogger.Printf("Error accepting tcp connection: %v", err)
		} else {
			go n.handleStreamConn(conn, connChan)
		}
	}
}

// handlePktConn 函数用于监听UDP数据包
// 其接收参数为：
//   - pktConn: net.PacketConn，数据包链接
//   - connChan: chan ConnectionInfo，链接信息通道
//
// 该函数将会读取 数据包链接 中的数据，并将其发送到链接信息通道中
func (n *Netter) handlePktConn(pktConn net.PacketConn, connChan chan ConnectionInfo) {
	// 可用缓冲区表
	bufList := make(chan []byte, 10000)
	for i := 0; i < 10000; i++ {
		bufList <- make([]byte, 65535)
	}

	for {
		// 从缓冲区表中取出缓冲区
		buf := <-bufList

		// 读取数据至缓冲区
		sz, addr, err := pktConn.ReadFrom(buf)
		if err != nil {
			n.NetterLogger.Printf("Error reading udp packet: %v", err)
			continue
		}

		go func() {
			// 从缓冲区中取出数据包
			pkt := make([]byte, sz)
			copy(pkt, buf[:sz])

			// 将缓冲区放回缓冲区表
			bufList <- buf

			// 返回链接信息至通道
			connChan <- ConnectionInfo{
				Protocol:   ProtocolUDP,
				Address:    addr,
				PacketConn: pktConn,
				Packet:     pkt,
			}
		}()
	}
}

// handleStreamConn 函数用于处理 流式链接
// 其接收参数为：
//   - conn: net.Conn，流式链接
//   - connChan: chan ConnectionInfo，链接信息通道
//
// 该函数将会读取 流式链接 中的数据，并将其发送到链接信息通道中
func (n *Netter) handleStreamConn(conn net.Conn, connChan chan ConnectionInfo) {
	buf := make([]byte, 10485760)

	sz, err := conn.Read(buf)
	if err != nil {
		n.NetterLogger.Printf("Error reading tcp packet: %v", err)
		return
	}

	msgSz := int(buf[0])<<8 + int(buf[1])
	for sz < msgSz {
		inc, err := conn.Read(buf[sz:])
		if err != nil {
			n.NetterLogger.Printf("Error reading tcp packet: %v", err)
			break
		}
		sz += inc
	}

	pkt := make([]byte, msgSz)
	copy(pkt, buf[2:2+msgSz])
	connChan <- ConnectionInfo{
		Protocol:   ProtocolTCP,
		Address:    conn.RemoteAddr(),
		StreamConn: conn,
		Packet:     pkt,
	}
}

// ConnectionInfo 结构体用于记录链接信息
// 其包含以下字段：
//   - Protocol: Protocol，网络协议
//   - Address: net.Addr，地址
//   - StreamConn: net.Conn，TCP 链接
//   - PacketConn: net.PacketConn，UDP 链接
//   - Packet: []byte，数据包
type ConnectionInfo struct {
	Protocol Protocol // 网络协议
	Address  net.Addr //	地址

	StreamConn net.Conn       // TCP 链接
	PacketConn net.PacketConn // UDP 链接

	Packet []byte //	数据包
}

// Protocol 用于表示网络协议
type Protocol string

const (
	ProtocolUDP Protocol = "udp"
	ProtocolTCP Protocol = "tcp"
)

func (p *Protocol) String() string {
	if *p == ProtocolUDP {
		return "UDP"
	}
	if *p == ProtocolTCP {
		return "TCP"
	}
	return "Unknown"
}

// Send 函数用于发送数据包
// 其接收参数为：
//   - connInfo: ConnectionInfo，链接信息
//   - data: []byte，数据包
func (n *Netter) Send(connInfo ConnectionInfo, data []byte) {
	if connInfo.Protocol == ProtocolUDP {
		_, err := connInfo.PacketConn.WriteTo(data, connInfo.Address)
		if err != nil {
			n.NetterLogger.Printf("Error writing udp packet: %v", err)
		}
	} else if connInfo.Protocol == ProtocolTCP {
		pktSize := len(data)
		if pktSize > 0xffff {
			pktSize = 0xffff
			n.NetterLogger.Printf("Warning: TCP packet size exceeds 0xffff, truncating to 0xffff")
		}

		lenByte := make([]byte, 2)
		binary.BigEndian.PutUint16(lenByte, uint16(pktSize))

		connInfo.StreamConn.Write(append(lenByte, data...))
		connInfo.StreamConn.Close()
	}

	n.NetterLogger.Printf("Packet sent to %s, size: %d", connInfo.Address, len(data))
}
