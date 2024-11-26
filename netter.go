package godns

import (
	"encoding/binary"
	"fmt"
	"net"
)

// NetterConfig 结构体用于记录网络监听器的配置
type NetterConfig struct {
	Port int
	MTU  int
}

// Netter 数据包监听器：接收、解析、发送数据包，并维护连接状态。
type Netter struct {
	Config NetterConfig
}

// Sniff 函数用于监听指定端口，并返回链接信息通道
// 其返回值为：chan ConnectionInfo，链接信息通道
func (n *Netter) Sniff() chan ConnectionInfo {
	connChan := make(chan ConnectionInfo)

	// udp
	pktConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", n.Config.Port))
	if err != nil {
		panic(fmt.Sprintln("Netter: Error listening on udp port: ", err))
	}
	go n.handlePktConn(pktConn, connChan)

	// tcp
	lstr, err := net.Listen("tcp", fmt.Sprintf(":%d", n.Config.Port))
	if err != nil {
		panic(fmt.Sprintln("Netter: Error listening on tcp port: ", err))
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
			fmt.Println("Netter: Error accepting tcp connection: ", err)
			continue
		}
		go n.handleStreamConn(conn, connChan)
	}
}

// handlePktConn 函数用于处理 数据包 链接
// 其接收参数为：
//   - pktConn: net.PacketConn，数据包链接
//   - connChan: chan ConnectionInfo，链接信息通道
//
// 该函数将会读取 数据包链接 中的数据，并将其发送到链接信息通道中
func (n *Netter) handlePktConn(pktConn net.PacketConn, connChan chan ConnectionInfo) {
	buf := make([]byte, n.Config.MTU)

	for {
		sz, addr, err := pktConn.ReadFrom(buf)
		if err != nil {
			fmt.Println("Netter: Error reading udp packet: ", err)
			return
		}

		pkt := make([]byte, sz)
		copy(pkt, buf[:sz])
		connChan <- ConnectionInfo{
			Protocol:   ProtocolUDP,
			Address:    addr,
			PacketConn: pktConn,
			Packet:     pkt,
		}
	}
}

// handleStreamConn 函数用于处理 流式链接
// 其接收参数为：
//   - conn: net.Conn，流式链接
//   - connChan: chan ConnectionInfo，链接信息通道
//
// 该函数将会读取 流式链接 中的数据，并将其发送到链接信息通道中
func (n *Netter) handleStreamConn(conn net.Conn, connChan chan ConnectionInfo) {
	buf := make([]byte, n.Config.MTU)

	sz, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Netter: Error reading tcp packet: ", err)
		return
	}

	msgSz := int(buf[0])<<8 + int(buf[1])
	for sz < msgSz {
		inc, err := conn.Read(buf[sz:])
		if err != nil {
			fmt.Println("Netter: Error reading tcp packet: ", err)
			return
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
			fmt.Println("Netter: Error writing udp packet: ", err)
		}
	}

	if connInfo.Protocol == ProtocolTCP {
		pktSize := len(data)
		if pktSize > 0xffff {
			pktSize = 0xffff
			fmt.Printf("Netter: Warning: packet size exceeds 0xffff, truncating to 0xffff\n")
		}

		lenByte := make([]byte, 2)
		binary.BigEndian.PutUint16(lenByte, uint16(pktSize))

		connInfo.StreamConn.Write(append(lenByte, data...))
		connInfo.StreamConn.Close()
	}
}
