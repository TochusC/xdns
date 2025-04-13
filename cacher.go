package xdns

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/tochusc/xdns/dns"
)

type Cacher struct {
	CacheLocation string
	CacherLogger  *log.Logger
}

type CacherConfig struct {
	CacheLocation string
	LogWriter     io.Writer
}

func NewCacher(conf CacherConfig) *Cacher {
	cacherLogger := log.New(conf.LogWriter, "Cacher: ", log.LstdFlags)

	return &Cacher{
		CacheLocation: conf.CacheLocation,
		CacherLogger:  cacherLogger,
	}
}

func (c *Cacher) CacheResponse(data []byte) error {
	ident, err := IdentifyMessage(data)
	if err != nil {
		c.CacherLogger.Printf("Error identifying response: %v", err)
		return err
	}

	path := filepath.Join(c.CacheLocation, ident)

	// 将响应缓存到磁盘

	// 如果缓存目录不存在，创建目录
	if _, err := os.Stat(c.CacheLocation); os.IsNotExist(err) {
		err := os.MkdirAll(c.CacheLocation, 0755)
		if err != nil {
			c.CacherLogger.Printf("Error creating cache directory %s: %v", c.CacheLocation, err)
			return err
		}
	}

	// 创建缓存文件
	file, err := os.Create(path)
	if err != nil {
		c.CacherLogger.Printf("Error creating cache file %s: %v", ident, err)
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		c.CacherLogger.Printf("Error writing cache file %s: %v", ident, err)
		return err
	}

	file.Close()
	c.CacherLogger.Printf("Cache saved %s\n", ident)

	return nil
}

func (c *Cacher) FetchCache(connInfo ConnectionInfo) ([]byte, error) {

	ident, err := IdentifyMessage(connInfo.Packet)
	if err != nil {
		c.CacherLogger.Printf("Error identifying response: %v", err)
		return []byte{}, err
	}

	path := filepath.Join(c.CacheLocation, ident)

	file, err := os.Open(path)
	if err != nil {
		c.CacherLogger.Printf("Cache miss %s\n", ident)
		return []byte{}, err
	}
	defer file.Close()

	cache := make([]byte, 65535)
	rd, err := file.Read(cache)
	if err != nil {
		c.CacherLogger.Printf("Error reading cache file %s: %v", ident, err)
		return []byte{}, err
	}

	c.CacherLogger.Printf("Cache hit %s\n", ident)

	// 修改Cache内容
	cache[0] = connInfo.Packet[0]
	cache[1] = connInfo.Packet[1]
	for i := 0; ; i++ {
		cache[12+i] = connInfo.Packet[12+i]

		if cache[12+i] > dns.NamePointerFlag {
			cache[13+i] = connInfo.Packet[13+i]
			break
		}
		if cache[12+i] == 0x00 {
			break
		}
	}

	return cache[:rd], nil
}

func IdentifyMessage(data []byte) (string, error) {
	// 解析 DNS 请求
	qName, offset, err := dns.DecodeDomainNameFromBuffer(data, 12)
	if err != nil {
		return "", err
	}
	qType := dns.DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
	qClass := dns.DNSClass(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	return fmt.Sprintf("%s-%s-%s", qName, qType.String(), qClass.String()), nil
}
