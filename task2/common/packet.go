package protocol

import (
	"encoding/binary"
	"io"
	"net"
)

// PacketInfo — данные, которые sniffer отправляет analyzer'у.
// Фиксированный бинарный формат для передачи через Unix-сокет.
//
// 5-tuple:
//   SrcIP, DstIP   — 4 байта каждый (IPv4)
//   SrcPort, DstPort — 2 байта каждый
//   Proto           — 1 байт (TCP=6, UDP=17, ICMP=1)
// + Length           — 2 байта (размер пакета)
//
// Итого: 4+4+2+2+1+2 = 15 байт на пакет
type PacketInfo struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Length  uint16
}

// MessageSize — фиксированный размер одного сообщения в байтах
const MessageSize = 15

// Encode записывает PacketInfo в writer в бинарном формате (big-endian)
func (p *PacketInfo) Encode(w io.Writer) error {
	buf := make([]byte, MessageSize)
	copy(buf[0:4], p.SrcIP[:])
	copy(buf[4:8], p.DstIP[:])
	binary.BigEndian.PutUint16(buf[8:10], p.SrcPort)
	binary.BigEndian.PutUint16(buf[10:12], p.DstPort)
	buf[12] = p.Proto
	binary.BigEndian.PutUint16(buf[13:15], p.Length)
	_, err := w.Write(buf)
	return err
}

// Decode читает PacketInfo из reader
func (p *PacketInfo) Decode(r io.Reader) error {
	buf := make([]byte, MessageSize)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	copy(p.SrcIP[:], buf[0:4])
	copy(p.DstIP[:], buf[4:8])
	p.SrcPort = binary.BigEndian.Uint16(buf[8:10])
	p.DstPort = binary.BigEndian.Uint16(buf[10:12])
	p.Proto = buf[12]
	p.Length = binary.BigEndian.Uint16(buf[13:15])
	return nil
}

// SrcIPString возвращает source IP как строку
func (p *PacketInfo) SrcIPString() string {
	return net.IP(p.SrcIP[:]).String()
}

// DstIPString возвращает destination IP как строку
func (p *PacketInfo) DstIPString() string {
	return net.IP(p.DstIP[:]).String()
}
