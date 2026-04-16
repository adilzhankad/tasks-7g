package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/adilzhankad/tasks-7g/task2/common"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	iface := flag.String("i", "", "Network interface (e.g. enp4s0)")
	hostIP := flag.String("host", "", "IP address to filter")
	sockPath := flag.String("sock", "/tmp/packet_analyzer.sock", "Unix socket path")
	flag.Parse()

	if *iface == "" || *hostIP == "" {
		fmt.Fprintf(os.Stderr, "Usage: sender -i <interface> -host <ip> [-sock <path>]\n")
		os.Exit(1)
	}

	// Подключаемся к Unix-сокету (receiver должен уже слушать)
	conn, err := net.Dial("unix", *sockPath)
	if err != nil {
		log.Fatalf("Cannot connect to receiver at %s: %v\nMake sure receiver is running first.", *sockPath, err)
	}
	defer conn.Close()
	log.Printf("Connected to receiver at %s", *sockPath)

	// Открываем интерфейс для захвата
	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Cannot open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	// BPF-фильтр — ядро отсеивает ненужные пакеты
	filter := fmt.Sprintf("host %s", *hostIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Cannot set BPF filter: %v", err)
	}
	log.Printf("Capturing on %s, filter: %s", *iface, filter)

	// Graceful shutdown по Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	count := 0
	for {
		select {
		case <-sig:
			log.Printf("Shutting down. Sent %d packets.", count)
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			info := extractPacketInfo(pkt)
			if info == nil {
				continue
			}
			if err := info.Encode(conn); err != nil {
				log.Printf("Send error: %v", err)
				return
			}
			count++
			if count%100 == 0 {
				log.Printf("Sent %d packets", count)
			}
		}
	}
}

// extractPacketInfo достаёт 5-tuple и длину из пакета
func extractPacketInfo(pkt gopacket.Packet) *protocol.PacketInfo {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip := ipLayer.(*layers.IPv4)

	info := &protocol.PacketInfo{
		Proto:  uint8(ip.Protocol),
		Length: uint16(len(pkt.Data())),
	}
	copy(info.SrcIP[:], ip.SrcIP.To4())
	copy(info.DstIP[:], ip.DstIP.To4())

	// Достаём порты из TCP или UDP
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
	}
	// Для ICMP порты остаются 0 — это нормально

	return info
}
