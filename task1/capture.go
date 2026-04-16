package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// StartCapture открывает интерфейс, ставит BPF-фильтр и в отдельной горутине
// ловит пакеты, складывая их в окно.
// Возвращает pcap handle (чтобы потом закрыть).
func StartCapture(iface, hostIP string, window *Window) *pcap.Handle {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface %s: %v", iface, err)
	}

	bpfFilter := fmt.Sprintf("host %s", hostIP)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("Failed to set BPF filter '%s': %v", bpfFilter, err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		for packet := range packetSource.Packets() {
			size := packet.Metadata().Length

			var srcIP, dstIP string
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip := ipLayer.(*layers.IPv6)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}

			window.Add(PacketInfo{Size: size, Src: srcIP, Dst: dstIP})
		}
	}()

	return handle
}
