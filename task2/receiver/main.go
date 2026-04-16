package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/adilzhankad/tasks-7g/task2/common"
)

// HostStats — статистика по одному IP-адресу
type HostStats struct {
	IP      string
	Packets uint64
	Bytes   uint64
}

var (
	stats []HostStats
	mu    sync.Mutex
)

func main() {
	sockPath := flag.String("sock", "/tmp/packet_analyzer.sock", "Unix socket path")
	interval := flag.Duration("interval", 5*time.Second, "Stats print interval")
	flag.Parse()

	// Удаляем старый сокет-файл если остался
	os.Remove(*sockPath)

	// Начинаем слушать Unix-сокет
	listener, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatalf("Cannot listen on %s: %v", *sockPath, err)
	}
	defer listener.Close()
	defer os.Remove(*sockPath)
	log.Printf("Listening on %s", *sockPath)

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down...")
		listener.Close()
	}()

	// Горутина: периодический вывод статистики
	go printStats(*interval)

	// Принимаем подключения от sender'ов
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Ошибка после закрытия listener при shutdown — нормально
			return
		}
		log.Println("Sender connected")
		go handleConnection(conn)
	}
}

// handleConnection читает PacketInfo из соединения и обновляет статистику
func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		var info protocol.PacketInfo
		err := info.Decode(conn)
		if err == io.EOF {
			log.Println("Sender disconnected")
			return
		}
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		updateStats(&info)
	}
}

// updateStats обновляет статистику по source и destination IP
func updateStats(info *protocol.PacketInfo) {
	srcIP := info.SrcIPString()
	dstIP := info.DstIPString()
	length := uint64(info.Length)

	mu.Lock()
	defer mu.Unlock()

	addToStats(srcIP, length)
	if dstIP != srcIP {
		addToStats(dstIP, length)
	}
}

// addToStats добавляет пакет к статистике конкретного IP
func addToStats(ip string, length uint64) {
	for i := range stats {
		if stats[i].IP == ip {
			stats[i].Packets++
			stats[i].Bytes += length
			return
		}
	}
	// IP ещё не встречался — добавляем
	stats = append(stats, HostStats{
		IP:      ip,
		Packets: 1,
		Bytes:   length,
	})
}

// printStats периодически выводит IP с макс. пакетами и IP с макс. байтами
func printStats(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		if len(stats) == 0 {
			mu.Unlock()
			log.Println("No data yet...")
			continue
		}

		// Ищем максимумы линейным проходом
		maxPktIdx := 0
		maxByteIdx := 0
		for i := 1; i < len(stats); i++ {
			if stats[i].Packets > stats[maxPktIdx].Packets {
				maxPktIdx = i
			}
			if stats[i].Bytes > stats[maxByteIdx].Bytes {
				maxByteIdx = i
			}
		}

		fmt.Printf("\n=== Stats (%s) ===\n", time.Now().Format("15:04:05"))
		fmt.Printf("Most packets: %s (%d packets)\n", stats[maxPktIdx].IP, stats[maxPktIdx].Packets)
		fmt.Printf("Most bytes:   %s (%d bytes)\n", stats[maxByteIdx].IP, stats[maxByteIdx].Bytes)
		fmt.Printf("Total unique IPs: %d\n", len(stats))

		mu.Unlock()
	}
}
