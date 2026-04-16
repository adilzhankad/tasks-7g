package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	iface := flag.String("i", "", "Network interface to capture from (e.g. eth0)")
	hostIP := flag.String("host", "", "IP address to filter by")
	windowSize := flag.Int("window", 100, "Sliding window size for entropy calculation")
	interval := flag.Duration("interval", 5*time.Second, "Print interval for entropy metric")
	flag.Parse()

	if *iface == "" || *hostIP == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -i <interface> -host <ip> [-window N] [-interval duration]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -i eth0 -host 192.168.1.1 -window 100 -interval 5s\n", os.Args[0])
		os.Exit(1)
	}

	fmt.Printf("Capturing on interface: %s\n", *iface)
	fmt.Printf("Filtering packets for host: %s\n", *hostIP)
	fmt.Printf("Sliding window size: %d\n", *windowSize)
	fmt.Printf("Print interval: %s\n", *interval)
	fmt.Println("---")

	window := NewWindow(*windowSize)
	handle := StartCapture(*iface, *hostIP, window)
	defer handle.Close()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			snapshot := window.Snapshot()
			sizes := make([]int, len(snapshot))
			uniqueIPs := make(map[string]int)

			for i, p := range snapshot {
				sizes[i] = p.Size
				if p.Src != *hostIP && p.Src != "" {
					uniqueIPs[p.Src]++
				}
				if p.Dst != *hostIP && p.Dst != "" {
					uniqueIPs[p.Dst]++
				}
			}

			entropy := CalculateEntropy(sizes)

			fmt.Printf("[%s] Packets: %d | Entropy: %.4f | IPs in window:\n",
				time.Now().Format("15:04:05"), len(snapshot), entropy)
			if len(uniqueIPs) == 0 {
				fmt.Println("  (no remote IPs yet)")
			}
			for ip, count := range uniqueIPs {
				fmt.Printf("  %-20s %d pkts\n", ip, count)
			}

		case <-sigCh:
			fmt.Println("\nStopping capture...")
			return
		}
	}
}
