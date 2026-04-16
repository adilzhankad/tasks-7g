package main

import "sync"

// PacketInfo хранит информацию об одном пакете
type PacketInfo struct {
	Size int
	Src  string
	Dst  string
}

// Window — потокобезопасное скользящее окно пакетов
type Window struct {
	mu      sync.Mutex
	packets []PacketInfo
	maxSize int
}

// NewWindow создаёт окно заданного размера
func NewWindow(maxSize int) *Window {
	return &Window{
		packets: make([]PacketInfo, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add добавляет пакет в окно. Если окно полное — выкидывает самый старый
func (w *Window) Add(p PacketInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.packets) >= w.maxSize {
		w.packets = w.packets[1:]
	}
	w.packets = append(w.packets, p)
}

// Snapshot возвращает копию текущего состояния окна (безопасно для чтения)
func (w *Window) Snapshot() []PacketInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	snap := make([]PacketInfo, len(w.packets))
	copy(snap, w.packets)
	return snap
}
