package main

import "math"

// CalculateEntropy вычисляет энтропию Шеннона по размерам пакетов.
// Каждый уникальный размер — отдельный символ.
func CalculateEntropy(sizes []int) float64 {
	n := len(sizes)
	if n == 0 {
		return 0.0
	}

	// Считаем частоту каждого размера
	freq := make(map[int]int)
	for _, size := range sizes {
		freq[size]++
	}

	// H = -Σ p(x) * log2(p(x))
	entropy := 0.0
	nf := float64(n)
	for _, count := range freq {
		p := float64(count) / nf
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
