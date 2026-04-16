package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
)

type WordCount struct {
	word  []byte
	count int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: wordfreq <file>\n")
		os.Exit(1)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	allWords := countWordsInFile(file)

	sort.Slice(allWords, func(i, j int) bool {
		return allWords[i].count > allWords[j].count
	})

	top := 20
	if len(allWords) < top {
		top = len(allWords)
	}
	for i := 0; i < top; i++ {
		fmt.Fprintf(os.Stdout, "%7d %s\n", allWords[i].count, allWords[i].word)
	}
}

func countWordsInFile(file *os.File) []WordCount {
	var allWords []WordCount
	var currentWord []byte

	reader := bufio.NewReader(file)

	for {
		b, err := reader.ReadByte()
		if err != nil {
			if len(currentWord) > 0 {
				allWords = findAndIncrement(allWords, currentWord)
			}
			break
		}

		if isLetter(b) {
			currentWord = append(currentWord, toLower(b))
		} else if len(currentWord) > 0 {
			allWords = findAndIncrement(allWords, currentWord)
			currentWord = nil
		}
	}

	return allWords
}

func findAndIncrement(allWords []WordCount, word []byte) []WordCount {
	for i := 0; i < len(allWords); i++ {
		if bytes.Equal(allWords[i].word, word) {
			allWords[i].count++
			return allWords
		}
	}

	wordCopy := make([]byte, len(word))
	copy(wordCopy, word)
	return append(allWords, WordCount{word: wordCopy, count: 1})
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
