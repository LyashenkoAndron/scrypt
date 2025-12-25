package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/scrypt"
)

type ScryptData struct {
	N      int
	R      int
	P      int
	KeyLen int
	Salt   []byte
	Hash   []byte
}

// N*r*p*keyLen*salt*hash
func parseFile(filename string) (*ScryptData, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(strings.TrimSpace(string(content)), "*")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid format, expected 6 parts, got %d", len(parts))
	}

	data := &ScryptData{}

	data.N, err = strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid N parameter: %v", err)
	}

	data.R, err = strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid r parameter: %v", err)
	}

	data.P, err = strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid p parameter: %v", err)
	}

	data.KeyLen, err = strconv.Atoi(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid keyLen parameter: %v", err)
	}

	data.Salt, err = hex.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %v", err)
	}

	data.Hash, err = hex.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid hash: %v", err)
	}

	return data, nil
}

func verifyPassword(password string, data *ScryptData) bool {
	hash, err := scrypt.Key([]byte(password), data.Salt, data.N, data.R, data.P, data.KeyLen)
	if err != nil {
		return false
	}
	return bytes.Equal(hash, data.Hash)
}

func getCharset(m rune) string {
	switch m {
	case 'a':
		return "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890"
	case 'd':
		return "1234567890"
	case 'l':
		return "qwertyuiopasdfghjklzxcvbnm"
	case 'u':
		return "QWERTYUIOPASDFGHJKLZXCVBNM"
	case 's':
		return "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}
	return ""
}

func generatePasswords(mask string, ch chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(ch)

	charsets := make([]string, len(mask))
	for i, m := range mask {
		charsets[i] = getCharset(m)
		if charsets[i] == "" {
			fmt.Fprintf(os.Stderr, "Invalid mask character: %c\n", m)
			return
		}
	}

	ind := make([]int, len(mask))
	password := make([]byte, len(mask))

	for {
		for i := range mask {
			password[i] = charsets[i][ind[i]]
		}
		ch <- string(password)

		carry := true
		for i := len(ind) - 1; i >= 0 && carry; i-- {
			ind[i]++
			if ind[i] < len(charsets[i]) {
				carry = false
			} else {
				ind[i] = 0
			}
		}

		if carry {
			break
		}
	}
}

func worker(passwords <-chan string, data *ScryptData, found *atomic.Bool, result chan<- string, tried *atomic.Uint64) {
	for password := range passwords {
		if found.Load() {
			for range passwords {
			}
			return
		}

		tried.Add(1)

		if verifyPassword(password, data) {
			if found.CompareAndSwap(false, true) {
				result <- password
			}
			return
		}
	}
}

func calculateTotalCombinations(mask string) uint64 {
	total := uint64(1)
	for _, m := range mask {
		total *= uint64(len(getCharset(m)))
	}
	return total
}

func main() {
	maskFlag := flag.String("m", "", "Password mask (a=all, d=digit, l=lowercase, u=uppercase, s=special)")
	flag.Parse()

	if *maskFlag == "" || flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s -m <mask> <hash_file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nMask characters:\n")
		fmt.Fprintf(os.Stderr, "  a - all characters (letters + digits)\n")
		fmt.Fprintf(os.Stderr, "  d - digits only (0-9)\n")
		fmt.Fprintf(os.Stderr, "  l - lowercase letters (a-z)\n")
		fmt.Fprintf(os.Stderr, "  u - uppercase letters (A-Z)\n")
		fmt.Fprintf(os.Stderr, "  s - special symbols (!@#$...)\n")
		fmt.Fprintf(os.Stderr, "\nExample: %s -m aaadd hash.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  This will try all 3-letter + 2-digit combinations\n")
		os.Exit(1)
	}

	data, err := parseFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing file: %v\n", err)
		os.Exit(1)
	}

	total := calculateTotalCombinations(*maskFlag)

	fmt.Printf("Scrypt bruteforce\n")
	fmt.Printf("=================\n")
	fmt.Printf("Parameters: N=%d, r=%d, p=%d\n", data.N, data.R, data.P)
	fmt.Printf("Mask: %s\n", *maskFlag)
	fmt.Printf("Total combinations: %d\n", total)
	fmt.Printf("CPU cores: %d\n\n", runtime.NumCPU())

	passwords := make(chan string, 10000)
	result := make(chan string, 1)
	var found atomic.Bool
	var tried atomic.Uint64
	var wg sync.WaitGroup

	wg.Add(1)
	go generatePasswords(*maskFlag, passwords, &wg)

	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		go worker(passwords, data, &found, result, &tried)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	done := make(chan bool)
	go func() {
		wg.Wait()
		time.Sleep(100 * time.Millisecond)
		done <- true
	}()

	start := time.Now()

	for {
		select {
		case <-ticker.C:
			count := tried.Load()
			progress := float64(count) / float64(total) * 100
			speed := float64(count) / time.Since(start).Seconds()

			remaining := float64(total-count) / speed
			fmt.Printf("\rProgress: %.2f%% | Tried: %d/%d | Speed: %.0f pwd/s | ETA: %.0fs    ",
				progress, count, total, speed, remaining)

		case pwd := <-result:
			fmt.Printf("\n\nPASSWORD FOUND: %s\n", pwd)
			fmt.Printf("Attempts: %d\n", tried.Load())
			fmt.Printf("Time: %.2f seconds\n", time.Since(start).Seconds())
			return

		case <-done:
			fmt.Printf("\n\nPASSWORD NOT FOUND\n")
			fmt.Printf("Tried: %d passwords\n", tried.Load())
			fmt.Printf("Time: %.2f seconds\n", time.Since(start).Seconds())
			return
		}
	}
}
