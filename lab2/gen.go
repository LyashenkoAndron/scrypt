package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
)

func generateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func computeScryptHash(password string, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, N, r, p, keyLen)
}

func main() {
	password := flag.String("pass", "", "Password to hash")
	output := flag.String("o", "", "Output file (optional)")
	N := flag.Int("N", 16384, "CPU/memory cost parameter (must be power of 2)")
	r := flag.Int("r", 8, "Block size parameter")
	p := flag.Int("P", 1, "Parallelization parameter")
	keyLen := flag.Int("l", 32, "Desired key length in bytes")
	flag.Parse()

	if *password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -pass <password> [-N 16384] [-r 8] [-P 1] [-l 32] [-o file]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nParameters:\n")
		fmt.Fprintf(os.Stderr, "  -pass : Password to hash (required)\n")
		fmt.Fprintf(os.Stderr, "  -N    : CPU/memory cost (default: 16384, must be power of 2)\n")
		fmt.Fprintf(os.Stderr, "  -r    : Block size (default: 8)\n")
		fmt.Fprintf(os.Stderr, "  -P    : Parallelization (default: 1)\n")
		fmt.Fprintf(os.Stderr, "  -l    : Key length in bytes (default: 32)\n")
		fmt.Fprintf(os.Stderr, "  -o    : Output file (optional, prints to stdout if not specified)\n")
		os.Exit(1)
	}

	salt := generateRandom(16)

	fmt.Fprintf(os.Stderr, "Generating scrypt hash...\n")
	fmt.Fprintf(os.Stderr, "Parameters: N=%d, r=%d, p=%d, keyLen=%d\n", *N, *r, *p, *keyLen)

	hashValue, err := computeScryptHash(*password, salt, *N, *r, *p, *keyLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing hash: %v\n", err)
		os.Exit(1)
	}

	result := fmt.Sprintf("%d*%d*%d*%d*%s*%s", *N, *r, *p, *keyLen, hex.EncodeToString(salt), hex.EncodeToString(hashValue))

	if *output != "" {
		err := os.WriteFile(*output, []byte(result), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Hash saved to: %s\n", *output)
	} else {
		fmt.Println(result)
	}
}
