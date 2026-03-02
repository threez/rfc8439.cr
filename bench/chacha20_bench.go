package main

import (
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20"
)

func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12) // 96-bit nonce for RFC 8439
	for i := range key {
		key[i] = 0xfe
	}
	for i := range nonce {
		nonce[i] = 0xfe
	}

	plaintext := make([]byte, 1024*1024) // 1 MB
	encrypted := make([]byte, 1024*1024)

	const iterations = 1024
	totalBytes := int64(iterations) * int64(len(plaintext))

	start := time.Now()
	for i := 0; i < iterations; i++ {
		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}
		cipher.SetCounter(0)
		cipher.XORKeyStream(encrypted, plaintext)
	}
	elapsed := time.Since(start)

	mbPerSec := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	fmt.Printf("CHACHA20 x/crypto (%d MB): %.2f MB/s (%.3fs)\n", totalBytes/(1024*1024), mbPerSec, elapsed.Seconds())
}
