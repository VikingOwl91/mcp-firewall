package logging

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

type HashChain struct {
	mu       sync.Mutex
	seq      uint64
	prevHash string
}

func NewHashChain() *HashChain {
	return &HashChain{
		prevHash: fmt.Sprintf("%x", sha256.Sum256([]byte(""))),
	}
}

func (hc *HashChain) Next(entryJSON []byte) (seq uint64, entryHash, prevHash string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.seq++
	seq = hc.seq
	prevHash = hc.prevHash

	hash := sha256.Sum256([]byte(prevHash + string(entryJSON)))
	entryHash = fmt.Sprintf("%x", hash)

	hc.prevHash = entryHash
	return seq, entryHash, prevHash
}
