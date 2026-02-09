package logging_test

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashChain_FirstEntry(t *testing.T) {
	hc := logging.NewHashChain()

	entry := []byte(`{"method":"tools/call","tool":"echo"}`)
	seq, entryHash, prevHash := hc.Next(entry)

	assert.Equal(t, uint64(1), seq)

	// prevHash should be SHA256("")
	genesis := fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	assert.Equal(t, genesis, prevHash)

	// entryHash should be SHA256(prevHash + entryJSON)
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(genesis+string(entry))))
	assert.Equal(t, expected, entryHash)
}

func TestHashChain_SecondEntry(t *testing.T) {
	hc := logging.NewHashChain()

	entry1 := []byte(`{"method":"tools/call","seq":1}`)
	seq1, entryHash1, _ := hc.Next(entry1)
	assert.Equal(t, uint64(1), seq1)

	entry2 := []byte(`{"method":"tools/list","seq":2}`)
	seq2, entryHash2, prevHash2 := hc.Next(entry2)

	assert.Equal(t, uint64(2), seq2)
	assert.Equal(t, entryHash1, prevHash2)

	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(entryHash1+string(entry2))))
	assert.Equal(t, expected, entryHash2)
}

func TestHashChain_ChainVerification(t *testing.T) {
	hc := logging.NewHashChain()

	entries := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"b":2}`),
		[]byte(`{"c":3}`),
	}

	type record struct {
		seq       uint64
		entryHash string
		prevHash  string
		data      []byte
	}

	var records []record
	for _, e := range entries {
		seq, eh, ph := hc.Next(e)
		records = append(records, record{seq, eh, ph, e})
	}

	// Verify chain integrity
	for i, r := range records {
		assert.Equal(t, uint64(i+1), r.seq)

		recomputed := fmt.Sprintf("%x", sha256.Sum256([]byte(r.prevHash+string(r.data))))
		assert.Equal(t, recomputed, r.entryHash, "chain broken at seq %d", r.seq)

		if i > 0 {
			assert.Equal(t, records[i-1].entryHash, r.prevHash, "prevHash mismatch at seq %d", r.seq)
		}
	}
}

func TestHashChain_Concurrent(t *testing.T) {
	hc := logging.NewHashChain()
	n := 100

	type result struct {
		seq       uint64
		entryHash string
		prevHash  string
	}

	results := make([]result, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			entry := []byte(fmt.Sprintf(`{"i":%d}`, idx))
			seq, eh, ph := hc.Next(entry)
			results[idx] = result{seq, eh, ph}
		}(i)
	}
	wg.Wait()

	// Collect all seq values — should be 1..n with no duplicates
	seqs := make(map[uint64]bool)
	for _, r := range results {
		require.False(t, seqs[r.seq], "duplicate seq %d", r.seq)
		seqs[r.seq] = true
	}
	assert.Len(t, seqs, n)

	for i := uint64(1); i <= uint64(n); i++ {
		assert.True(t, seqs[i], "missing seq %d", i)
	}
}
