package rpc

import (
	"encoding/json"
	"sync"
	"time"

	"padi-chain/common"
	"padi-chain/core"
)

// Polling filters.
//
// A client that wants to watch for events without a persistent connection
// installs a filter and asks periodically for what has happened since it last
// asked. That is how web3.py, ethers and most tooling watch logs over plain
// HTTP, so a node without it looks broken to them even though eth_getLogs works.
//
// Filters are per-node state rather than chain state: they hold a cursor, not a
// commitment, and a client that stops polling simply has its filter expire.

// filterKind distinguishes what a filter is watching.
type filterKind uint8

const (
	filterLogs filterKind = iota
	filterBlocks
	filterPendingTx
)

type filter struct {
	kind     filterKind
	criteria filterCriteria
	// cursor is the next block to report from, for log and block filters.
	cursor   uint64
	lastUsed time.Time
}

// filterSet holds a node's active filters.
type filterSet struct {
	mu      sync.Mutex
	filters map[string]*filter
	nextID  uint64
	ttl     time.Duration
	now     func() time.Time
}

func newFilterSet() *filterSet {
	return &filterSet{
		filters: make(map[string]*filter),
		ttl:     5 * time.Minute,
		now:     time.Now,
	}
}

// add installs a filter and returns its identifier.
func (s *filterSet) add(f *filter) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireLocked()
	s.nextID++
	id := common.EncodeHexUint(s.nextID)
	f.lastUsed = s.now()
	s.filters[id] = f
	return id
}

// get returns a filter and marks it used.
func (s *filterSet) get(id string) (*filter, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.filters[id]
	if !ok {
		return nil, false
	}
	f.lastUsed = s.now()
	return f, true
}

// remove uninstalls a filter.
func (s *filterSet) remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.filters[id]
	delete(s.filters, id)
	return ok
}

// expireLocked drops filters nobody has polled recently, so a client that
// disappears does not leak one forever.
func (s *filterSet) expireLocked() {
	cutoff := s.now().Add(-s.ttl)
	for id, f := range s.filters {
		if f.lastUsed.Before(cutoff) {
			delete(s.filters, id)
		}
	}
}

// count returns how many filters are installed.
func (s *filterSet) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.filters)
}

// --- RPC methods ---

func (a *API) newFilter(params []json.RawMessage) (any, error) {
	criteria, err := decodeParam[filterCriteria](params, 0)
	if err != nil {
		return nil, err
	}
	from, _, err := a.resolveRange(criteria.FromBlock, criteria.ToBlock)
	if err != nil {
		return nil, err
	}
	return a.filters.add(&filter{kind: filterLogs, criteria: criteria, cursor: from}), nil
}

func (a *API) newBlockFilter(params []json.RawMessage) (any, error) {
	head := a.backend.Chain().CurrentBlock().NumberU64()
	return a.filters.add(&filter{kind: filterBlocks, cursor: head + 1}), nil
}

func (a *API) newPendingTransactionFilter(params []json.RawMessage) (any, error) {
	return a.filters.add(&filter{kind: filterPendingTx}), nil
}

func (a *API) uninstallFilter(params []json.RawMessage) (any, error) {
	id, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	return a.filters.remove(id), nil
}

// getFilterChanges returns what has happened since the filter was last polled.
func (a *API) getFilterChanges(params []json.RawMessage) (any, error) {
	id, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	f, ok := a.filters.get(id)
	if !ok {
		return nil, NewError(CodeInvalidParams, "filter %s does not exist", id)
	}

	head := a.backend.Chain().CurrentBlock().NumberU64()

	switch f.kind {
	case filterBlocks:
		hashes := []string{}
		for n := f.cursor; n <= head; n++ {
			if block := a.backend.Chain().GetBlockByNumber(n); block != nil {
				hashes = append(hashes, block.Hash().Hex())
			}
		}
		f.cursor = head + 1
		return hashes, nil

	case filterPendingTx:
		// Report what is pending now. A cursor over the pool would be
		// misleading: entries leave it by being mined, not by being read.
		hashes := []string{}
		for _, txs := range a.backend.TxPool().Pending() {
			for _, tx := range txs {
				hashes = append(hashes, tx.Hash().Hex())
			}
		}
		return hashes, nil

	default:
		logs, err := a.collectLogs(f.criteria, f.cursor, head)
		if err != nil {
			return nil, err
		}
		f.cursor = head + 1
		return logs, nil
	}
}

// getFilterLogs returns everything a log filter matches, ignoring the cursor.
func (a *API) getFilterLogs(params []json.RawMessage) (any, error) {
	id, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	f, ok := a.filters.get(id)
	if !ok {
		return nil, NewError(CodeInvalidParams, "filter %s does not exist", id)
	}
	if f.kind != filterLogs {
		return []map[string]any{}, nil
	}
	from, to, err := a.resolveRange(f.criteria.FromBlock, f.criteria.ToBlock)
	if err != nil {
		return nil, err
	}
	return a.collectLogs(f.criteria, from, to)
}

// collectLogs gathers matching logs across a block range.
func (a *API) collectLogs(criteria filterCriteria, from, to uint64) ([]map[string]any, error) {
	addresses, err := parseAddressFilter(criteria.Address)
	if err != nil {
		return nil, err
	}
	topics, err := parseTopicFilter(criteria.Topics)
	if err != nil {
		return nil, err
	}

	bc := a.backend.Chain()
	out := []map[string]any{}
	for n := from; n <= to; n++ {
		block := bc.GetBlockByNumber(n)
		if block == nil {
			continue
		}
		// The header's bloom rules most blocks out without touching receipts.
		if !bloomMayContain(block.Bloom(), addresses, topics) {
			continue
		}
		for _, log := range bc.GetLogs(block.Hash()) {
			if matchesFilter(log, addresses, topics) {
				out = append(out, marshalLog(log))
			}
		}
	}
	return out, nil
}

var _ = core.Log{}
