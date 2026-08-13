// Package txpool holds transactions that have been accepted but not yet
// included in a block.
package txpool

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/evm"
	"padi-chain/processor"
	"padi-chain/state"
)

// Rejection reasons. A transaction that fails any of these is never stored, so
// the pool cannot be filled with transactions that could never be mined.
var (
	ErrAlreadyKnown       = errors.New("txpool: transaction is already in the pool")
	ErrNonceTooLow        = errors.New("txpool: nonce is below the account's current nonce")
	ErrInsufficientFunds  = errors.New("txpool: sender cannot afford the transaction")
	ErrIntrinsicGas       = errors.New("txpool: gas limit is below the intrinsic cost")
	ErrGasLimitTooHigh    = errors.New("txpool: gas limit exceeds the block gas limit")
	ErrUnderpriced        = errors.New("txpool: fee cap is below the pool minimum")
	ErrPoolFull           = errors.New("txpool: pool is full and this transaction is not competitive")
	ErrNegativeValue      = errors.New("txpool: value is negative")
	ErrOversizedData      = errors.New("txpool: transaction is too large")
	ErrReplaceUnderpriced = errors.New("txpool: replacement fee is not high enough")
	ErrInvalidSender      = errors.New("txpool: cannot recover the sender")
	ErrSenderNotEOA       = errors.New("txpool: sender has contract code")
)

// Config tunes pool capacity and admission.
type Config struct {
	// GlobalSlots caps the number of executable transactions held.
	GlobalSlots int
	// GlobalQueue caps the number of future-nonce transactions held.
	GlobalQueue int
	// AccountSlots caps how many pending transactions one account may have.
	AccountSlots int
	// PriceLimit is the minimum fee cap the pool will accept.
	PriceLimit *big.Int
	// PriceBump is the percentage a replacement must exceed the original by.
	PriceBump uint64
	// MaxTxSize caps a single transaction's encoded size.
	MaxTxSize uint64
}

// DefaultConfig returns sensible pool limits.
func DefaultConfig() *Config {
	return &Config{
		GlobalSlots:  4096,
		GlobalQueue:  1024,
		AccountSlots: 64,
		PriceLimit:   big.NewInt(1),
		PriceBump:    10,
		MaxTxSize:    128 * 1024,
	}
}

// StateReader gives the pool the account state it validates against.
type StateReader interface {
	CurrentState() (*state.StateDB, error)
	CurrentGasLimit() uint64
	CurrentBaseFee() *big.Int
}

// TxPool holds pending and queued transactions.
//
// A transaction is *pending* when its nonce follows on from the account's
// current nonce, and *queued* when it leaves a gap. Queued transactions are
// promoted as the gaps fill in.
type TxPool struct {
	mu sync.RWMutex

	config *Config
	signer *core.Signer
	chain  StateReader

	pending map[common.Address]*accountList
	queue   map[common.Address]*accountList
	all     map[common.Hash]*core.Transaction

	// nonces tracks the next nonce each sender may use, including pool
	// contents, so consecutive transactions can be submitted without waiting.
	nonces map[common.Address]uint64

	subMu       sync.Mutex
	subscribers []chan<- []*core.Transaction
}

// accountList holds one sender's transactions ordered by nonce.
type accountList struct {
	txs map[uint64]*core.Transaction
}

func newAccountList() *accountList {
	return &accountList{txs: make(map[uint64]*core.Transaction)}
}

func (l *accountList) add(tx *core.Transaction) { l.txs[tx.Nonce()] = tx }

func (l *accountList) get(nonce uint64) *core.Transaction { return l.txs[nonce] }

func (l *accountList) remove(nonce uint64) { delete(l.txs, nonce) }

func (l *accountList) len() int { return len(l.txs) }

// sorted returns the transactions in nonce order.
func (l *accountList) sorted() core.Transactions {
	out := make(core.Transactions, 0, len(l.txs))
	for _, tx := range l.txs {
		out = append(out, tx)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nonce() < out[j].Nonce() })
	return out
}

// New creates a transaction pool.
func New(config *Config, chainID *big.Int, chain StateReader) *TxPool {
	if config == nil {
		config = DefaultConfig()
	}
	return &TxPool{
		config:  config,
		signer:  core.NewSigner(chainID),
		chain:   chain,
		pending: make(map[common.Address]*accountList),
		queue:   make(map[common.Address]*accountList),
		all:     make(map[common.Hash]*core.Transaction),
		nonces:  make(map[common.Address]uint64),
	}
}

// Signer returns the pool's transaction signer.
func (p *TxPool) Signer() *core.Signer { return p.signer }

// Subscribe registers a channel that receives newly accepted transactions.
func (p *TxPool) Subscribe(ch chan<- []*core.Transaction) {
	p.subMu.Lock()
	defer p.subMu.Unlock()
	p.subscribers = append(p.subscribers, ch)
}

func (p *TxPool) publish(txs []*core.Transaction) {
	p.subMu.Lock()
	defer p.subMu.Unlock()
	for _, ch := range p.subscribers {
		select {
		case ch <- txs:
		default:
			// Never let a slow subscriber block admission.
		}
	}
}

// Add validates a transaction and stores it.
func (p *TxPool) Add(tx *core.Transaction) error {
	p.mu.Lock()
	if err := p.addLocked(tx); err != nil {
		p.mu.Unlock()
		return err
	}
	p.mu.Unlock()

	p.publish([]*core.Transaction{tx})
	return nil
}

// AddBatch adds several transactions, returning one error per input.
func (p *TxPool) AddBatch(txs []*core.Transaction) []error {
	errs := make([]error, len(txs))
	var accepted []*core.Transaction

	p.mu.Lock()
	for i, tx := range txs {
		errs[i] = p.addLocked(tx)
		if errs[i] == nil {
			accepted = append(accepted, tx)
		}
	}
	p.mu.Unlock()

	if len(accepted) > 0 {
		p.publish(accepted)
	}
	return errs
}

func (p *TxPool) addLocked(tx *core.Transaction) error {
	hash := tx.Hash()
	if _, ok := p.all[hash]; ok {
		return ErrAlreadyKnown
	}

	from, err := p.validate(tx)
	if err != nil {
		return err
	}

	// A transaction that reuses a pooled nonce is a replacement, wherever the
	// original currently sits. Routing it as a new arrival would leave both
	// copies in the pool.
	if list := p.listHolding(from, tx.Nonce()); list != nil {
		existing := list.get(tx.Nonce())
		if !p.priceBumpSatisfied(existing, tx) {
			return fmt.Errorf("%w: need %d%% above fee cap %s and tip %s",
				ErrReplaceUnderpriced, p.config.PriceBump, existing.GasFeeCap(), existing.GasTipCap())
		}
		delete(p.all, existing.Hash())
		list.add(tx)
		p.all[hash] = tx
		return nil
	}

	statedb, err := p.chain.CurrentState()
	if err != nil {
		return err
	}
	currentNonce := statedb.GetNonce(from)

	// A transaction that continues the account's sequence is immediately
	// executable; one that leaves a gap has to wait.
	if tx.Nonce() == p.nextNonce(from, currentNonce) {
		if err := p.insert(p.pending, from, tx); err != nil {
			return err
		}
		p.nonces[from] = tx.Nonce() + 1
		p.all[hash] = tx
		p.promote(from, statedb)
		return nil
	}

	if tx.Nonce() < currentNonce {
		return fmt.Errorf("%w: nonce %d, account is at %d", ErrNonceTooLow, tx.Nonce(), currentNonce)
	}
	if p.queueLen() >= p.config.GlobalQueue {
		return ErrPoolFull
	}
	if err := p.insert(p.queue, from, tx); err != nil {
		return err
	}
	p.all[hash] = tx
	return nil
}

// nextNonce returns the nonce the pool expects next from an account.
func (p *TxPool) nextNonce(addr common.Address, stateNonce uint64) uint64 {
	if pooled, ok := p.nonces[addr]; ok && pooled > stateNonce {
		return pooled
	}
	return stateNonce
}

// listHolding returns the list containing a sender's transaction at the given
// nonce, or nil if there is none.
func (p *TxPool) listHolding(from common.Address, nonce uint64) *accountList {
	if list, ok := p.pending[from]; ok && list.get(nonce) != nil {
		return list
	}
	if list, ok := p.queue[from]; ok && list.get(nonce) != nil {
		return list
	}
	return nil
}

// insert adds a transaction to a list, handling same-nonce replacement.
func (p *TxPool) insert(lists map[common.Address]*accountList, from common.Address, tx *core.Transaction) error {
	list, ok := lists[from]
	if !ok {
		list = newAccountList()
		lists[from] = list
	}

	if existing := list.get(tx.Nonce()); existing != nil {
		// Replacing a transaction requires a meaningfully higher fee, so the
		// pool cannot be churned for free.
		if !p.priceBumpSatisfied(existing, tx) {
			return fmt.Errorf("%w: need %d%% above %s", ErrReplaceUnderpriced, p.config.PriceBump, existing.GasFeeCap())
		}
		delete(p.all, existing.Hash())
	} else if list.len() >= p.config.AccountSlots {
		return fmt.Errorf("%w: account already has %d transactions", ErrPoolFull, list.len())
	}

	list.add(tx)
	return nil
}

// priceBumpSatisfied reports whether replacement outbids current by the
// configured margin on both the fee cap and the tip.
func (p *TxPool) priceBumpSatisfied(current, replacement *core.Transaction) bool {
	bump := big.NewInt(int64(100 + p.config.PriceBump))

	feeThreshold := new(big.Int).Mul(current.GasFeeCap(), bump)
	feeThreshold.Div(feeThreshold, big.NewInt(100))
	if replacement.GasFeeCap().Cmp(feeThreshold) < 0 {
		return false
	}
	tipThreshold := new(big.Int).Mul(current.GasTipCap(), bump)
	tipThreshold.Div(tipThreshold, big.NewInt(100))
	return replacement.GasTipCap().Cmp(tipThreshold) >= 0
}

// validate applies every admission rule that does not depend on pool contents.
func (p *TxPool) validate(tx *core.Transaction) (common.Address, error) {
	if tx.Size() > p.config.MaxTxSize {
		return common.Address{}, fmt.Errorf("%w: %d bytes", ErrOversizedData, tx.Size())
	}
	if tx.Value().Sign() < 0 {
		return common.Address{}, ErrNegativeValue
	}
	if limit := p.chain.CurrentGasLimit(); tx.Gas() > limit {
		return common.Address{}, fmt.Errorf("%w: %d > %d", ErrGasLimitTooHigh, tx.Gas(), limit)
	}
	if tx.GasFeeCap().Cmp(p.config.PriceLimit) < 0 {
		return common.Address{}, fmt.Errorf("%w: %s < %s", ErrUnderpriced, tx.GasFeeCap(), p.config.PriceLimit)
	}
	if tx.GasFeeCap().Cmp(tx.GasTipCap()) < 0 {
		return common.Address{}, processor.ErrTipAboveFeeCap
	}

	intrinsic, err := processor.IntrinsicGas(tx.Data(), tx.AccessList(), tx.IsContractCreation())
	if err != nil {
		return common.Address{}, err
	}
	if tx.Gas() < intrinsic {
		return common.Address{}, fmt.Errorf("%w: %d < %d", ErrIntrinsicGas, tx.Gas(), intrinsic)
	}
	if tx.IsContractCreation() && len(tx.Data()) > evm.MaxInitCodeSize {
		return common.Address{}, processor.ErrInitCodeTooLarge
	}

	// Sender recovery is the most expensive check, so it comes last.
	from, err := p.signer.Sender(tx)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSender, err)
	}

	statedb, err := p.chain.CurrentState()
	if err != nil {
		return common.Address{}, err
	}
	if codeHash := statedb.GetCodeHash(from); codeHash != (common.Hash{}) && codeHash != common.Hash(common.EmptyCodeHash) {
		return common.Address{}, fmt.Errorf("%w: %s", ErrSenderNotEOA, from)
	}
	if tx.Nonce() < statedb.GetNonce(from) {
		return common.Address{}, fmt.Errorf("%w: nonce %d, account is at %d", ErrNonceTooLow, tx.Nonce(), statedb.GetNonce(from))
	}
	// The sender must be able to cover this transaction on top of everything
	// already queued from the same account.
	needed := new(big.Int).Set(tx.Cost())
	for _, pooled := range p.allFrom(from) {
		if pooled.Hash() != tx.Hash() {
			needed.Add(needed, pooled.Cost())
		}
	}
	if balance := statedb.GetBalance(from); balance.Cmp(needed) < 0 {
		return common.Address{}, fmt.Errorf("%w: has %s, needs %s across %d pooled transactions",
			ErrInsufficientFunds, balance, needed, len(p.allFrom(from))+1)
	}
	return from, nil
}

func (p *TxPool) allFrom(addr common.Address) core.Transactions {
	var out core.Transactions
	if list, ok := p.pending[addr]; ok {
		out = append(out, list.sorted()...)
	}
	if list, ok := p.queue[addr]; ok {
		out = append(out, list.sorted()...)
	}
	return out
}

// promote moves queued transactions into pending as their nonce gaps close.
func (p *TxPool) promote(addr common.Address, statedb *state.StateDB) {
	queued, ok := p.queue[addr]
	if !ok {
		return
	}
	next := p.nextNonce(addr, statedb.GetNonce(addr))
	for {
		tx := queued.get(next)
		if tx == nil {
			break
		}
		queued.remove(next)
		if err := p.insert(p.pending, addr, tx); err != nil {
			delete(p.all, tx.Hash())
			break
		}
		next++
		p.nonces[addr] = next
	}
	if queued.len() == 0 {
		delete(p.queue, addr)
	}
}

// Get returns a pooled transaction by hash.
func (p *TxPool) Get(hash common.Hash) *core.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.all[hash]
}

// Has reports whether a transaction is pooled.
func (p *TxPool) Has(hash common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.all[hash]
	return ok
}

// Nonce returns the next nonce an account should use, accounting for pooled
// transactions.
func (p *TxPool) Nonce(addr common.Address) (uint64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	statedb, err := p.chain.CurrentState()
	if err != nil {
		return 0, err
	}
	return p.nextNonce(addr, statedb.GetNonce(addr)), nil
}

// Stats returns the number of pending and queued transactions.
func (p *TxPool) Stats() (pending int, queued int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, list := range p.pending {
		pending += list.len()
	}
	return pending, p.queueLen()
}

func (p *TxPool) queueLen() int {
	n := 0
	for _, list := range p.queue {
		n += list.len()
	}
	return n
}

// Pending returns the executable transactions grouped by sender.
func (p *TxPool) Pending() map[common.Address]core.Transactions {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[common.Address]core.Transactions, len(p.pending))
	for addr, list := range p.pending {
		if list.len() > 0 {
			out[addr] = list.sorted()
		}
	}
	return out
}

// Ready returns executable transactions ordered for inclusion in a block:
// by fee first, but never breaking an account's nonce sequence.
func (p *TxPool) Ready(limit int) core.Transactions {
	pending := p.Pending()
	baseFee := p.chain.CurrentBaseFee()

	// Take each account's transactions in nonce order, and pick between
	// accounts by the effective tip of their next transaction.
	heads := make([]core.Transactions, 0, len(pending))
	for _, txs := range pending {
		heads = append(heads, txs)
	}

	var out core.Transactions
	for len(heads) > 0 && (limit <= 0 || len(out) < limit) {
		best := 0
		for i := 1; i < len(heads); i++ {
			if heads[i][0].EffectiveTip(baseFee).Cmp(heads[best][0].EffectiveTip(baseFee)) > 0 {
				best = i
			}
		}
		out = append(out, heads[best][0])
		if len(heads[best]) == 1 {
			heads = append(heads[:best], heads[best+1:]...)
		} else {
			heads[best] = heads[best][1:]
		}
	}
	return out
}

// Remove drops a transaction from the pool.
func (p *TxPool) Remove(hash common.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(hash)
}

func (p *TxPool) removeLocked(hash common.Hash) {
	tx, ok := p.all[hash]
	if !ok {
		return
	}
	delete(p.all, hash)

	from, err := p.signer.Sender(tx)
	if err != nil {
		return
	}
	if list, ok := p.pending[from]; ok {
		list.remove(tx.Nonce())
		if list.len() == 0 {
			delete(p.pending, from)
		}
	}
	if list, ok := p.queue[from]; ok {
		list.remove(tx.Nonce())
		if list.len() == 0 {
			delete(p.queue, from)
		}
	}
}

// Reset drops transactions that the new chain head has made invalid: those
// already included, and those whose sender can no longer afford them.
func (p *TxPool) Reset(included core.Transactions) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, tx := range included {
		p.removeLocked(tx.Hash())
	}

	statedb, err := p.chain.CurrentState()
	if err != nil {
		return
	}

	// Re-validate everything left against the new state.
	for _, tx := range p.snapshotAll() {
		from, err := p.signer.Sender(tx)
		if err != nil {
			p.removeLocked(tx.Hash())
			continue
		}
		if tx.Nonce() < statedb.GetNonce(from) || statedb.GetBalance(from).Cmp(tx.Cost()) < 0 {
			p.removeLocked(tx.Hash())
		}
	}

	// Recompute the expected nonces, then close any gaps that opened up.
	p.nonces = make(map[common.Address]uint64)
	for addr, list := range p.pending {
		next := statedb.GetNonce(addr)
		for _, tx := range list.sorted() {
			if tx.Nonce() != next {
				// A gap appeared: everything from here on is no longer
				// executable and moves back to the queue.
				list.remove(tx.Nonce())
				p.insert(p.queue, addr, tx)
				continue
			}
			next++
		}
		p.nonces[addr] = next
	}
	for addr := range p.queue {
		p.promote(addr, statedb)
	}
}

func (p *TxPool) snapshotAll() core.Transactions {
	out := make(core.Transactions, 0, len(p.all))
	for _, tx := range p.all {
		out = append(out, tx)
	}
	return out
}

// Clear empties the pool.
func (p *TxPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = make(map[common.Address]*accountList)
	p.queue = make(map[common.Address]*accountList)
	p.all = make(map[common.Hash]*core.Transaction)
	p.nonces = make(map[common.Address]uint64)
}

// Content returns everything in the pool, for inspection.
func (p *TxPool) Content() (pending, queued map[common.Address]core.Transactions) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pending = make(map[common.Address]core.Transactions, len(p.pending))
	queued = make(map[common.Address]core.Transactions, len(p.queue))
	for addr, list := range p.pending {
		pending[addr] = list.sorted()
	}
	for addr, list := range p.queue {
		queued[addr] = list.sorted()
	}
	return pending, queued
}
