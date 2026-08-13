package state

import (
	"fmt"
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/db"
)

func newTestState(t *testing.T) (*StateDB, db.Database) {
	t.Helper()
	store := db.NewMemoryDB()
	s, err := New(common.Hash{}, store)
	if err != nil {
		t.Fatal(err)
	}
	return s, store
}

var addrA = common.MustHexToAddress("0x1111111111111111111111111111111111111111")
var addrB = common.MustHexToAddress("0x2222222222222222222222222222222222222222")

func TestBalanceArithmetic(t *testing.T) {
	s, _ := newTestState(t)
	if s.GetBalance(addrA).Sign() != 0 {
		t.Fatal("a missing account must have a zero balance")
	}
	s.AddBalance(addrA, big.NewInt(100))
	s.AddBalance(addrA, big.NewInt(50))
	s.SubBalance(addrA, big.NewInt(30))
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(120)) != 0 {
		t.Fatalf("balance = %s, want 120", got)
	}
	s.SetBalance(addrA, big.NewInt(7))
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("balance after SetBalance = %s", got)
	}
}

func TestNonceAndCode(t *testing.T) {
	s, _ := newTestState(t)
	if s.GetNonce(addrA) != 0 {
		t.Fatal("missing account nonce must be zero")
	}
	s.SetNonce(addrA, 5)
	if s.GetNonce(addrA) != 5 {
		t.Fatalf("nonce = %d", s.GetNonce(addrA))
	}

	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
	s.SetCode(addrA, code)
	if got := s.GetCode(addrA); string(got) != string(code) {
		t.Fatalf("code = %x", got)
	}
	if s.GetCodeSize(addrA) != len(code) {
		t.Fatalf("code size = %d", s.GetCodeSize(addrA))
	}
	if s.GetCodeHash(addrA) != common.Keccak256(code) {
		t.Fatal("code hash does not match the installed code")
	}
	// An account with no code reports the hash of the empty string.
	s.AddBalance(addrB, big.NewInt(1))
	if s.GetCodeHash(addrB) != common.Hash(common.EmptyCodeHash) {
		t.Fatal("an account with no code must have the empty code hash")
	}
}

func TestStorageReadWrite(t *testing.T) {
	s, _ := newTestState(t)
	key := common.BytesToHash([]byte{1})
	value := common.BytesToHash([]byte{42})

	if s.GetState(addrA, key) != (common.Hash{}) {
		t.Fatal("unset storage must read as zero")
	}
	s.SetState(addrA, key, value)
	if s.GetState(addrA, key) != value {
		t.Fatal("storage write is not visible to a later read")
	}
	// The committed view still shows the pre-transaction value.
	if s.GetCommittedState(addrA, key) != (common.Hash{}) {
		t.Fatal("GetCommittedState must ignore pending writes")
	}
}

func TestSnapshotAndRevert(t *testing.T) {
	s, _ := newTestState(t)
	s.AddBalance(addrA, big.NewInt(100))
	s.SetNonce(addrA, 1)
	s.SetState(addrA, common.Hash{1}, common.Hash{9})

	snap := s.Snapshot()

	s.AddBalance(addrA, big.NewInt(500))
	s.SetNonce(addrA, 2)
	s.SetState(addrA, common.Hash{1}, common.Hash{8})
	s.SetState(addrA, common.Hash{2}, common.Hash{7})
	s.SetCode(addrA, []byte{0x01})
	s.AddBalance(addrB, big.NewInt(1))

	s.RevertToSnapshot(snap)

	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("balance after revert = %s, want 100", got)
	}
	if s.GetNonce(addrA) != 1 {
		t.Errorf("nonce after revert = %d, want 1", s.GetNonce(addrA))
	}
	if s.GetState(addrA, common.Hash{1}) != (common.Hash{9}) {
		t.Error("storage write after the snapshot was not rolled back")
	}
	if s.GetState(addrA, common.Hash{2}) != (common.Hash{}) {
		t.Error("a slot first written after the snapshot must revert to zero")
	}
	if len(s.GetCode(addrA)) != 0 {
		t.Error("code installed after the snapshot was not rolled back")
	}
	if s.GetBalance(addrB).Sign() != 0 {
		t.Error("an account created after the snapshot must be gone")
	}
}

func TestNestedSnapshots(t *testing.T) {
	s, _ := newTestState(t)
	s.AddBalance(addrA, big.NewInt(1))

	outer := s.Snapshot()
	s.AddBalance(addrA, big.NewInt(10))
	inner := s.Snapshot()
	s.AddBalance(addrA, big.NewInt(100))

	s.RevertToSnapshot(inner)
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(11)) != 0 {
		t.Fatalf("after reverting the inner snapshot: %s, want 11", got)
	}
	s.RevertToSnapshot(outer)
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("after reverting the outer snapshot: %s, want 1", got)
	}
}

func TestRevertRefundAndLogs(t *testing.T) {
	s, _ := newTestState(t)
	s.SetTxContext(common.Hash{1}, 0)
	s.AddRefund(100)
	snap := s.Snapshot()
	s.AddRefund(50)
	s.AddLog(&core.Log{Address: addrA})
	if s.GetRefund() != 150 || len(s.Logs()) != 1 {
		t.Fatal("refund or log was not recorded")
	}
	s.RevertToSnapshot(snap)
	if s.GetRefund() != 100 {
		t.Errorf("refund after revert = %d, want 100", s.GetRefund())
	}
	if len(s.Logs()) != 0 {
		t.Errorf("logs after revert = %d, want 0", len(s.Logs()))
	}
}

func TestCommitAndReload(t *testing.T) {
	s, store := newTestState(t)
	code := []byte{0x60, 0x2a, 0x60, 0x00, 0x55}

	s.AddBalance(addrA, big.NewInt(1000))
	s.SetNonce(addrA, 3)
	s.SetCode(addrA, code)
	s.SetState(addrA, common.Hash{1}, common.BytesToHash([]byte{0xaa}))
	s.SetState(addrA, common.Hash{2}, common.BytesToHash([]byte{0xbb}))
	s.AddBalance(addrB, big.NewInt(5))

	root, err := s.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if root == (common.Hash{}) {
		t.Fatal("commit produced a zero root")
	}

	reloaded, err := New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.GetBalance(addrA); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("balance after reload = %s", got)
	}
	if reloaded.GetNonce(addrA) != 3 {
		t.Errorf("nonce after reload = %d", reloaded.GetNonce(addrA))
	}
	if got := reloaded.GetCode(addrA); string(got) != string(code) {
		t.Errorf("code after reload = %x", got)
	}
	if got := reloaded.GetState(addrA, common.Hash{1}); got != common.BytesToHash([]byte{0xaa}) {
		t.Errorf("storage slot 1 after reload = %s", got)
	}
	if got := reloaded.GetState(addrA, common.Hash{2}); got != common.BytesToHash([]byte{0xbb}) {
		t.Errorf("storage slot 2 after reload = %s", got)
	}
	if got := reloaded.GetBalance(addrB); got.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("second account balance after reload = %s", got)
	}
}

func TestStateRootIsDeterministic(t *testing.T) {
	build := func() common.Hash {
		s, _ := newTestState(t)
		for i := 0; i < 20; i++ {
			addr := common.BytesToAddress([]byte{byte(i)})
			s.AddBalance(addr, big.NewInt(int64(i*100)))
			s.SetNonce(addr, uint64(i))
			s.SetState(addr, common.BytesToHash([]byte{byte(i)}), common.BytesToHash([]byte{byte(i * 2)}))
		}
		root, err := s.Commit(true)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	if a, b := build(), build(); a != b {
		t.Fatalf("the same state produced different roots: %s vs %s", a, b)
	}
}

func TestStorageDeletionChangesRoot(t *testing.T) {
	s, store := newTestState(t)
	s.SetState(addrA, common.Hash{1}, common.BytesToHash([]byte{1}))
	s.AddBalance(addrA, big.NewInt(1))
	withSlot, err := s.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	next, err := New(withSlot, store)
	if err != nil {
		t.Fatal(err)
	}
	// Writing zero deletes the slot, which must be reflected in the root.
	next.SetState(addrA, common.Hash{1}, common.Hash{})
	withoutSlot, err := next.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if withoutSlot == withSlot {
		t.Fatal("clearing a storage slot did not change the state root")
	}

	reloaded, _ := New(withoutSlot, store)
	if reloaded.GetState(addrA, common.Hash{1}) != (common.Hash{}) {
		t.Fatal("the cleared slot still has a value")
	}
}

func TestEmptyAccountDeletion(t *testing.T) {
	s, store := newTestState(t)
	s.AddBalance(addrA, big.NewInt(1))
	root, _ := s.Commit(true)

	next, _ := New(root, store)
	// Draining the account leaves it empty; EIP-161 says it must be removed.
	next.SubBalance(addrA, big.NewInt(1))
	emptied, err := next.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	reloaded, _ := New(emptied, store)
	if reloaded.Exist(addrA) {
		t.Fatal("an emptied account must be deleted from the trie")
	}
}

func TestSelfDestruct(t *testing.T) {
	s, store := newTestState(t)
	s.AddBalance(addrA, big.NewInt(500))
	s.SetCode(addrA, []byte{0x01, 0x02})
	s.SetState(addrA, common.Hash{1}, common.Hash{2})
	root, _ := s.Commit(true)

	next, _ := New(root, store)
	next.SelfDestruct(addrA)
	if !next.HasSelfDestructed(addrA) {
		t.Fatal("HasSelfDestructed = false after SelfDestruct")
	}
	if next.GetBalance(addrA).Sign() != 0 {
		t.Fatal("self-destruct must zero the balance")
	}
	after, err := next.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	reloaded, _ := New(after, store)
	if reloaded.Exist(addrA) {
		t.Fatal("a self-destructed account must be gone from state")
	}
}

func TestSelfDestructRevert(t *testing.T) {
	s, _ := newTestState(t)
	s.AddBalance(addrA, big.NewInt(100))
	snap := s.Snapshot()
	s.SelfDestruct(addrA)
	s.RevertToSnapshot(snap)

	if s.HasSelfDestructed(addrA) {
		t.Error("self-destruct was not rolled back")
	}
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("balance after reverting self-destruct = %s, want 100", got)
	}
}

func TestCreateAccountPreservesBalance(t *testing.T) {
	s, _ := newTestState(t)
	// Value can arrive at an address before a contract is deployed there; the
	// deployment must not destroy it.
	s.AddBalance(addrA, big.NewInt(999))
	s.CreateAccount(addrA)
	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(999)) != 0 {
		t.Fatalf("balance after CreateAccount = %s, want 999", got)
	}
	if s.GetNonce(addrA) != 0 || len(s.GetCode(addrA)) != 0 {
		t.Fatal("CreateAccount must reset nonce and code")
	}
}

func TestAccessList(t *testing.T) {
	s, _ := newTestState(t)
	slot := common.Hash{7}

	if s.AddressInAccessList(addrA) {
		t.Fatal("a fresh access list must be empty")
	}
	s.Prepare(addrA, common.Address{9}, &addrB, []common.Address{{1}}, core.AccessList{{
		Address:     common.Address{3},
		StorageKeys: []common.Hash{slot},
	}})

	for _, addr := range []common.Address{addrA, addrB, {1}, {3}, {9}} {
		if !s.AddressInAccessList(addr) {
			t.Errorf("%s should be warm after Prepare", addr.Hex())
		}
	}
	if _, slotPresent := s.SlotInAccessList(common.Address{3}, slot); !slotPresent {
		t.Error("a declared storage slot should be warm")
	}
	if _, slotPresent := s.SlotInAccessList(common.Address{3}, common.Hash{8}); slotPresent {
		t.Error("an undeclared slot must be cold")
	}

	// Access list additions are journaled like any other state change.
	snap := s.Snapshot()
	s.AddSlotToAccessList(addrA, slot)
	if _, present := s.SlotInAccessList(addrA, slot); !present {
		t.Fatal("slot was not warmed")
	}
	s.RevertToSnapshot(snap)
	if _, present := s.SlotInAccessList(addrA, slot); present {
		t.Fatal("warming a slot must be reverted with the snapshot")
	}
}

func TestTransientStorage(t *testing.T) {
	s, _ := newTestState(t)
	key, value := common.Hash{1}, common.Hash{2}

	s.SetTransientState(addrA, key, value)
	if s.GetTransientState(addrA, key) != value {
		t.Fatal("transient write is not readable")
	}
	// It must not reach the trie.
	root, err := s.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if s.GetState(addrA, key) != (common.Hash{}) {
		t.Fatal("transient storage leaked into persistent storage")
	}
	_ = root

	// And it is discarded when the transaction ends.
	if s.GetTransientState(addrA, key) != (common.Hash{}) {
		t.Fatal("transient storage must not survive Finalise")
	}
}

func TestCopyIsIndependent(t *testing.T) {
	s, _ := newTestState(t)
	s.AddBalance(addrA, big.NewInt(100))
	s.SetState(addrA, common.Hash{1}, common.Hash{1})

	copied := s.Copy()
	copied.AddBalance(addrA, big.NewInt(900))
	copied.SetState(addrA, common.Hash{1}, common.Hash{2})
	copied.AddBalance(addrB, big.NewInt(1))

	if got := s.GetBalance(addrA); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("the original balance changed: %s", got)
	}
	if s.GetState(addrA, common.Hash{1}) != (common.Hash{1}) {
		t.Error("the original storage changed")
	}
	if s.Exist(addrB) {
		t.Error("an account created in the copy appeared in the original")
	}
	if got := copied.GetBalance(addrA); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("the copy's balance = %s, want 1000", got)
	}
}

func TestIncrementalCommitsMatchSingleCommit(t *testing.T) {
	// Applying changes across several commits must land on the same root as
	// applying them all at once.
	incremental, store := newTestState(t)
	var root common.Hash
	for i := 0; i < 5; i++ {
		s, err := New(root, store)
		if err != nil {
			t.Fatal(err)
		}
		addr := common.BytesToAddress([]byte{byte(i)})
		s.AddBalance(addr, big.NewInt(int64(i+1)))
		s.SetState(addr, common.Hash{byte(i)}, common.Hash{byte(i + 1)})
		root, err = s.Commit(true)
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = incremental

	oneShot, _ := newTestState(t)
	for i := 0; i < 5; i++ {
		addr := common.BytesToAddress([]byte{byte(i)})
		oneShot.AddBalance(addr, big.NewInt(int64(i+1)))
		oneShot.SetState(addr, common.Hash{byte(i)}, common.Hash{byte(i + 1)})
	}
	want, err := oneShot.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if root != want {
		t.Fatalf("incremental root %s != single-commit root %s", root, want)
	}
}

func TestLargeStateCommit(t *testing.T) {
	s, store := newTestState(t)
	const n = 500
	for i := 0; i < n; i++ {
		addr := common.BytesToAddress([]byte(fmt.Sprintf("account-%d", i)))
		s.AddBalance(addr, big.NewInt(int64(i)+1))
		s.SetNonce(addr, uint64(i))
		for j := 0; j < 3; j++ {
			s.SetState(addr, common.BytesToHash([]byte{byte(j)}), common.BytesToHash([]byte{byte(i), byte(j)}))
		}
	}
	root, err := s.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		addr := common.BytesToAddress([]byte(fmt.Sprintf("account-%d", i)))
		if got := reloaded.GetBalance(addr); got.Cmp(big.NewInt(int64(i)+1)) != 0 {
			t.Fatalf("account %d balance = %s", i, got)
		}
		want := common.BytesToHash([]byte{byte(i), byte(1)})
		if got := reloaded.GetState(addr, common.BytesToHash([]byte{1})); got != want {
			t.Fatalf("account %d storage = %s, want %s", i, got, want)
		}
	}
}
