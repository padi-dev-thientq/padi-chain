// Package trie implements the Merkle Patricia Trie: the authenticated,
// deterministic key/value structure that commits to account state, storage,
// transactions and receipts.
//
// Keys are traversed one hex nibble at a time. Three node shapes make up the
// structure:
//
//	leaf       a terminating [encodedPath, value] pair
//	extension  a shared path prefix pointing at one child, [encodedPath, child]
//	branch     a 17-slot fan-out, one per nibble plus a value for a key that
//	           terminates exactly here
//
// A node is referenced by its RLP encoding when that encoding is shorter than
// 32 bytes, and by the Keccak-256 hash of the encoding otherwise. That rule is
// what makes the root hash a commitment to the entire key/value set.
package trie

import (
	"bytes"
	"errors"
	"fmt"

	"padi-chain/common"
	"padi-chain/db"
)

// EmptyRoot is the root hash of a trie with no entries: keccak256(rlp("")).
var EmptyRoot = common.Keccak256([]byte{0x80})

var (
	ErrMissingNode = errors.New("trie: node missing from the database")
	ErrInvalidNode = errors.New("trie: malformed node encoding")
)

// node is one of nilNode, valueNode, hashNode, *shortNode or *fullNode.
type node interface{ cache() ([]byte, bool) }

type (
	// fullNode is a branch: 16 child slots plus a terminating value.
	fullNode struct {
		children [17]node
		flags    nodeFlag
	}
	// shortNode covers both leaves and extensions; the distinction lives in the
	// hex-prefix encoding of its key and in whether the value terminates.
	shortNode struct {
		key   []byte // nibbles, with a terminator nibble (16) for leaves
		value node
		flags nodeFlag
	}
	// hashNode is a reference to a node that still lives in the database.
	hashNode []byte
	// valueNode is a stored value at a terminating position.
	valueNode []byte
)

// nodeFlag caches what is known about a node's identity.
//
// hash is the node's reference once computed; dirty means the cached hash no
// longer matches the node's contents; persisted means the encoding has actually
// been written to the store. Hashing alone does not persist anything, so the
// two flags have to be tracked separately — otherwise Commit would skip
// subtrees that Hash had merely visited.
type nodeFlag struct {
	hash      []byte
	dirty     bool
	persisted bool
}

func (n *fullNode) cache() ([]byte, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() ([]byte, bool) { return n.flags.hash, n.flags.dirty }
func (n hashNode) cache() ([]byte, bool)   { return nil, true }
func (n valueNode) cache() ([]byte, bool)  { return nil, true }

// stored reports whether the node's encoding is already in the store.
func (n *fullNode) stored() bool  { return n.flags.persisted && !n.flags.dirty }
func (n *shortNode) stored() bool { return n.flags.persisted && !n.flags.dirty }

func (n *fullNode) copy() *fullNode   { c := *n; return &c }
func (n *shortNode) copy() *shortNode { c := *n; return &c }

// Trie is a Merkle Patricia Trie backed by a node store.
type Trie struct {
	root     node
	store    db.Database
	unhashed int
}

// New loads the trie rooted at the given hash. An empty or zero root yields an
// empty trie.
func New(root common.Hash, store db.Database) (*Trie, error) {
	t := &Trie{store: store}
	if root == (common.Hash{}) || root == EmptyRoot {
		return t, nil
	}
	if store == nil {
		return nil, errors.New("trie: a non-empty root requires a node store")
	}
	resolved, err := t.resolveHash(root[:])
	if err != nil {
		return nil, err
	}
	t.root = resolved
	return t, nil
}

// NewEmpty returns an empty trie backed by store.
func NewEmpty(store db.Database) *Trie { return &Trie{store: store} }

// Get returns the value stored at key, or nil if the key is absent.
func (t *Trie) Get(key []byte) ([]byte, error) {
	value, newRoot, didResolve, err := t.get(t.root, keyToNibbles(key), 0)
	if err != nil {
		return nil, err
	}
	if didResolve {
		// Cache the nodes we pulled out of the database for later lookups.
		t.root = newRoot
	}
	return value, nil
}

func (t *Trie) get(n node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := n.(type) {
	case nil:
		return nil, nil, false, nil

	case valueNode:
		return n, n, false, nil

	case *shortNode:
		if len(key)-pos < len(n.key) || !bytes.Equal(n.key, key[pos:pos+len(n.key)]) {
			return nil, n, false, nil // the key diverges from this node's path
		}
		value, newnode, didResolve, err = t.get(n.value, key, pos+len(n.key))
		if err == nil && didResolve {
			n = n.copy()
			n.value = newnode
		}
		return value, n, didResolve, err

	case *fullNode:
		value, newnode, didResolve, err = t.get(n.children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.children[key[pos]] = newnode
		}
		return value, n, didResolve, err

	case hashNode:
		child, err := t.resolveHash(n)
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err

	default:
		return nil, nil, false, fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
	}
}

// Update inserts or replaces the value at key. Storing an empty value deletes
// the key, matching the state trie's convention that absent and empty are the
// same thing.
func (t *Trie) Update(key, value []byte) error {
	t.unhashed++
	k := keyToNibbles(key)
	if len(value) == 0 {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
		return nil
	}
	_, n, err := t.insert(t.root, nil, k, valueNode(common.CopyBytes(value)))
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// Delete removes key from the trie.
func (t *Trie) Delete(key []byte) error {
	t.unhashed++
	_, n, err := t.delete(t.root, nil, keyToNibbles(key))
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}

	switch n := n.(type) {
	case *shortNode:
		match := commonPrefixLen(key, n.key)
		if match == len(n.key) {
			// The whole path matches: recurse into the child.
			dirty, nn, err := t.insert(n.value, append(prefix, key[:match]...), key[match:], value)
			if err != nil || !dirty {
				return false, n, err
			}
			return true, &shortNode{key: n.key, value: nn, flags: t.newFlag()}, nil
		}
		// The paths diverge; a branch has to take over at the split point.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.children[n.key[match]], err = t.insert(nil, append(prefix, n.key[:match+1]...), n.key[match+1:], n.value)
		if err != nil {
			return false, nil, err
		}
		_, branch.children[key[match]], err = t.insert(nil, append(prefix, key[:match+1]...), key[match+1:], value)
		if err != nil {
			return false, nil, err
		}
		if match == 0 {
			return true, branch, nil
		}
		// Keep the shared prefix as an extension in front of the branch.
		return true, &shortNode{key: key[:match], value: branch, flags: t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.children[key[0]], append(prefix, key[0]), key[1:], value)
		if err != nil || !dirty {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.children[key[0]] = nn
		return true, n, nil

	case nil:
		return true, &shortNode{key: key, value: value, flags: t.newFlag()}, nil

	case hashNode:
		resolved, err := t.resolveHash(n)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(resolved, prefix, key, value)
		if err != nil || !dirty {
			return false, resolved, err
		}
		return true, nn, nil

	default:
		return false, nil, fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
	}
}

func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		match := commonPrefixLen(key, n.key)
		if match < len(n.key) {
			return false, n, nil // key not present
		}
		if match == len(key) {
			return true, nil, nil // this node held the key
		}
		// Delete from the subtree; the child keeps at least one nibble of path.
		dirty, child, err := t.delete(n.value, append(prefix, key[:len(n.key)]...), key[len(n.key):])
		if err != nil || !dirty {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// Two chained short nodes collapse into one.
			return true, &shortNode{key: concat(n.key, child.key...), value: child.value, flags: t.newFlag()}, nil
		default:
			return true, &shortNode{key: n.key, value: child, flags: t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.children[key[0]], append(prefix, key[0]), key[1:])
		if err != nil || !dirty {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.children[key[0]] = nn

		// A branch with a single remaining entry degenerates into a short node.
		pos := -1
		for i, child := range &n.children {
			if child != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2 // more than one child: the branch stays
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// Pull up the surviving child, prefixing its path with this nibble.
				cnode, err := t.resolve(n.children[pos], prefix)
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					return true, &shortNode{key: concat([]byte{byte(pos)}, cnode.key...), value: cnode.value, flags: t.newFlag()}, nil
				}
				return true, &shortNode{key: []byte{byte(pos)}, value: n.children[pos], flags: t.newFlag()}, nil
			}
			// Only the terminating value is left.
			return true, &shortNode{key: []byte{16}, value: n.children[16], flags: t.newFlag()}, nil
		}
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		resolved, err := t.resolveHash(n)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(resolved, prefix, key)
		if err != nil || !dirty {
			return false, resolved, err
		}
		return true, nn, nil

	default:
		return false, nil, fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
	}
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if h, ok := n.(hashNode); ok {
		return t.resolveHash(h)
	}
	return n, nil
}

func (t *Trie) resolveHash(h []byte) (node, error) {
	if t.store == nil {
		return nil, fmt.Errorf("%w: %x (no store attached)", ErrMissingNode, h)
	}
	enc, err := t.store.Get(nodeKey(h))
	if err != nil {
		return nil, fmt.Errorf("%w: %x", ErrMissingNode, h)
	}
	return decodeNode(h, enc)
}

func (t *Trie) newFlag() nodeFlag { return nodeFlag{dirty: true} }

// Hash returns the root hash without writing anything to the database.
func (t *Trie) Hash() common.Hash {
	if t.root == nil {
		return EmptyRoot
	}
	hashed, cached := t.hashNode(t.root, nil)
	t.root = cached
	if h, ok := hashed.(hashNode); ok {
		return common.BytesToHash(h)
	}
	// A root whose encoding is under 32 bytes is still committed to by its hash.
	return common.Keccak256(encodeNode(hashed))
}

// Commit writes every dirty node to the batch and returns the new root hash.
// The caller is responsible for calling Write on the batch.
func (t *Trie) Commit(batch db.Batch) (common.Hash, error) {
	if t.root == nil {
		return EmptyRoot, nil
	}
	hashed, cached, err := t.commitNode(t.root, batch)
	if err != nil {
		return common.Hash{}, err
	}
	t.root = cached
	t.unhashed = 0
	if h, ok := hashed.(hashNode); ok {
		return common.BytesToHash(h), nil
	}
	// Small roots are not referenced by hash anywhere, so store them explicitly
	// to keep the trie loadable from its root hash alone.
	enc := encodeNode(hashed)
	root := common.Keccak256(enc)
	if err := batch.Put(nodeKey(root[:]), enc); err != nil {
		return common.Hash{}, err
	}
	return root, nil
}

// Root is Commit against a batch that is written immediately.
func (t *Trie) CommitTo(store db.Database) (common.Hash, error) {
	batch := store.NewBatch()
	root, err := t.Commit(batch)
	if err != nil {
		return common.Hash{}, err
	}
	if err := batch.Write(); err != nil {
		return common.Hash{}, err
	}
	return root, nil
}

// Copy returns an independent trie sharing the same backing store. Cached nodes
// are shared, which is safe because nodes are treated as immutable once hashed.
func (t *Trie) Copy() *Trie {
	return &Trie{root: t.root, store: t.store, unhashed: t.unhashed}
}

// ForEach walks every key/value pair in the trie in key order.
func (t *Trie) ForEach(fn func(key, value []byte) bool) error {
	_, err := t.forEach(t.root, nil, fn)
	return err
}

func (t *Trie) forEach(n node, path []byte, fn func(key, value []byte) bool) (bool, error) {
	switch n := n.(type) {
	case nil:
		return true, nil
	case valueNode:
		return fn(nibblesToKey(path), n), nil
	case *shortNode:
		return t.forEach(n.value, append(append([]byte{}, path...), n.key...), fn)
	case *fullNode:
		for i, child := range &n.children {
			if child == nil {
				continue
			}
			next := path
			if i < 16 {
				next = append(append([]byte{}, path...), byte(i))
			} else {
				next = append(append([]byte{}, path...), 16)
			}
			cont, err := t.forEach(child, next, fn)
			if err != nil || !cont {
				return cont, err
			}
		}
		return true, nil
	case hashNode:
		resolved, err := t.resolveHash(n)
		if err != nil {
			return false, err
		}
		return t.forEach(resolved, path, fn)
	default:
		return false, fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
	}
}

// nodeKey namespaces trie nodes within the shared store.
func nodeKey(hash []byte) []byte { return append([]byte("n"), hash...) }

func concat(a []byte, b ...byte) []byte {
	out := make([]byte, len(a)+len(b))
	copy(out, a)
	copy(out[len(a):], b)
	return out
}

func commonPrefixLen(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// keyToNibbles expands a byte key into nibbles and appends the terminator that
// marks a value-bearing path.
func keyToNibbles(key []byte) []byte {
	out := make([]byte, len(key)*2+1)
	for i, b := range key {
		out[i*2] = b >> 4
		out[i*2+1] = b & 0x0f
	}
	out[len(out)-1] = 16
	return out
}

// nibblesToKey is the inverse of keyToNibbles, dropping the terminator.
func nibblesToKey(nibbles []byte) []byte {
	if len(nibbles) > 0 && nibbles[len(nibbles)-1] == 16 {
		nibbles = nibbles[:len(nibbles)-1]
	}
	out := make([]byte, len(nibbles)/2)
	for i := 0; i < len(out); i++ {
		out[i] = nibbles[i*2]<<4 | nibbles[i*2+1]
	}
	return out
}

// hexPrefixEncode packs a nibble path into bytes with the flag nibble that
// records whether the path terminates and whether its length is odd.
func hexPrefixEncode(nibbles []byte) []byte {
	terminator := byte(0)
	if len(nibbles) > 0 && nibbles[len(nibbles)-1] == 16 {
		terminator = 1
		nibbles = nibbles[:len(nibbles)-1]
	}
	odd := byte(len(nibbles) % 2)
	flags := 2*terminator + odd

	var buf []byte
	if odd == 1 {
		buf = append(buf, flags<<4|nibbles[0])
		nibbles = nibbles[1:]
	} else {
		buf = append(buf, flags<<4)
	}
	for i := 0; i < len(nibbles); i += 2 {
		buf = append(buf, nibbles[i]<<4|nibbles[i+1])
	}
	return buf
}

// hexPrefixDecode unpacks the encoding produced by hexPrefixEncode.
func hexPrefixDecode(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty hex-prefix path", ErrInvalidNode)
	}
	flags := b[0] >> 4
	if flags > 3 {
		return nil, fmt.Errorf("%w: invalid hex-prefix flags %d", ErrInvalidNode, flags)
	}
	terminated := flags&2 != 0
	odd := flags&1 != 0

	var nibbles []byte
	if odd {
		nibbles = append(nibbles, b[0]&0x0f)
	}
	for _, c := range b[1:] {
		nibbles = append(nibbles, c>>4, c&0x0f)
	}
	if terminated {
		nibbles = append(nibbles, 16)
	}
	return nibbles, nil
}

// VisitNodes walks every node of the trie, reporting each stored node's hash
// and each key/value pair.
//
// This is what a pruner needs: the set of node hashes reachable from a root is
// exactly the set that must survive, and the leaf values are how the walk
// crosses into storage tries and contract code.
func (t *Trie) VisitNodes(onNode func(hash common.Hash) error, onLeaf func(key, value []byte) error) error {
	return t.visit(t.root, nil, onNode, onLeaf)
}

func (t *Trie) visit(n node, path []byte, onNode func(common.Hash) error, onLeaf func(key, value []byte) error) error {
	switch n := n.(type) {
	case nil:
		return nil

	case valueNode:
		if onLeaf == nil {
			return nil
		}
		return onLeaf(nibblesToKey(path), n)

	case *shortNode:
		// A node with a cached hash is one that was stored under it.
		if n.flags.hash != nil && onNode != nil {
			if err := onNode(common.BytesToHash(n.flags.hash)); err != nil {
				return err
			}
		}
		return t.visit(n.value, append(append([]byte{}, path...), n.key...), onNode, onLeaf)

	case *fullNode:
		if n.flags.hash != nil && onNode != nil {
			if err := onNode(common.BytesToHash(n.flags.hash)); err != nil {
				return err
			}
		}
		for i, child := range &n.children {
			if child == nil {
				continue
			}
			next := append(append([]byte{}, path...), byte(i))
			if err := t.visit(child, next, onNode, onLeaf); err != nil {
				return err
			}
		}
		return nil

	case hashNode:
		// The node lives in the store; resolving it is what makes it visible
		// to the walk.
		if onNode != nil {
			if err := onNode(common.BytesToHash(n)); err != nil {
				return err
			}
		}
		resolved, err := t.resolveHash(n)
		if err != nil {
			return err
		}
		return t.visit(resolved, path, onNode, onLeaf)

	default:
		return fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
	}
}

// NodeKey returns the store key a trie node is written under. The pruner needs
// it to sweep, and a sync protocol needs it to serve nodes by hash.
func NodeKey(hash common.Hash) []byte { return nodeKey(hash[:]) }

// NodeKeyPrefix is the namespace trie nodes occupy in the store.
var NodeKeyPrefix = []byte("n")
