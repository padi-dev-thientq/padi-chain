package trie

import (
	"bytes"
	"errors"
	"fmt"

	"padi-chain/common"
	"padi-chain/db"
	"padi-chain/rlp"
)

var (
	// ErrProofInvalid means the supplied nodes do not chain from the root.
	ErrProofInvalid = errors.New("trie: proof does not chain to the root")
	// ErrProofMissing means the proof lacks a node needed to continue.
	ErrProofMissing = errors.New("trie: proof is missing a node")
)

// Prove collects the nodes along the path to key, from the root down. The
// result proves either that key maps to a value, or that it is absent.
func (t *Trie) Prove(key []byte) ([][]byte, error) {
	// Hashing first ensures every node on the path has a stable encoding.
	t.Hash()

	var (
		nibbles = keyToNibbles(key)
		proof   [][]byte
		n       = t.root
	)
	for n != nil {
		switch cur := n.(type) {
		case *shortNode:
			collapsed := cur.copy()
			if _, ok := cur.value.(valueNode); !ok {
				ref, _ := t.hashNode(cur.value, nil)
				collapsed.value = ref
			}
			proof = append(proof, encodeNode(collapsed))
			if len(nibbles) < len(cur.key) || !bytes.Equal(cur.key, nibbles[:len(cur.key)]) {
				return proof, nil // divergence: this is an exclusion proof
			}
			nibbles = nibbles[len(cur.key):]
			n = cur.value

		case *fullNode:
			collapsed := cur.copy()
			for i := 0; i < 16; i++ {
				if cur.children[i] != nil {
					ref, _ := t.hashNode(cur.children[i], nil)
					collapsed.children[i] = ref
				}
			}
			proof = append(proof, encodeNode(collapsed))
			if len(nibbles) == 0 {
				return proof, nil
			}
			n = cur.children[nibbles[0]]
			nibbles = nibbles[1:]

		case hashNode:
			resolved, err := t.resolveHash(cur)
			if err != nil {
				return nil, err
			}
			n = resolved

		case valueNode:
			return proof, nil

		default:
			return nil, fmt.Errorf("%w: unexpected node %T", ErrInvalidNode, n)
		}
	}
	return proof, nil
}

// VerifyProof checks a proof against a root hash and returns the proven value.
// A nil value with a nil error is a valid proof of absence.
func VerifyProof(root common.Hash, key []byte, proof [][]byte) ([]byte, error) {
	// Index the proof by node hash so hash references can be followed. Nodes
	// small enough to be inlined are not in this map; they are reached through
	// their parent's encoding instead.
	nodes := make(map[common.Hash][]byte, len(proof))
	for _, enc := range proof {
		nodes[common.Keccak256(enc)] = enc
	}

	load := func(h common.Hash) (node, error) {
		enc, ok := nodes[h]
		if !ok {
			return nil, fmt.Errorf("%w: %x", ErrProofMissing, h)
		}
		return decodeNode(h[:], enc)
	}

	cur, err := load(root)
	if err != nil {
		return nil, err
	}
	nibbles := keyToNibbles(key)

	for {
		switch n := cur.(type) {
		case *shortNode:
			if len(nibbles) < len(n.key) || !bytes.Equal(n.key, nibbles[:len(n.key)]) {
				return nil, nil // the path diverges: proven absent
			}
			nibbles = nibbles[len(n.key):]
			cur = n.value

		case *fullNode:
			if len(nibbles) == 0 {
				return nil, nil
			}
			idx := nibbles[0]
			nibbles = nibbles[1:]
			cur = n.children[idx]
			if cur == nil {
				return nil, nil // no child on this branch: proven absent
			}

		case valueNode:
			if len(nibbles) != 0 {
				return nil, nil
			}
			return n, nil

		case hashNode:
			next, err := load(common.BytesToHash(n))
			if err != nil {
				return nil, err
			}
			cur = next

		case nil:
			return nil, nil

		default:
			return nil, fmt.Errorf("%w: unexpected node %T in proof", ErrProofInvalid, cur)
		}
	}
}

// ProofDB collects proof nodes into a store, which lets a verifier load a
// partial trie and walk it with the normal machinery.
type ProofDB struct{ *db.MemoryDB }

func NewProofDB(proof [][]byte) *ProofDB {
	store := db.NewMemoryDB()
	for _, enc := range proof {
		h := common.Keccak256(enc)
		store.Put(nodeKey(h[:]), enc)
	}
	return &ProofDB{store}
}

// DeriveRoot builds a throwaway trie keyed by the RLP-encoded index of each
// item and returns its root. This is how transaction and receipt roots in a
// block header are defined.
func DeriveRoot(items [][]byte) common.Hash {
	t := NewEmpty(db.NewMemoryDB())
	for i, item := range items {
		key, err := rlp.Encode(uint64(i))
		if err != nil {
			panic(fmt.Sprintf("trie: encoding index %d: %v", i, err))
		}
		if err := t.Update(key, item); err != nil {
			panic(fmt.Sprintf("trie: building derived root: %v", err))
		}
	}
	return t.Hash()
}
