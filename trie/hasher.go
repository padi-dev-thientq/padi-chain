package trie

import (
	"fmt"

	"layer1/common"
	"layer1/db"
	"layer1/rlp"
)

// encodeNode serializes a node to its RLP form. Children are replaced by their
// hash reference, or inlined when their encoding is shorter than 32 bytes.
func encodeNode(n node) []byte {
	switch n := n.(type) {
	case *shortNode:
		return rlp.EncodeList(
			rlp.EncodeBytes(hexPrefixEncode(n.key)),
			encodeChild(n.value),
		)
	case *fullNode:
		items := make([][]byte, 17)
		for i, child := range &n.children {
			if child == nil {
				items[i] = []byte{rlp.EmptyString}
			} else {
				items[i] = encodeChild(child)
			}
		}
		return rlp.EncodeList(items...)
	case valueNode:
		return rlp.EncodeBytes(n)
	case hashNode:
		return rlp.EncodeBytes(n)
	default:
		panic(fmt.Sprintf("trie: cannot encode node type %T", n))
	}
}

// encodeChild renders a child reference: a hash string for large nodes, the
// node's own encoding spliced in for small ones.
func encodeChild(n node) []byte {
	switch n := n.(type) {
	case valueNode:
		return rlp.EncodeBytes(n)
	case hashNode:
		return rlp.EncodeBytes(n)
	case nil:
		return []byte{rlp.EmptyString}
	default:
		enc := encodeNode(n)
		if len(enc) < 32 {
			return enc // inlined verbatim, not as a byte string
		}
		h := common.Keccak256(enc)
		return rlp.EncodeBytes(h[:])
	}
}

// hashNodeOf returns the reference used for a node from its encoding.
func referenceFor(enc []byte) node {
	if len(enc) < 32 {
		return nil // inlined; the caller keeps the node itself
	}
	h := common.Keccak256(enc)
	return hashNode(h[:])
}

// hashNode computes hashes bottom-up without persisting anything. It returns
// the reference for n and a version of n with its subtree hashes cached.
func (t *Trie) hashNode(n node, path []byte) (node, node) {
	switch n := n.(type) {
	case *shortNode:
		if hash, dirty := n.cache(); hash != nil && !dirty {
			return hashNode(hash), n
		}
		collapsed := n.copy()
		if _, ok := n.value.(valueNode); !ok {
			ref, cached := t.hashNode(n.value, append(path, n.key...))
			collapsed.value = ref
			n = n.copy()
			n.value = cached
		}
		enc := encodeNode(collapsed)
		if ref := referenceFor(enc); ref != nil {
			h := ref.(hashNode)
			n.flags = nodeFlag{hash: h, dirty: false, persisted: n.flags.persisted}
			return h, n
		}
		return collapsed, n

	case *fullNode:
		if hash, dirty := n.cache(); hash != nil && !dirty {
			return hashNode(hash), n
		}
		collapsed := n.copy()
		cachedNode := n.copy()
		for i := 0; i < 16; i++ {
			if n.children[i] == nil {
				continue
			}
			ref, cached := t.hashNode(n.children[i], append(path, byte(i)))
			collapsed.children[i] = ref
			cachedNode.children[i] = cached
		}
		enc := encodeNode(collapsed)
		if ref := referenceFor(enc); ref != nil {
			h := ref.(hashNode)
			cachedNode.flags = nodeFlag{hash: h, dirty: false, persisted: n.flags.persisted}
			return h, cachedNode
		}
		return collapsed, cachedNode

	default:
		// Value and hash nodes are already in reference form.
		return n, n
	}
}

// commitNode is hashNode plus persistence: every node whose encoding is at
// least 32 bytes is written to the batch under its hash.
func (t *Trie) commitNode(n node, batch db.Batch) (node, node, error) {
	switch n := n.(type) {
	case *shortNode:
		if n.stored() && n.flags.hash != nil {
			return hashNode(n.flags.hash), n, nil
		}
		collapsed := n.copy()
		cachedNode := n.copy()
		if _, ok := n.value.(valueNode); !ok {
			ref, cached, err := t.commitNode(n.value, batch)
			if err != nil {
				return nil, nil, err
			}
			collapsed.value = ref
			cachedNode.value = cached
		}
		enc := encodeNode(collapsed)
		if len(enc) >= 32 {
			h := common.Keccak256(enc)
			if err := batch.Put(nodeKey(h[:]), enc); err != nil {
				return nil, nil, err
			}
			cachedNode.flags = nodeFlag{hash: h[:], dirty: false, persisted: true}
			return hashNode(h[:]), cachedNode, nil
		}
		return collapsed, cachedNode, nil

	case *fullNode:
		if n.stored() && n.flags.hash != nil {
			return hashNode(n.flags.hash), n, nil
		}
		collapsed := n.copy()
		cachedNode := n.copy()
		for i := 0; i < 16; i++ {
			if n.children[i] == nil {
				continue
			}
			ref, cached, err := t.commitNode(n.children[i], batch)
			if err != nil {
				return nil, nil, err
			}
			collapsed.children[i] = ref
			cachedNode.children[i] = cached
		}
		enc := encodeNode(collapsed)
		if len(enc) >= 32 {
			h := common.Keccak256(enc)
			if err := batch.Put(nodeKey(h[:]), enc); err != nil {
				return nil, nil, err
			}
			cachedNode.flags = nodeFlag{hash: h[:], dirty: false, persisted: true}
			return hashNode(h[:]), cachedNode, nil
		}
		return collapsed, cachedNode, nil

	default:
		return n, n, nil
	}
}

// decodeNode parses a stored node encoding.
func decodeNode(hash, enc []byte) (node, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("%w: empty encoding", ErrInvalidNode)
	}
	items, err := rlp.Split(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNode, err)
	}
	switch len(items) {
	case 2:
		return decodeShort(hash, items)
	case 17:
		return decodeFull(hash, items)
	default:
		return nil, fmt.Errorf("%w: node has %d items", ErrInvalidNode, len(items))
	}
}

func decodeShort(hash []byte, items [][]byte) (node, error) {
	var pathEnc []byte
	if err := rlp.Decode(items[0], &pathEnc); err != nil {
		return nil, fmt.Errorf("%w: short node path: %v", ErrInvalidNode, err)
	}
	key, err := hexPrefixDecode(pathEnc)
	if err != nil {
		return nil, err
	}
	flags := nodeFlag{hash: hash, persisted: true}
	if len(key) > 0 && key[len(key)-1] == 16 {
		// Leaf: the second item is the value itself.
		var value []byte
		if err := rlp.Decode(items[1], &value); err != nil {
			return nil, fmt.Errorf("%w: leaf value: %v", ErrInvalidNode, err)
		}
		return &shortNode{key: key, value: valueNode(value), flags: flags}, nil
	}
	child, err := decodeRef(items[1])
	if err != nil {
		return nil, err
	}
	return &shortNode{key: key, value: child, flags: flags}, nil
}

func decodeFull(hash []byte, items [][]byte) (node, error) {
	n := &fullNode{flags: nodeFlag{hash: hash, persisted: true}}
	for i := 0; i < 16; i++ {
		child, err := decodeRef(items[i])
		if err != nil {
			return nil, err
		}
		n.children[i] = child
	}
	var value []byte
	if err := rlp.Decode(items[16], &value); err != nil {
		return nil, fmt.Errorf("%w: branch value: %v", ErrInvalidNode, err)
	}
	if len(value) > 0 {
		n.children[16] = valueNode(value)
	}
	return n, nil
}

// decodeRef reads a child reference: an empty string, a 32-byte hash, or an
// inlined node.
func decodeRef(item []byte) (node, error) {
	if len(item) == 0 {
		return nil, nil
	}
	kind, size, err := rlp.NewStream(item).Kind()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNode, err)
	}
	switch kind {
	case rlp.List:
		// An inlined node: it must have been under 32 bytes to be embedded.
		if len(item) >= 32 {
			return nil, fmt.Errorf("%w: oversized inline node (%d bytes)", ErrInvalidNode, len(item))
		}
		return decodeNode(nil, item)
	default:
		var b []byte
		if err := rlp.Decode(item, &b); err != nil {
			return nil, fmt.Errorf("%w: child reference: %v", ErrInvalidNode, err)
		}
		if len(b) == 0 {
			return nil, nil
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%w: hash reference is %d bytes, want 32", ErrInvalidNode, len(b))
		}
		_ = size
		return hashNode(b), nil
	}
}
