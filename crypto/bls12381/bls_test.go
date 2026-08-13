package bls12381

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()
	msg := []byte("padi-chain attests to block 42")

	sig := key.Sign(msg)
	if !Verify(pub, msg, sig) {
		t.Fatal("a valid signature failed verification")
	}
	if Verify(pub, []byte("a different message"), sig) {
		t.Fatal("the signature verified against the wrong message")
	}

	other, _ := GenerateKey()
	if Verify(other.PublicKey(), msg, sig) {
		t.Fatal("the signature verified against an unrelated key")
	}
}

func TestSigningIsDeterministic(t *testing.T) {
	key, _ := GenerateKey()
	msg := []byte("same message")
	// BLS signatures are unique: there is exactly one valid signature per key
	// and message, which is what makes aggregation well defined.
	if !key.Sign(msg).Equal(key.Sign(msg)) {
		t.Fatal("signing the same message twice gave different signatures")
	}
}

func TestAggregationOverOneMessage(t *testing.T) {
	const signers = 12
	msg := []byte("block 100")

	var keys []*PublicKey
	var sigs []*Signature
	for i := 0; i < signers; i++ {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.PublicKey())
		sigs = append(sigs, k.Sign(msg))
	}

	aggregate, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	// One 96-byte signature stands for all twelve.
	if len(aggregate.Bytes()) != SignatureLength {
		t.Fatalf("aggregate is %d bytes", len(aggregate.Bytes()))
	}
	if !FastAggregateVerify(keys, msg, aggregate) {
		t.Fatal("the aggregate signature did not verify")
	}

	// Dropping a signer must invalidate it, or a minority could pass for a
	// quorum.
	if FastAggregateVerify(keys[:signers-1], msg, aggregate) {
		t.Fatal("the aggregate verified against a subset of the signers")
	}
	// As must adding a key that did not sign.
	extra, _ := GenerateKey()
	if FastAggregateVerify(append(keys, extra.PublicKey()), msg, aggregate) {
		t.Fatal("the aggregate verified with an extra key")
	}
}

func TestAggregationIsOrderIndependent(t *testing.T) {
	msg := []byte("order should not matter")
	var keys []*PublicKey
	var sigs []*Signature
	for i := 0; i < 5; i++ {
		k, _ := GenerateKey()
		keys = append(keys, k.PublicKey())
		sigs = append(sigs, k.Sign(msg))
	}

	forward, _ := AggregateSignatures(sigs)
	reversed := make([]*Signature, len(sigs))
	for i := range sigs {
		reversed[i] = sigs[len(sigs)-1-i]
	}
	backward, _ := AggregateSignatures(reversed)

	// Nodes that collected the same signatures in different orders must produce
	// the same certificate, or they would build different blocks.
	if !forward.Equal(backward) {
		t.Fatal("aggregation depends on the order signatures arrived in")
	}
	if !FastAggregateVerify(keys, msg, backward) {
		t.Fatal("the reordered aggregate did not verify")
	}
}

func TestIncrementalAggregation(t *testing.T) {
	msg := []byte("votes arrive one at a time")
	var keys []*PublicKey
	running := (*Signature)(nil)

	// A quorum is assembled as votes arrive, not in one batch.
	for i := 0; i < 8; i++ {
		k, _ := GenerateKey()
		keys = append(keys, k.PublicKey())
		sig := k.Sign(msg)
		if running == nil {
			running = sig
		} else {
			var err error
			running, err = AggregateSignatures([]*Signature{running, sig})
			if err != nil {
				t.Fatal(err)
			}
		}
		if !FastAggregateVerify(keys, msg, running) {
			t.Fatalf("the running aggregate failed after %d signatures", i+1)
		}
	}
}

func TestProofOfPossessionStopsRogueKeys(t *testing.T) {
	// The rogue key attack: an attacker registers a public key computed so
	// that the aggregate of the honest keys and its own equals a key it
	// controls alone. It can then produce an "aggregate" signature nobody
	// else agreed to.
	honest, _ := GenerateKey()
	honestPub := honest.PublicKey()

	attacker, _ := GenerateKey()
	// rogue = attacker's key minus the honest key, so rogue + honest =
	// attacker's key.
	rogue := &PublicKey{p: attacker.PublicKey().Point().Add(honestPub.Point().Neg())}

	msg := []byte("a message the honest validator never signed")
	forged := attacker.Sign(msg)

	// The attack works against naive aggregate verification.
	if !FastAggregateVerify([]*PublicKey{honestPub, rogue}, msg, forged) {
		t.Fatal("the rogue key attack did not reproduce; the test is not testing anything")
	}

	// It fails at registration, because the attacker cannot prove possession
	// of the rogue key: it does not know its discrete logarithm.
	if VerifyPossession(rogue, attacker.ProvePossession()) {
		t.Fatal("a rogue key passed the proof of possession check")
	}
	// An honest key passes.
	if !VerifyPossession(honestPub, honest.ProvePossession()) {
		t.Fatal("an honest key failed the proof of possession check")
	}
}

func TestPossessionProofIsNotAnAttestation(t *testing.T) {
	// The two are domain-separated, so a proof of possession cannot be
	// replayed as a signature over the public key as a message.
	key, _ := GenerateKey()
	pub := key.PublicKey()
	proof := key.ProvePossession()

	if Verify(pub, pub.Bytes(), proof) {
		t.Fatal("a possession proof verified as an ordinary signature")
	}
	if VerifyPossession(pub, key.Sign(pub.Bytes())) {
		t.Fatal("an ordinary signature verified as a possession proof")
	}
}

func TestAggregateVerifyDistinctMessages(t *testing.T) {
	var keys []*PublicKey
	var messages [][]byte
	var sigs []*Signature
	for i := 0; i < 4; i++ {
		k, _ := GenerateKey()
		msg := []byte(fmt.Sprintf("message %d", i))
		keys = append(keys, k.PublicKey())
		messages = append(messages, msg)
		sigs = append(sigs, k.Sign(msg))
	}
	aggregate, _ := AggregateSignatures(sigs)

	if !AggregateVerify(keys, messages, aggregate) {
		t.Fatal("the aggregate over distinct messages did not verify")
	}
	// Swapping which key signed which message must fail.
	swapped := [][]byte{messages[1], messages[0], messages[2], messages[3]}
	if AggregateVerify(keys, swapped, aggregate) {
		t.Fatal("the aggregate verified with messages attributed to the wrong keys")
	}
	// Repeated messages are refused: with them, one signer's signature could
	// be replayed as another's.
	repeated := [][]byte{messages[0], messages[0], messages[2], messages[3]}
	if AggregateVerify(keys, repeated, aggregate) {
		t.Fatal("repeated messages were accepted")
	}
}

func TestSerializationRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	pub := key.PublicKey()
	sig := key.Sign([]byte("round trip"))

	encodedKey := pub.Bytes()
	if len(encodedKey) != PublicKeyLength {
		t.Fatalf("public key is %d bytes, want %d", len(encodedKey), PublicKeyLength)
	}
	decodedKey, err := PublicKeyFromBytes(encodedKey)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedKey.Equal(pub) {
		t.Fatal("the public key changed across the round trip")
	}

	encodedSig := sig.Bytes()
	if len(encodedSig) != SignatureLength {
		t.Fatalf("signature is %d bytes, want %d", len(encodedSig), SignatureLength)
	}
	decodedSig, err := SignatureFromBytes(encodedSig)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedSig.Equal(sig) {
		t.Fatal("the signature changed across the round trip")
	}
	// And it still verifies after the trip.
	if !Verify(decodedKey, []byte("round trip"), decodedSig) {
		t.Fatal("the decoded signature did not verify")
	}
}

func TestMalformedEncodingsRejected(t *testing.T) {
	key, _ := GenerateKey()
	valid := key.PublicKey().Bytes()

	for name, input := range map[string][]byte{
		"too short":      valid[:47],
		"too long":       append(append([]byte{}, valid...), 0),
		"not compressed": func() []byte { b := append([]byte{}, valid...); b[0] &^= flagCompressed; return b }(),
		"garbage":        make([]byte, PublicKeyLength),
	} {
		if _, err := PublicKeyFromBytes(input); err == nil {
			t.Errorf("%s: was accepted", name)
		}
	}

	// A point on the curve but outside the prime-order subgroup must be
	// refused: it is the input that breaks the pairing's guarantees.
	for i := int64(1); i < 200; i++ {
		x := feFromBig(big.NewInt(i))
		rhs := fpAdd(fpMul(fpMul(x, x), x), curveB)
		y, ok := fpSqrtBase(rhs)
		if !ok {
			continue
		}
		point := &G1{X: x, Y: y}
		if point.InSubgroup() {
			continue
		}
		encoded := (&PublicKey{p: point}).Bytes()
		if _, err := PublicKeyFromBytes(encoded); err == nil {
			t.Fatal("a point outside the prime-order subgroup was accepted as a public key")
		}
		return
	}
	t.Skip("no small-order point found to test with")
}

func TestInfinityIsRefused(t *testing.T) {
	// The identity is not a usable key: everything verifies against it.
	zero := &PublicKey{p: G1Zero()}
	key, _ := GenerateKey()
	if Verify(zero, []byte("anything"), key.Sign([]byte("anything"))) {
		t.Fatal("the identity was accepted as a public key")
	}
}

func TestDerivedKeysAreDeterministic(t *testing.T) {
	a := DeriveSecretKey([]byte("seed material"))
	b := DeriveSecretKey([]byte("seed material"))
	if a.PublicKey().Equal(b.PublicKey()) != true {
		t.Fatal("key derivation is not deterministic")
	}
	c := DeriveSecretKey([]byte("different seed"))
	if a.PublicKey().Equal(c.PublicKey()) {
		t.Fatal("different seeds derived the same key")
	}
}

func BenchmarkSign(b *testing.B) {
	key, _ := GenerateKey()
	msg := []byte("bench")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	key, _ := GenerateKey()
	msg := []byte("bench")
	pub := key.PublicKey()
	sig := key.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkFastAggregateVerify128(b *testing.B) {
	msg := []byte("bench")
	var keys []*PublicKey
	var sigs []*Signature
	for i := 0; i < 128; i++ {
		k, _ := GenerateKey()
		keys = append(keys, k.PublicKey())
		sigs = append(sigs, k.Sign(msg))
	}
	agg, _ := AggregateSignatures(sigs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FastAggregateVerify(keys, msg, agg)
	}
}
