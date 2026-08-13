package secp256k1

import (
	"bytes"
	"math/big"
	"testing"

	"padi-chain/crypto/keccak"
)

func hashOf(s string) []byte {
	h := keccak.Sum256([]byte(s))
	return h[:]
}

func TestGeneratorOnCurve(t *testing.T) {
	if !Generator().OnCurve() {
		t.Fatal("G is not on the curve")
	}
}

func TestPrivateKeyOneYieldsGenerator(t *testing.T) {
	k := &PrivateKey{D: big.NewInt(1)}
	pub := k.PublicKey()
	if pub.X.Cmp(Gx) != 0 || pub.Y.Cmp(Gy) != 0 {
		t.Fatalf("1*G = (%x, %x), want the generator", pub.X, pub.Y)
	}
}

func TestScalarMulMatchesRepeatedAddition(t *testing.T) {
	g := Generator()
	acc := Infinity()
	for i := 0; i < 16; i++ {
		acc = acc.Add(g)
	}
	if !acc.Equal(g.ScalarMul(big.NewInt(16))) {
		t.Fatal("16*G disagrees with sixteen additions of G")
	}
}

func TestOrderTimesGeneratorIsInfinity(t *testing.T) {
	if !ScalarBaseMul(N).IsInfinity() {
		t.Fatal("N*G must be the point at infinity")
	}
	// (N-1)*G == -G
	if !ScalarBaseMul(new(big.Int).Sub(N, big.NewInt(1))).Equal(Generator().Neg()) {
		t.Fatal("(N-1)*G must equal -G")
	}
}

func TestAddInverseGivesInfinity(t *testing.T) {
	g := Generator()
	if !g.Add(g.Neg()).IsInfinity() {
		t.Fatal("G + (-G) must be infinity")
	}
}

func TestKnownPublicKeyVector(t *testing.T) {
	// Private key 1's public key hashes to a well-known Ethereum address.
	k := &PrivateKey{D: big.NewInt(1)}
	h := keccak.Sum256(k.PublicKey().Bytes())
	got := "0x" + string(hexdigits(h[12:]))
	want := "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	if got != want {
		t.Fatalf("address for key 1 = %s, want %s", got, want)
	}
}

func hexdigits(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return out
}

func TestSignVerifyRecover(t *testing.T) {
	key, err := PrivateKeyFromHex("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()
	hash := hashOf("padi-chain says hello")

	sig, err := Sign(key, hash)
	if err != nil {
		t.Fatal(err)
	}
	if sig.S.Cmp(halfN) > 0 {
		t.Fatal("signature must be canonical low-s")
	}
	if !Verify(pub, hash, sig) {
		t.Fatal("valid signature failed verification")
	}
	rec, err := Recover(hash, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Equal(pub) {
		t.Fatalf("recovered %x, want %x", rec.Bytes(), pub.Bytes())
	}
}

func TestSignIsDeterministic(t *testing.T) {
	key, _ := PrivateKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	hash := hashOf("same message")
	a, _ := Sign(key, hash)
	b, _ := Sign(key, hash)
	if a.R.Cmp(b.R) != 0 || a.S.Cmp(b.S) != 0 || a.V != b.V {
		t.Fatal("signing the same message twice produced different signatures")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key, _ := GenerateKey()
	pub := key.PublicKey()
	hash := hashOf("original")
	sig, err := Sign(key, hash)
	if err != nil {
		t.Fatal(err)
	}

	if Verify(pub, hashOf("different"), sig) {
		t.Error("signature verified against the wrong message")
	}

	bad := &Signature{R: new(big.Int).Add(sig.R, big.NewInt(1)), S: sig.S, V: sig.V}
	if Verify(pub, hash, bad) {
		t.Error("signature verified with a mutated r")
	}

	other, _ := GenerateKey()
	if Verify(other.PublicKey(), hash, sig) {
		t.Error("signature verified against an unrelated public key")
	}
}

func TestVerifyRejectsHighS(t *testing.T) {
	key, _ := GenerateKey()
	hash := hashOf("malleable")
	sig, _ := Sign(key, hash)
	// The mirrored signature is mathematically valid but non-canonical.
	high := &Signature{R: sig.R, S: new(big.Int).Sub(N, sig.S), V: sig.V ^ 1}
	if Verify(key.PublicKey(), hash, high) {
		t.Fatal("high-s signature must be rejected as non-canonical")
	}
}

func TestVerifyRejectsOutOfRangeScalars(t *testing.T) {
	key, _ := GenerateKey()
	hash := hashOf("range")
	sig, _ := Sign(key, hash)
	for name, bad := range map[string]*Signature{
		"zero r": {R: big.NewInt(0), S: sig.S, V: sig.V},
		"zero s": {R: sig.R, S: big.NewInt(0), V: sig.V},
		"r >= N": {R: new(big.Int).Set(N), S: sig.S, V: sig.V},
		"s >= N": {R: sig.R, S: new(big.Int).Set(N), V: sig.V},
		"neg r":  {R: big.NewInt(-1), S: sig.S, V: sig.V},
	} {
		if Verify(key.PublicKey(), hash, bad) {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestRecoverAcrossManyKeys(t *testing.T) {
	// Exercises both recovery-id parities over many random keys.
	for i := 0; i < 25; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		hash := hashOf("message " + string(rune('a'+i)))
		sig, err := Sign(key, hash)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := Recover(hash, sig)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !rec.Equal(key.PublicKey()) {
			t.Fatalf("iteration %d: recovery returned the wrong key", i)
		}
	}
}

func TestRecoverWithWrongVFindsDifferentKey(t *testing.T) {
	key, _ := GenerateKey()
	hash := hashOf("flip v")
	sig, _ := Sign(key, hash)
	flipped := &Signature{R: sig.R, S: sig.S, V: sig.V ^ 1}
	rec, err := Recover(hash, flipped)
	if err == nil && rec.Equal(key.PublicKey()) {
		t.Fatal("flipping the recovery id must not return the same key")
	}
}

func TestPublicKeySerializationRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	pub := key.PublicKey()
	for name, enc := range map[string][]byte{
		"raw64":        pub.Bytes(),
		"uncompressed": pub.SEC1Uncompressed(),
		"compressed":   pub.SEC1Compressed(),
	} {
		got, err := ParsePublicKey(enc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.Equal(pub) {
			t.Fatalf("%s: round-trip changed the key", name)
		}
	}
}

func TestParsePublicKeyRejectsOffCurve(t *testing.T) {
	bad := make([]byte, 64)
	bad[31] = 1 // (1, 0) is not on the curve
	if _, err := ParsePublicKey(bad); err == nil {
		t.Fatal("off-curve point must be rejected")
	}
	if _, err := ParsePublicKey([]byte{0x04, 0x01}); err == nil {
		t.Fatal("malformed encoding must be rejected")
	}
}

func TestSignatureSerializationRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	sig, _ := Sign(key, hashOf("serialize"))
	got, err := ParseSignature(sig.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.R.Cmp(sig.R) != 0 || got.S.Cmp(sig.S) != 0 || got.V != sig.V {
		t.Fatal("signature round-trip mismatch")
	}
	if _, err := ParseSignature(make([]byte, 64)); err == nil {
		t.Fatal("short signature must be rejected")
	}
}

func TestPrivateKeyValidation(t *testing.T) {
	if _, err := PrivateKeyFromBytes(make([]byte, 32)); err == nil {
		t.Error("zero key must be rejected")
	}
	nBytes := make([]byte, 32)
	N.FillBytes(nBytes)
	if _, err := PrivateKeyFromBytes(nBytes); err == nil {
		t.Error("key equal to the group order must be rejected")
	}
	if _, err := PrivateKeyFromBytes(make([]byte, 31)); err == nil {
		t.Error("short key must be rejected")
	}
}

func TestGenerateKeyIsRandom(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if a.D.Cmp(b.D) == 0 {
		t.Fatal("two generated keys collided")
	}
}

func BenchmarkSign(b *testing.B) {
	key, _ := GenerateKey()
	hash := hashOf("bench")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(key, hash)
	}
}

func BenchmarkRecover(b *testing.B) {
	key, _ := GenerateKey()
	hash := hashOf("bench")
	sig, _ := Sign(key, hash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Recover(hash, sig)
	}
}
