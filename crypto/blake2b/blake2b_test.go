package blake2b

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from EIP-152, which defines the precompile.
func TestEIP152Vectors(t *testing.T) {
	const (
		// The state and message used by every vector below: the BLAKE2b
		// compression of "abc" with the standard parameter block.
		state   = "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
		message = "6162630000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000"
		counters = "03000000000000000000000000000000"
	)

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "zero rounds",
			input: "00000000" + state + message + counters + "01",
			want:  "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b",
		},
		{
			name:  "twelve rounds, final block",
			input: "0000000c" + state + message + counters + "01",
			want:  "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
		},
		{
			name:  "twelve rounds, not final",
			input: "0000000c" + state + message + counters + "00",
			want:  "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",
		},
		{
			name:  "one round",
			input: "00000001" + state + message + counters + "01",
			want:  "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rounds, h, m, tt, final, ok := ParseInput(mustHex(t, c.input))
			if !ok {
				t.Fatal("input was rejected")
			}
			F(&h, m, tt, final, rounds)
			if got := hex.EncodeToString(EncodeState(h)); got != c.want {
				t.Fatalf("F = %s\nwant  %s", got, c.want)
			}
		})
	}
}

func TestMalformedInputRejected(t *testing.T) {
	valid := "0000000c" +
		"48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b" +
		"6162630000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"03000000000000000000000000000000" + "01"

	if _, _, _, _, _, ok := ParseInput(mustHex(t, valid)); !ok {
		t.Fatal("the reference input was rejected")
	}

	// Short input.
	if _, _, _, _, _, ok := ParseInput(mustHex(t, valid)[:100]); ok {
		t.Error("a truncated input was accepted")
	}
	// Long input.
	if _, _, _, _, _, ok := ParseInput(append(mustHex(t, valid), 0)); ok {
		t.Error("an over-long input was accepted")
	}
	// The final-block flag must be strictly 0 or 1.
	bad := mustHex(t, valid)
	bad[len(bad)-1] = 2
	if _, _, _, _, _, ok := ParseInput(bad); ok {
		t.Error("a non-boolean flag byte was accepted")
	}
}

func TestRoundsAffectOutput(t *testing.T) {
	var h [8]uint64
	copy(h[:], IV[:])
	var m [16]uint64
	m[0] = 0x636261

	a := h
	F(&a, m, [2]uint64{3, 0}, true, 12)
	b := h
	F(&b, m, [2]uint64{3, 0}, true, 11)
	if a == b {
		t.Fatal("eleven and twelve rounds produced the same state")
	}

	// The permutation cycles every ten rounds, but the state keeps evolving.
	c := h
	F(&c, m, [2]uint64{3, 0}, true, 10)
	d := h
	F(&d, m, [2]uint64{3, 0}, true, 20)
	if c == d {
		t.Fatal("ten and twenty rounds produced the same state")
	}
}
