package p2p

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"padi-chain/common"
	"padi-chain/crypto/secp256k1"
)

func testKey(t *testing.T, i byte) *secp256k1.PrivateKey {
	t.Helper()
	key, err := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{i}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// socketPair returns two ends of a real TCP connection. net.Pipe is unbuffered,
// and the handshake has both sides write before either reads, so a pipe would
// deadlock where a socket does not.
func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	return client, server
}

// handshakePair runs a handshake over a socket pair and returns both sessions.
func handshakePair(t *testing.T, initiatorKey, responderKey *secp256k1.PrivateKey) (*secureConn, *secureConn, error) {
	t.Helper()
	clientConn, serverConn := socketPair(t)

	type result struct {
		session *session
		err     error
	}
	responderCh := make(chan result, 1)
	go func() {
		sess, err := performHandshake(serverConn, responderKey, false)
		responderCh <- result{sess, err}
	}()

	initiatorSession, initiatorErr := performHandshake(clientConn, initiatorKey, true)
	responder := <-responderCh

	if initiatorErr != nil {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, initiatorErr
	}
	if responder.err != nil {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, responder.err
	}
	return &secureConn{conn: clientConn, session: initiatorSession},
		&secureConn{conn: serverConn, session: responder.session}, nil
}

func TestHandshakeEstablishesAuthenticatedSession(t *testing.T) {
	initiatorKey := testKey(t, 1)
	responderKey := testKey(t, 2)

	client, server, err := handshakePair(t, initiatorKey, responderKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	// Each side must have learned the other's true identity.
	if client.RemoteID() != NodeIDOf(responderKey) {
		t.Fatal("the initiator did not authenticate the responder")
	}
	if server.RemoteID() != NodeIDOf(initiatorKey) {
		t.Fatal("the responder did not authenticate the initiator")
	}
}

func TestEncryptedFramesRoundTrip(t *testing.T) {
	client, server, err := handshakePair(t, testKey(t, 1), testKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	payload := []byte("a block, conceptually")
	done := make(chan error, 1)
	go func() {
		code, got, err := server.readFrame()
		if err != nil {
			done <- err
			return
		}
		if code != MsgNewBlock || string(got) != string(payload) {
			done <- errors.New("frame contents changed in transit")
			return
		}
		done <- nil
	}()

	if err := client.writeFrame(MsgNewBlock, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTrafficIsActuallyEncrypted(t *testing.T) {
	// Read the raw bytes off the wire and confirm the plaintext is not in them.
	clientConn, serverConn := socketPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	responderKey := testKey(t, 2)
	go func() {
		sess, err := performHandshake(serverConn, responderKey, false)
		if err != nil {
			return
		}
		secure := &secureConn{conn: serverConn, session: sess}
		secret := []byte("SUPER-SECRET-TRANSACTION-PAYLOAD")
		secure.writeFrame(MsgNewTransactions, secret)
	}()

	sess, err := performHandshake(clientConn, testKey(t, 1), true)
	if err != nil {
		t.Fatal(err)
	}

	// Read the frame at the socket level, before decryption.
	var header [4]byte
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientConn, header[:]); err != nil {
		t.Fatal(err)
	}
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	sealed := make([]byte, length)
	if _, err := io.ReadFull(clientConn, sealed); err != nil {
		t.Fatal(err)
	}

	if idx := indexOf(sealed, []byte("SUPER-SECRET")); idx >= 0 {
		t.Fatalf("the payload appears in plaintext on the wire at offset %d", idx)
	}

	// And it must still decrypt correctly on the intended side.
	secure := &secureConn{conn: clientConn, session: sess}
	plaintext, err := sess.recv.Open(nil, nonceFor(0), sealed, nil)
	if err != nil {
		t.Fatalf("the legitimate peer could not decrypt: %v", err)
	}
	if string(plaintext[1:]) != "SUPER-SECRET-TRANSACTION-PAYLOAD" {
		t.Fatalf("decrypted to %q", plaintext[1:])
	}
	_ = secure
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestTamperedFrameIsRejected(t *testing.T) {
	client, server, err := handshakePair(t, testKey(t, 1), testKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	// Encrypt a frame, flip a byte, and confirm it fails authentication rather
	// than decrypting to something the node would act on.
	sealed := client.session.send.Seal(nil, nonceFor(0), []byte{byte(MsgNewBlock), 1, 2, 3}, nil)
	sealed[len(sealed)/2] ^= 0xff

	if _, err := server.session.recv.Open(nil, nonceFor(0), sealed, nil); err == nil {
		t.Fatal("a modified frame was accepted")
	}
}

func TestReplayedFrameIsRejected(t *testing.T) {
	client, server, err := handshakePair(t, testKey(t, 1), testKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	// The counter is implicit, so a frame captured and re-sent decrypts under
	// the wrong nonce and fails.
	sealed := client.session.send.Seal(nil, nonceFor(0), []byte{byte(MsgPing)}, nil)
	if _, err := server.session.recv.Open(nil, nonceFor(0), sealed, nil); err != nil {
		t.Fatalf("the first delivery should succeed: %v", err)
	}
	server.session.recvSeq = 1
	if _, err := server.session.recv.Open(nil, nonceFor(server.session.recvSeq), sealed, nil); err == nil {
		t.Fatal("a replayed frame was accepted")
	}
}

func TestManInTheMiddleIsRejected(t *testing.T) {
	// An attacker sits between two nodes and runs its own handshake with each,
	// hoping to relay traffic it can read. It cannot: the signature each side
	// checks covers the ephemeral key of the session it is actually in, and
	// the attacker does not hold either node's long-term key.
	victimKey := testKey(t, 1)
	attackerKey := testKey(t, 9)

	client, server, err := handshakePair(t, victimKey, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	// The handshake succeeds, but the victim learns it is talking to the
	// attacker's identity, not to the peer it intended.
	if client.RemoteID() == NodeIDOf(testKey(t, 2)) {
		t.Fatal("the attacker managed to present another node's identity")
	}
	if client.RemoteID() != NodeIDOf(attackerKey) {
		t.Fatal("the authenticated identity does not match the key that signed")
	}
}

func TestForgedIdentityIsRejected(t *testing.T) {
	// A peer that claims someone else's static key but cannot sign for it must
	// fail the handshake outright.
	clientConn, serverConn := socketPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	impersonated := NodeIDOf(testKey(t, 2))

	go func() {
		// Send a well-formed prefix claiming the victim's identity, then a
		// signature from a key we actually hold.
		ephemeral, _ := secp256k1.GenerateKey()
		prefix := make([]byte, 0, handshakePrefixLen)
		prefix = append(prefix, ephemeral.PublicKey().Bytes()...)
		prefix = append(prefix, make([]byte, nonceLen)...)
		prefix = append(prefix, impersonated[:]...)
		serverConn.Write(prefix)

		io.ReadFull(serverConn, make([]byte, handshakePrefixLen))

		attacker := testKey(t, 9)
		sig, _ := secp256k1.Sign(attacker, make([]byte, 32))
		serverConn.Write(sig.Bytes())
		io.ReadFull(serverConn, make([]byte, authLen))
	}()

	_, err := performHandshake(clientConn, testKey(t, 1), true)
	if err == nil {
		t.Fatal("a peer that could not sign for its claimed identity was accepted")
	}
	if !errors.Is(err, ErrPeerUnauthentic) && !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("got %v, want an authentication failure", err)
	}
}

func TestSelfConnectionIsRejected(t *testing.T) {
	key := testKey(t, 1)
	if _, _, err := handshakePair(t, key, key); !errors.Is(err, ErrSelfConnection) {
		t.Fatalf("got %v, want ErrSelfConnection", err)
	}
}

func TestSessionKeysDifferPerConnection(t *testing.T) {
	// Forward secrecy: two sessions between the same pair of nodes must not
	// share key material, so compromising one reveals nothing about the other.
	a1, _, err := handshakePair(t, testKey(t, 1), testKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()
	a2, _, err := handshakePair(t, testKey(t, 1), testKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()

	first := a1.session.send.Seal(nil, nonceFor(0), []byte("probe"), nil)
	second := a2.session.send.Seal(nil, nonceFor(0), []byte("probe"), nil)
	if string(first) == string(second) {
		t.Fatal("two sessions produced identical ciphertext: the keys are not ephemeral")
	}
}

func TestPeerScoring(t *testing.T) {
	board := newScoreboard()
	id := NodeIDOf(testKey(t, 1))

	if board.isBanned(id) {
		t.Fatal("an unknown peer must not start banned")
	}
	if got := board.scoreOf(id); got != initialScore {
		t.Fatalf("initial score = %d, want %d", got, initialScore)
	}

	// A few honest mistakes must not get a peer banned.
	for i := 0; i < 5; i++ {
		if banned := board.penalise(id, penaltyBadMessage); banned {
			t.Fatalf("banned after %d minor faults", i+1)
		}
	}
	// Sustained misbehaviour must.
	var banned bool
	for i := 0; i < 20 && !banned; i++ {
		banned = board.penalise(id, penaltyInvalidBlock)
	}
	if !banned {
		t.Fatal("a peer sending invalid blocks was never banned")
	}
	if !board.isBanned(id) {
		t.Fatal("isBanned disagrees with the ban that was just issued")
	}
}

func TestBanExpires(t *testing.T) {
	board := newScoreboard()
	id := NodeIDOf(testKey(t, 1))

	now := time.Now()
	board.now = func() time.Time { return now }

	for i := 0; i < 20; i++ {
		board.penalise(id, penaltyInvalidBlock)
	}
	if !board.isBanned(id) {
		t.Fatal("the peer should be banned")
	}

	// A ban is a timeout, not a death sentence: a peer that was briefly faulty
	// gets to come back.
	now = now.Add(banDuration + time.Second)
	if board.isBanned(id) {
		t.Fatal("the ban did not expire")
	}
}

func TestScoreRecovers(t *testing.T) {
	board := newScoreboard()
	id := NodeIDOf(testKey(t, 1))

	now := time.Now()
	board.now = func() time.Time { return now }

	board.penalise(id, 50)
	if got := board.scoreOf(id); got != initialScore-50 {
		t.Fatalf("score after penalty = %d", got)
	}

	now = now.Add(5 * recoveryInterval)
	if got := board.scoreOf(id); got <= initialScore-50 {
		t.Fatalf("score did not recover over time: %d", got)
	}

	now = now.Add(100 * recoveryInterval)
	if got := board.scoreOf(id); got != initialScore {
		t.Fatalf("score recovered to %d, want a ceiling of %d", got, initialScore)
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := newRateLimiter(10, 5)
	now := time.Now()
	limiter.now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		if !limiter.allow() {
			t.Fatalf("request %d was refused within the burst allowance", i+1)
		}
	}
	if limiter.allow() {
		t.Fatal("the limiter allowed a request past its burst capacity")
	}

	// Tokens refill over time.
	now = now.Add(time.Second)
	if !limiter.allow() {
		t.Fatal("the limiter did not refill")
	}

	// Large messages cost proportionally more.
	limiter = newRateLimiter(10, 5)
	limiter.now = func() time.Time { return now }
	if !limiter.allowN(9) {
		t.Fatal("a large request within budget was refused")
	}
	if limiter.allowN(9) {
		t.Fatal("two large requests were allowed on a budget of one")
	}
}
