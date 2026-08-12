package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := NewServer()
	t.Cleanup(func() { s.Stop() })
	s.Register("test_echo", func(params []json.RawMessage) (any, error) {
		if len(params) == 0 {
			return "", nil
		}
		var v string
		json.Unmarshal(params[0], &v)
		return v, nil
	})
	s.Register("test_fail", func(params []json.RawMessage) (any, error) {
		return nil, NewError(CodeExecutionError, "deliberate failure")
	})
	s.Register("test_panic", func(params []json.RawMessage) (any, error) {
		panic("a handler bug")
	})
	return s
}

func post(t *testing.T, s *Server, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	data, _ := io.ReadAll(rec.Body)
	return rec, string(data)
}

func TestSingleCall(t *testing.T) {
	s := newTestServer(t)
	_, body := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_echo","params":["hello"]}`)

	var resp Response
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result != "hello" {
		t.Fatalf("result = %v", resp.Result)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer(t)
	_, body := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"nope"}`)

	var resp Response
	json.Unmarshal([]byte(body), &resp)
	if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
		t.Fatalf("got %v, want a method-not-found error", resp.Error)
	}
}

func TestHandlerPanicBecomesAnError(t *testing.T) {
	s := newTestServer(t)
	// A bug in one handler must not take the node down with it.
	_, body := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_panic"}`)

	var resp Response
	json.Unmarshal([]byte(body), &resp)
	if resp.Error == nil || resp.Error.Code != CodeInternalError {
		t.Fatalf("got %v, want an internal error", resp.Error)
	}
}

func TestMalformedRequest(t *testing.T) {
	s := newTestServer(t)
	_, body := post(t, s, `{not json`)

	var resp Response
	json.Unmarshal([]byte(body), &resp)
	if resp.Error == nil || resp.Error.Code != CodeParseError {
		t.Fatalf("got %v, want a parse error", resp.Error)
	}
}

func TestBatch(t *testing.T) {
	s := newTestServer(t)
	_, body := post(t, s, `[
		{"jsonrpc":"2.0","id":1,"method":"test_echo","params":["a"]},
		{"jsonrpc":"2.0","id":2,"method":"test_fail"},
		{"jsonrpc":"2.0","id":3,"method":"test_echo","params":["c"]}
	]`)

	var responses []Response
	if err := json.Unmarshal([]byte(body), &responses); err != nil {
		t.Fatal(err)
	}
	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 3", len(responses))
	}
	if responses[0].Result != "a" || responses[2].Result != "c" {
		t.Error("batch results are wrong or out of order")
	}
	if responses[1].Error == nil {
		t.Error("the failing call should have reported an error")
	}
}

func TestOversizedBatchRejected(t *testing.T) {
	s := newTestServer(t)
	s.MaxBatchSize = 3

	var calls []string
	for i := 0; i < 10; i++ {
		calls = append(calls, `{"jsonrpc":"2.0","id":1,"method":"test_echo"}`)
	}
	_, body := post(t, s, "["+strings.Join(calls, ",")+"]")

	var resp Response
	json.Unmarshal([]byte(body), &resp)
	if resp.Error == nil {
		t.Fatal("an oversized batch must be rejected")
	}
}

func TestOversizedBodyIsTruncated(t *testing.T) {
	s := newTestServer(t)
	s.MaxBodySize = 64

	huge := `{"jsonrpc":"2.0","id":1,"method":"test_echo","params":["` + strings.Repeat("x", 10000) + `"]}`
	rec, _ := post(t, s, huge)
	// The point is that the node does not read the whole thing into memory;
	// the truncated body then fails to parse.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.RequestsPerSecond = 1
	limits.Burst = 5
	s := NewServerWithLimits(limits)
	defer s.Stop()
	s.Register("test_echo", func(params []json.RawMessage) (any, error) { return "ok", nil })

	// The burst allowance is spent first.
	for i := 0; i < 5; i++ {
		rec, _ := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_echo"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst was refused with %d", i+1, rec.Code)
		}
	}
	rec, _ := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_echo"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the budget is spent", rec.Code)
	}
}

func TestRateLimitIsPerClient(t *testing.T) {
	limits := DefaultLimits()
	limits.RequestsPerSecond = 1
	limits.Burst = 2
	s := NewServerWithLimits(limits)
	defer s.Stop()
	s.Register("test_echo", func(params []json.RawMessage) (any, error) { return "ok", nil })

	call := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"test_echo"}`))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}

	// One client exhausting its budget must not affect another.
	for i := 0; i < 2; i++ {
		call("10.0.0.1:1000")
	}
	if code := call("10.0.0.1:1000"); code != http.StatusTooManyRequests {
		t.Fatalf("the noisy client was not limited: %d", code)
	}
	if code := call("10.0.0.2:1000"); code != http.StatusOK {
		t.Fatalf("an unrelated client was limited: %d", code)
	}
}

func TestExpensiveMethodsCostMore(t *testing.T) {
	if costOf("eth_estimateGas") <= costOf("eth_blockNumber") {
		t.Fatal("estimateGas does far more work than blockNumber and must cost more")
	}
	if costOf("eth_getLogs") <= costOf("eth_chainId") {
		t.Fatal("a log scan must cost more than a constant lookup")
	}
	if costOf("some_unknown_method") != 1 {
		t.Fatal("unknown methods should fall into the cheapest tier")
	}
}

func TestBatchIsChargedForEveryCall(t *testing.T) {
	limits := DefaultLimits()
	limits.RequestsPerSecond = 0.001
	limits.Burst = 5
	s := NewServerWithLimits(limits)
	defer s.Stop()
	s.Register("test_echo", func(params []json.RawMessage) (any, error) { return "ok", nil })

	// Ten calls in one request must not slip through a budget of five.
	var calls []string
	for i := 0; i < 10; i++ {
		calls = append(calls, `{"jsonrpc":"2.0","id":1,"method":"test_echo"}`)
	}
	rec, _ := post(t, s, "["+strings.Join(calls, ",")+"]")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d: batching bypassed the rate limit", rec.Code)
	}
}

func TestBudgetRefills(t *testing.T) {
	limits := DefaultLimits()
	limits.RequestsPerSecond = 10
	limits.Burst = 1
	l := newLimiter(limits)

	now := time.Now()
	l.now = func() time.Time { return now }

	if !l.allow("client", 1) {
		t.Fatal("the first call should be allowed")
	}
	if l.allow("client", 1) {
		t.Fatal("the budget should be spent")
	}
	now = now.Add(time.Second)
	if !l.allow("client", 1) {
		t.Fatal("the budget did not refill")
	}
}

func TestIdleClientsAreForgotten(t *testing.T) {
	limits := DefaultLimits()
	limits.ClientTTL = time.Minute
	l := newLimiter(limits)

	now := time.Now()
	l.now = func() time.Time { return now }
	l.allow("transient", 1)
	if len(l.clients) != 1 {
		t.Fatal("the client was not recorded")
	}

	// Otherwise a stream of one-shot clients would grow the map forever.
	now = now.Add(2 * time.Minute)
	l.sweep()
	if len(l.clients) != 0 {
		t.Fatalf("%d idle clients survived the sweep", len(l.clients))
	}
}

func TestConcurrencyIsCapped(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxConcurrent = 2
	limits.CallTimeout = 200 * time.Millisecond
	s := NewServerWithLimits(limits)
	defer s.Stop()

	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	var once sync.Once
	s.Register("test_slow", func(params []json.RawMessage) (any, error) {
		once.Do(func() {})
		started.Done()
		<-release
		return "done", nil
	})

	// Occupy both slots.
	for i := 0; i < 2; i++ {
		go post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_slow"}`)
	}
	started.Wait()

	// A third call must be shed rather than queued indefinitely.
	done := make(chan string, 1)
	go func() {
		_, body := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"test_slow"}`)
		done <- body
	}()

	select {
	case body := <-done:
		if !strings.Contains(body, "capacity") {
			t.Fatalf("expected a capacity error, got %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the overflow call neither ran nor was refused")
	}
	close(release)
}

func TestDirectCallBypassesHTTP(t *testing.T) {
	s := newTestServer(t)
	result, err := s.Call("test_echo", "in process")
	if err != nil {
		t.Fatal(err)
	}
	if result != "in process" {
		t.Fatalf("result = %v", result)
	}
}

func TestCORSPreflight(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("preflight status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("no CORS header on the preflight response")
	}
}

func TestOnlyPostIsAccepted(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}

func TestConcurrentRequests(t *testing.T) {
	s := newTestServer(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(
				[]byte(`{"jsonrpc":"2.0","id":1,"method":"test_echo","params":["x"]}`)))
			req.RemoteAddr = "10.0.0.99:1000"
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
		}(i)
	}
	wg.Wait()
}
