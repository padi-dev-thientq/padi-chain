// Package rpc serves the JSON-RPC 2.0 API over HTTP.
package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JSON-RPC error codes, from the specification plus the conventional
// Ethereum extension for execution failures.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeExecutionError = 3
)

// Request is an incoming JSON-RPC call.
type Request struct {
	Version string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

// Response is an outgoing JSON-RPC reply.
type Response struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// NewError builds a JSON-RPC error.
func NewError(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Handler implements one RPC method.
type Handler func(params []json.RawMessage) (any, error)

// Server dispatches JSON-RPC requests to registered handlers.
type Server struct {
	mu       sync.RWMutex
	handlers map[string]Handler

	http     *http.Server
	listener net.Listener
	// MaxBodySize caps a request body, so a hostile client cannot exhaust
	// memory with a single POST.
	MaxBodySize int64
	// MaxBatchSize caps how many calls one request may contain.
	MaxBatchSize int

	limiter  *limiter
	quit     chan struct{}
	quitOnce sync.Once
}

// NewServer creates an empty RPC server.
func NewServer() *Server {
	return NewServerWithLimits(DefaultLimits())
}

// NewServerWithLimits creates a server with explicit resource limits.
func NewServerWithLimits(limits *Limits) *Server {
	s := &Server{
		handlers:     make(map[string]Handler),
		MaxBodySize:  5 * 1024 * 1024,
		MaxBatchSize: 100,
		limiter:      newLimiter(limits),
		quit:         make(chan struct{}),
	}
	go s.sweepLoop()
	return s
}

// sweepLoop expires idle client budgets.
func (s *Server) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.limiter.sweep()
		}
	}
}

// Register adds a method handler. Registering the same name twice is a
// programming error and panics.
func (s *Server) Register(method string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.handlers[method]; exists {
		panic("rpc: method registered twice: " + method)
	}
	s.handlers[method] = handler
}

// Methods returns the registered method names.
func (s *Server) Methods() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.handlers))
	for name := range s.handlers {
		out = append(out, name)
	}
	return out
}

// ServeHTTP handles a JSON-RPC request or batch.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cross-origin access is allowed: this API is read-mostly and the node
	// holds no credentials that a browser could leak.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxBodySize))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(nil, NewError(CodeParseError, "reading request: %v", err)))
		return
	}

	trimmed := strings.TrimSpace(string(body))
	w.Header().Set("Content-Type", "application/json")
	client := clientKey(r)

	// A leading bracket means a batch of calls.
	if strings.HasPrefix(trimmed, "[") {
		var batch []Request
		if err := json.Unmarshal(body, &batch); err != nil {
			writeJSON(w, http.StatusOK, errorResponse(nil, NewError(CodeParseError, "malformed batch: %v", err)))
			return
		}
		if len(batch) > s.MaxBatchSize {
			writeJSON(w, http.StatusOK, errorResponse(nil, NewError(CodeInvalidRequest, "batch of %d exceeds the limit of %d", len(batch), s.MaxBatchSize)))
			return
		}
		// A batch is charged for every call it contains, so batching cannot be
		// used to slip past the per-call budget.
		var total float64
		for i := range batch {
			total += costOf(batch[i].Method)
		}
		if !s.limiter.allow(client, total) {
			writeJSON(w, http.StatusTooManyRequests, errorResponse(nil, NewError(CodeInvalidRequest, "rate limit exceeded")))
			return
		}
		responses := make([]Response, 0, len(batch))
		for i := range batch {
			responses = append(responses, s.serve(&batch[i]))
		}
		writeJSON(w, http.StatusOK, responses)
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusOK, errorResponse(nil, NewError(CodeParseError, "malformed request: %v", err)))
		return
	}
	if !s.limiter.allow(client, costOf(req.Method)) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse(req.ID, NewError(CodeInvalidRequest, "rate limit exceeded")))
		return
	}
	writeJSON(w, http.StatusOK, s.serve(&req))
}

// serve runs one call under the concurrency cap.
func (s *Server) serve(req *Request) Response {
	if !s.limiter.acquire() {
		return Response{
			Version: "2.0",
			ID:      req.ID,
			Error:   NewError(CodeInternalError, "the node is at capacity, try again shortly"),
		}
	}
	defer s.limiter.release()
	return s.dispatch(req)
}

// dispatch runs one call, converting a panic in a handler into an error rather
// than taking the node down.
func (s *Server) dispatch(req *Request) (resp Response) {
	resp = Response{Version: "2.0", ID: req.ID}

	defer func() {
		if r := recover(); r != nil {
			resp.Result = nil
			resp.Error = NewError(CodeInternalError, "handler panicked: %v", r)
		}
	}()

	if req.Method == "" {
		resp.Error = NewError(CodeInvalidRequest, "no method specified")
		return resp
	}

	s.mu.RLock()
	handler, ok := s.handlers[req.Method]
	s.mu.RUnlock()
	if !ok {
		resp.Error = NewError(CodeMethodNotFound, "the method %s does not exist", req.Method)
		return resp
	}

	result, err := handler(req.Params)
	if err != nil {
		if rpcErr, ok := err.(*Error); ok {
			resp.Error = rpcErr
		} else {
			resp.Error = NewError(CodeInternalError, "%v", err)
		}
		return resp
	}
	resp.Result = result
	return resp
}

// Call invokes a method directly, bypassing HTTP. Used by tests and by the
// in-process console.
func (s *Server) Call(method string, params ...any) (any, error) {
	raw := make([]json.RawMessage, 0, len(params))
	for _, p := range params {
		enc, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		raw = append(raw, enc)
	}
	resp := s.dispatch(&Request{Method: method, Params: raw})
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

// Start begins serving on addr.
func (s *Server) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("rpc: listening on %s: %w", addr, err)
	}
	s.listener = listener
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go s.http.Serve(listener)
	return nil
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop shuts the server down.
func (s *Server) Stop() error {
	s.quitOnce.Do(func() { close(s.quit) })
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func errorResponse(id json.RawMessage, err *Error) Response {
	return Response{Version: "2.0", ID: id, Error: err}
}
