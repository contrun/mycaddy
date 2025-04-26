// Package quicsshproxy provides listener wrappers for QUIC and WebSocket connections
package quicsshproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// ConnWrapper is an interface for wrapped connections
type ConnWrapper interface {
	io.ReadWriteCloser
	GetTarget() string
}

// ListenerWrapper is an interface for wrapped listeners
type ListenerWrapper interface {
	Accept() (ConnWrapper, error)
	Close() error
}

// QUICConnWrapper wraps a QUIC stream and session
type QUICConnWrapper struct {
	stream     quic.Stream
	session    quic.Connection
	target     string
	serverName string
}

// Read reads data from the QUIC stream
func (q *QUICConnWrapper) Read(p []byte) (int, error) {
	return q.stream.Read(p)
}

// Write writes data to the QUIC stream
func (q *QUICConnWrapper) Write(p []byte) (int, error) {
	return q.stream.Write(p)
}

// Close closes the QUIC stream and session
func (q *QUICConnWrapper) Close() error {
	q.stream.Close()
	q.session.CloseWithError(0, "close")
	return nil
}

// GetTarget returns the target to connect to
func (q *QUICConnWrapper) GetTarget() string {
	return q.target
}

// GetServerName returns the server name from the TLS connection
func (q *QUICConnWrapper) GetServerName() string {
	return q.serverName
}

// WebSocketConnWrapper wraps a WebSocket connection
type WebSocketConnWrapper struct {
	conn   *websocket.Conn
	target string
	ctx    context.Context
	reader io.Reader
	mu     sync.Mutex
}

// NewWebSocketConnWrapper creates a new WebSocket connection wrapper
func NewWebSocketConnWrapper(conn *websocket.Conn, target string) *WebSocketConnWrapper {
	return &WebSocketConnWrapper{
		conn:   conn,
		target: target,
		ctx:    context.Background(),
	}
}

// Read reads data from the WebSocket connection
func (w *WebSocketConnWrapper) Read(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.reader == nil {
		// Read a message
		_, reader, err := w.conn.Reader(w.ctx)
		if err != nil {
			return 0, err
		}
		w.reader = reader
	}

	// Read from the current message
	n, err := w.reader.Read(p)
	if err == io.EOF {
		// Message fully read, prepare for next message
		w.reader = nil
		return n, nil
	}
	return n, err
}

// Write writes data to the WebSocket connection
func (w *WebSocketConnWrapper) Write(p []byte) (int, error) {
	err := w.conn.Write(w.ctx, websocket.MessageBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the WebSocket connection
func (w *WebSocketConnWrapper) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "closed")
}

// GetTarget returns the target to connect to
func (w *WebSocketConnWrapper) GetTarget() string {
	return w.target
}

// QUICListenerWrapper wraps a QUIC listener
type QUICListenerWrapper struct {
	listener quic.Listener
	logger   *zap.Logger
}

// NewQUICListenerWrapper creates a new QUIC listener wrapper
func NewQUICListenerWrapper(addr string, tlsConfig *tls.Config, logger *zap.Logger) (*QUICListenerWrapper, error) {
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("starting QUIC listener: %w", err)
	}

	return &QUICListenerWrapper{
		listener: listener,
		logger:   logger,
	}, nil
}

// Accept accepts a connection and wraps it
func (q *QUICListenerWrapper) Accept() (ConnWrapper, error) {
	ctx := context.Background()

	// Accept a QUIC connection
	session, err := q.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	// Get the server name from the connection (for routing)
	serverName := session.ConnectionState().TLS.ServerName

	// Accept a stream from the connection
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		session.CloseWithError(0, "failed to accept stream")
		return nil, err
	}

	// Create a wrapped connection
	return &QUICConnWrapper{
		stream:     stream,
		session:    session,
		target:     serverName,
		serverName: serverName,
	}, nil
}

// Close closes the QUIC listener
func (q *QUICListenerWrapper) Close() error {
	return q.listener.Close()
}

// MultiListenerWrapper manages multiple listener wrappers
type MultiListenerWrapper struct {
	listeners []ListenerWrapper
	acceptCh  chan acceptResult
	errCh     chan error
	doneCh    chan struct{}
	logger    *zap.Logger
}

// acceptResult represents the result of an Accept operation
type acceptResult struct {
	conn ConnWrapper
	err  error
}

// NewMultiListenerWrapper creates a new multi-listener wrapper
func NewMultiListenerWrapper(listeners []ListenerWrapper, logger *zap.Logger) *MultiListenerWrapper {
	return &MultiListenerWrapper{
		listeners: listeners,
		acceptCh:  make(chan acceptResult),
		errCh:     make(chan error),
		doneCh:    make(chan struct{}),
		logger:    logger,
	}
}

// Start starts accepting connections from all listeners
func (m *MultiListenerWrapper) Start() {
	for _, listener := range m.listeners {
		go m.acceptLoop(listener)
	}
}

// acceptLoop accepts connections from a listener
func (m *MultiListenerWrapper) acceptLoop(listener ListenerWrapper) {
	for {
		conn, err := listener.Accept()

		select {
		case <-m.doneCh:
			return
		case m.acceptCh <- acceptResult{conn, err}:
			// Delivered the connection or error
		}

		if err != nil {
			// Stop accepting from this listener if there was an error
			return
		}
	}
}

// Accept accepts a connection from any of the listeners
func (m *MultiListenerWrapper) Accept() (ConnWrapper, error) {
	select {
	case result := <-m.acceptCh:
		return result.conn, result.err
	case <-m.doneCh:
		return nil, net.ErrClosed
	}
}

// Close closes all listeners
func (m *MultiListenerWrapper) Close() error {
	close(m.doneCh)

	var lastErr error
	for _, listener := range m.listeners {
		if err := listener.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}
