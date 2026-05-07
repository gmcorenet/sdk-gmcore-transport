package gmcore_transport

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewTransport(t *testing.T) {
	cfg := Config{Mode: ModeTCP, Host: "localhost", Ports: []int{8080}}
	tp := New(cfg)
	if tp == nil {
		t.Fatal("expected non-nil transport")
	}
	if tp.config.Mode != ModeTCP {
		t.Errorf("expected ModeTCP, got %s", tp.config.Mode)
	}
}

func TestTransport_UseSecurity(t *testing.T) {
	cfg := Config{Mode: ModeTCP}
	tp := New(cfg)
	sec := &NoOpSecurity{}
	tp.UseSecurity(sec)
	if tp.sec != sec {
		t.Error("security should be set")
	}
}

func TestTransport_Listen_TCP_NilHandlerPanic(t *testing.T) {
	cfg := Config{Mode: ModeTCP, Host: "localhost", Ports: []int{18080}}
	tp := New(cfg)
	tp.UseSecurity(&NoOpSecurity{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := tp.Listen(ctx)
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTransport_Listen_UnsupportedMode(t *testing.T) {
	cfg := Config{Mode: Mode("invalid")}
	tp := New(cfg)
	err := tp.Listen(context.Background())
	if err == nil {
		t.Error("expected error for unsupported mode")
	}
}

func TestTransport_Close(t *testing.T) {
	cfg := Config{Mode: ModeTCP}
	tp := New(cfg)
	err := tp.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewServer(t *testing.T) {
	ln, err := listenDummyUnixSocket("/tmp/test_transport.sock")
	if err != nil {
		t.Skipf("skipping: could not create test socket: %v", err)
	}
	defer ln.Close()

	s := NewServer(ln, &NoOpSecurity{})
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if len(s.conns) != 0 {
		t.Error("expected empty conns map")
	}
}

func TestServer_SetHandler(t *testing.T) {
	ln, _ := listenDummyUnixSocket("/tmp/test_transport2.sock")
	defer ln.Close()

	s := NewServer(ln, &NoOpSecurity{})
	handler := func(cmd string, payload []byte) ([]byte, error) {
		return []byte("pong"), nil
	}
	s.SetHandler(handler)
	if s.handler == nil {
		t.Error("handler should be set")
	}
}

func TestServer_SetHTTPHandler(t *testing.T) {
	ln, _ := listenDummyUnixSocket("/tmp/test_transport3.sock")
	defer ln.Close()

	s := NewServer(ln, &NoOpSecurity{})
	s.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if s.httpHandler == nil {
		t.Error("httpHandler should be set")
	}
}

func TestServer_Close(t *testing.T) {
	ln, _ := listenDummyUnixSocket("/tmp/test_transport4.sock")
	s := NewServer(ln, &NoOpSecurity{})

	err := s.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoOpSecurity(t *testing.T) {
	s := &NoOpSecurity{}
	data := []byte("hello")
	secured, err := s.Secure(data)
	if err != nil {
		t.Errorf("Secure failed: %v", err)
	}
	if len(secured) == 0 {
		t.Error("expected non-empty secured data")
	}

	signed := s.Sign(data)
	if len(signed) == 0 {
		t.Error("expected non-empty signed data")
	}

	if !s.Verify(data, signed) {
		t.Error("Verify should return true")
	}

	if s.Type() != SecurityNone {
		t.Errorf("expected SecurityNone, got %s", s.Type())
	}

	if s.Handshake(nil) != nil {
		t.Error("Handshake should return nil")
	}
}

func TestHMACSecurity(t *testing.T) {
	key := []byte("test-secret-key-12345678901234567890")
	s := NewHMACSecurity(key)

	data := []byte("hello world")
	secured, err := s.Secure(data)
	if err != nil {
		t.Fatalf("Secure failed: %v", err)
	}
	if len(secured) <= len(data) {
		t.Error("secured data should be longer than original")
	}

	signed := s.Sign(data)
	if len(signed) == 0 {
		t.Error("expected non-empty signed data")
	}

	if !s.Verify(data, signed) {
		t.Error("Verify should return true")
	}
	if s.Verify([]byte("wrong"), signed) {
		t.Error("Verify should return false for wrong data")
	}

	if s.Type() != SecurityHMAC {
		t.Errorf("expected SecurityHMAC, got %s", s.Type())
	}
}

func TestNewTCPServer(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18081}}
	s := NewTCPServer(cfg)
	if s == nil {
		t.Fatal("expected non-nil TCPServer")
	}
}

func TestTCPServer_SetHandler(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18082}}
	s := NewTCPServer(cfg)
	handler := func(cmd string, payload []byte) ([]byte, error) {
		return []byte("pong"), nil
	}
	s.SetHandler(handler)
	if s.handler == nil {
		t.Error("handler should be set")
	}
}

func TestTCPServer_UseSecurity(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18083}}
	s := NewTCPServer(cfg)
	sec := &NoOpSecurity{}
	s.UseSecurity(sec)
	if s.sec != sec {
		t.Error("security should be set")
	}
}

func TestTCPServer_Listen_DefaultPort(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Port: 18084}
	s := NewTCPServer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Listen(ctx)
	if err == nil {
		s.Close()
		t.Error("expected error when no ports available")
	}
}

func TestTCPServer_Close(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18085}}
	s := NewTCPServer(cfg)
	s.Close()
}

func TestTCPServer_Addrs(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18086}}
	s := NewTCPServer(cfg)
	addrs := s.Addrs()
	if len(addrs) != 0 {
		t.Error("expected empty addrs before Listen")
	}
}

func TestTCPServer_Addr(t *testing.T) {
	cfg := TCPServerConfig{Host: "localhost", Ports: []int{18087}}
	s := NewTCPServer(cfg)
	addr := s.Addr()
	if addr != "" {
		t.Error("expected empty addr before Listen")
	}
}

func TestNewTCPClient(t *testing.T) {
	c := NewTCPClient("localhost", 8080)
	if c == nil {
		t.Fatal("expected non-nil TCPClient")
	}
}

func TestTCPClient_UseSecurity(t *testing.T) {
	c := NewTCPClient("localhost", 8080)
	sec := &NoOpSecurity{}
	c.UseSecurity(sec)
	if c.sec != sec {
		t.Error("security should be set")
	}
}

func TestTCPClient_IsConnected(t *testing.T) {
	c := NewTCPClient("localhost", 8080)
	if c.IsConnected() {
		t.Error("should not be connected initially")
	}
}

func TestTCPClient_Connect_NotConnected(t *testing.T) {
	c := NewTCPClient("localhost", 65535)
	err := c.Connect()
	if err == nil {
		c.Close()
		t.Error("expected error connecting to non-existent port")
	}
}

func TestTCPClient_Send_NotConnected(t *testing.T) {
	c := NewTCPClient("localhost", 65535)
	_, err := c.Send([]byte("test"))
	if err == nil {
		t.Error("expected error when not connected")
	}
}

func TestTCPClient_Close(t *testing.T) {
	c := NewTCPClient("localhost", 8080)
	c.Close()
}

func TestNewUDSClient(t *testing.T) {
	c := NewUDSClient("/tmp/test.sock")
	if c == nil {
		t.Fatal("expected non-nil UDSClient")
	}
}

func TestUDSClient_UseSecurity(t *testing.T) {
	c := NewUDSClient("/tmp/test.sock")
	sec := &NoOpSecurity{}
	c.UseSecurity(sec)
	if c.sec != sec {
		t.Error("security should be set")
	}
}

func TestUDSClient_IsConnected(t *testing.T) {
	c := NewUDSClient("/tmp/test.sock")
	if c.IsConnected() {
		t.Error("should not be connected initially")
	}
}

func TestUDSClient_Connect_NotFound(t *testing.T) {
	c := NewUDSClient("/tmp/nonexistent.sock")
	err := c.Connect()
	if err == nil {
		c.Close()
		t.Error("expected error connecting to non-existent socket")
	}
}

func TestUDSClient_Send_NotConnected(t *testing.T) {
	c := NewUDSClient("/tmp/nonexistent.sock")
	_, err := c.Send([]byte("test"))
	if err == nil {
		t.Error("expected error when not connected")
	}
}

func TestUDSClient_Close(t *testing.T) {
	c := NewUDSClient("/tmp/test.sock")
	c.Close()
}

func TestParseHostPort(t *testing.T) {
	host, port, err := ParseHostPort("localhost:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "localhost" {
		t.Errorf("expected localhost, got %s", host)
	}
	if port != 8080 {
		t.Errorf("expected 8080, got %d", port)
	}
}

func TestParseHostPort_Invalid(t *testing.T) {
	_, _, err := ParseHostPort("invalid")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewUDSServer(t *testing.T) {
	cfg := UDSServerConfig{Path: "/tmp/test_server.sock", Perm: 0660}
	s := NewUDSServer(cfg)
	if s == nil {
		t.Fatal("expected non-nil UDSServer")
	}
}

func TestUDSServer_SetHandler(t *testing.T) {
	cfg := UDSServerConfig{Path: "/tmp/test_server2.sock"}
	s := NewUDSServer(cfg)
	handler := func(cmd string, payload []byte) ([]byte, error) {
		return []byte("pong"), nil
	}
	s.SetHandler(handler)
	if s.handler == nil {
		t.Error("handler should be set")
	}
}

func TestUDSServer_UseSecurity(t *testing.T) {
	cfg := UDSServerConfig{Path: "/tmp/test_server3.sock"}
	s := NewUDSServer(cfg)
	sec := &NoOpSecurity{}
	s.UseSecurity(sec)
	if s.sec != sec {
		t.Error("security should be set")
	}
}

func TestUDSServer_Close(t *testing.T) {
	cfg := UDSServerConfig{Path: "/tmp/test_server4.sock"}
	s := NewUDSServer(cfg)
	s.Close()
}

func TestEnsureSocketDir(t *testing.T) {
	err := EnsureSocketDir("/tmp/test_socket_dir")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDefaultSocketPerms(t *testing.T) {
	perms := DefaultSocketPerms()
	if perms != 0660 {
		t.Errorf("expected 0660, got %o", perms)
	}
}

func TestHijackedResponseWriter_Header(t *testing.T) {
	w := &HijackedResponseWriter{}
	if w.Header() == nil {
		t.Error("Header should not be nil")
	}
}

func TestClient_NewClient(t *testing.T) {
	c := NewClient("tcp", "localhost:8080")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClient_IsConnected(t *testing.T) {
	c := NewClient("tcp", "localhost:8080")
	if c.IsConnected() {
		t.Error("should not be connected initially")
	}
}

func TestClient_Connect_NotFound(t *testing.T) {
	c := NewClient("tcp", "localhost:65535")
	err := c.Connect()
	if err == nil {
		c.Close()
		t.Error("expected error")
	}
}

func TestClient_Close(t *testing.T) {
	c := NewClient("tcp", "localhost:8080")
	c.Close()
}

func TestErrorConstants(t *testing.T) {
	if ErrNotConnected.Error() != "not connected" {
		t.Errorf("unexpected: %s", ErrNotConnected.Error())
	}
	if ErrInvalidMessage.Error() != "invalid message" {
		t.Errorf("unexpected: %s", ErrInvalidMessage.Error())
	}
	if ErrSecurityError.Error() != "security error" {
		t.Errorf("unexpected: %s", ErrSecurityError.Error())
	}
	if ErrHandshakeFailed.Error() != "handshake failed" {
		t.Errorf("unexpected: %s", ErrHandshakeFailed.Error())
	}
}

func listenDummyUnixSocket(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
