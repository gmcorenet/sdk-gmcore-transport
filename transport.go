package gmcore_transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	ErrNotConnected    = errors.New("not connected")
	ErrInvalidMessage  = errors.New("invalid message")
	ErrSecurityError   = errors.New("security error")
	ErrHandshakeFailed = errors.New("handshake failed")
)

type Mode string

const (
	ModeUDS  Mode = "uds"
	ModeTCP  Mode = "tcp"
	ModeBoth Mode = "both"
)

type Config struct {
	Mode     Mode   `yaml:"mode" json:"mode"`
	Path     string `yaml:"path" json:"path"`
	Host     string `yaml:"host" json:"host"`
	Ports    []int  `yaml:"ports" json:"ports"`
	KeysDir  string `yaml:"keys_dir" json:"keys_dir"`
	SelfCert bool   `yaml:"self_cert" json:"self_cert"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	CAFile   string `yaml:"ca_file" json:"ca_file"`
}

type SecurityConfig struct {
	Type    string `yaml:"type" json:"type"`         // none, hmac, mutual
	Key     string `yaml:"key" json:"key"`           // for HMAC
	CertDir string `yaml:"cert_dir" json:"cert_dir"` // for mutual
}

type ServerConfig struct {
	Mode     Mode           `yaml:"mode" json:"mode"`
	UDS      UDSConfig      `yaml:"uds" json:"uds"`
	TCP      TCPConfig      `yaml:"tcp" json:"tcp"`
	Security SecurityConfig `yaml:"security" json:"security"`
}

type UDSConfig struct {
	Path       string `yaml:"path" json:"path"`
	Perm       uint32 `yaml:"perm" json:"perm"`
	Group      string `yaml:"group" json:"group"`
	AutoRemove bool   `yaml:"auto_remove" json:"auto_remove"`
}

type TCPConfig struct {
	Host  string `yaml:"host" json:"host"`
	Ports []int  `yaml:"ports" json:"ports"`
}

type FullConfig struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Security SecurityConfig `yaml:"security" json:"security"`
}

type Transport struct {
	config    Config
	server    *Server
	sec       SecurityProvider
	handler   CommandHandler
	discovery *Discovery
	mu        sync.RWMutex
}

func New(cfg Config) *Transport {
	return &Transport{
		config: cfg,
	}
}

func (t *Transport) UseSecurity(s SecurityProvider) {
	t.sec = s
}

func (t *Transport) SetHandler(h CommandHandler) {
	t.handler = h
}

func (t *Transport) WithDiscovery(cfg DiscoveryConfig) *Transport {
	t.discovery = NewDiscovery(cfg)
	return t
}

func (t *Transport) Register(name, host string, port int) error {
	if t.discovery == nil {
		return fmt.Errorf("discovery not configured")
	}
	return t.discovery.Register(name, host, port)
}

func (t *Transport) Discover(name string) (Peer, error) {
	if t.discovery == nil {
		return Peer{}, fmt.Errorf("discovery not configured")
	}
	return t.discovery.Discover(name)
}

func (t *Transport) Peers() []Peer {
	if t.discovery == nil {
		return nil
	}
	return t.discovery.Peers()
}

func (t *Transport) Dial(name string) (net.Conn, error) {
	return t.discovery.Dial(name)
}

func (t *Transport) Listen(ctx context.Context) error {
	if t.sec == nil {
		t.sec = &NoOpSecurity{}
	}

	switch t.config.Mode {
	case ModeUDS:
		return t.listenUDS(ctx)
	case ModeTCP:
		return t.listenTCP(ctx)
	case ModeBoth:
		return t.listenBoth(ctx)
	default:
		return fmt.Errorf("unsupported mode: %s", t.config.Mode)
	}
}

func (t *Transport) listenUDS(ctx context.Context) error {
	ln, err := net.Listen("unix", t.config.Path)
	if err != nil {
		return fmt.Errorf("failed to listen on UDS: %w", err)
	}

	t.server = NewServer(ln, t.sec)
	if t.handler != nil {
		t.server.SetHandler(t.handler)
	}
	return t.server.Serve(ctx)
}

func (t *Transport) listenTCP(ctx context.Context) error {
	tcpServer := NewTCPServer(TCPServerConfig{
		Host:  t.config.Host,
		Ports: t.config.Ports,
	})
	tcpServer.UseSecurity(t.sec)
	if t.handler != nil {
		tcpServer.SetHandler(t.handler)
	} else if t.server != nil {
		tcpServer.SetHandler(t.server.handler)
	}

	errCh := make(chan error, 1)
	stopCh := make(chan struct{})

	go func() {
		if err := tcpServer.Listen(ctx); err != nil {
			select {
			case errCh <- err:
			case <-stopCh:
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		close(stopCh)
		return ctx.Err()
	}
}

func (t *Transport) listenBoth(ctx context.Context) error {
	errCh := make(chan error, 2)
	stopCh := make(chan struct{})

	go func() {
		if err := t.listenUDS(ctx); err != nil {
			select {
			case errCh <- err:
			case <-stopCh:
			}
		}
	}()

	go func() {
		if err := t.listenTCP(ctx); err != nil {
			select {
			case errCh <- err:
			case <-stopCh:
			}
		}
	}()

	select {
	case err := <-errCh:
		close(stopCh)
		return err
	case <-ctx.Done():
		close(stopCh)
		return ctx.Err()
	}
}

func (t *Transport) Close() error {
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}

type SecurityProvider interface {
	Secure(data []byte) ([]byte, error)
	Sign(data []byte) []byte
	Verify(data, sig []byte) bool
	Handshake(conn net.Conn) error
	Type() SecurityType
}

type SecurityType string

const (
	SecurityNone   SecurityType = "none"
	SecurityHMAC   SecurityType = "hmac"
	SecurityMutual SecurityType = "mutual"
)

type NoOpSecurity struct{}

func (s *NoOpSecurity) Secure(data []byte) ([]byte, error) { return data, nil }
func (s *NoOpSecurity) Sign(data []byte) []byte            { return data }
func (s *NoOpSecurity) Verify(data, sig []byte) bool       { return true }
func (s *NoOpSecurity) Handshake(conn net.Conn) error      { return nil }
func (s *NoOpSecurity) Type() SecurityType                 { return SecurityNone }

type HMACSecurity struct {
	key []byte
}

func NewHMACSecurity(key []byte) *HMACSecurity {
	return &HMACSecurity{key: key}
}

func (s *HMACSecurity) Secure(data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	sig := h.Sum(nil)
	return append(data, sig...), nil
}

func (s *HMACSecurity) Verify(data, sig []byte) bool {
	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	expected := h.Sum(nil)
	return hmac.Equal(sig, expected)
}

func (s *HMACSecurity) Handshake(conn net.Conn) error {
	return nil
}

func (s *HMACSecurity) Type() SecurityType {
	return SecurityHMAC
}

func (s *HMACSecurity) Sign(data []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	return h.Sum(nil)
}

type Message struct {
	Type      string            `json:"type"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      []byte            `json:"body"`
	Timestamp int64             `json:"timestamp"`
}

type CommandHandler func(cmd string, payload []byte) ([]byte, error)

type Server struct {
	listener    net.Listener
	sec         SecurityProvider
	handler     CommandHandler
	httpHandler http.Handler
	mu          sync.RWMutex
	conns       map[net.Conn]bool
	done        chan struct{}
}

func NewServer(ln net.Listener, security SecurityProvider) *Server {
	return &Server{
		listener: ln,
		sec:      security,
		conns:    make(map[net.Conn]bool),
		done:     make(chan struct{}),
	}
}

func (s *Server) SetHandler(h CommandHandler) {
	s.handler = h
}

func (s *Server) SetHTTPHandler(h http.Handler) {
	s.httpHandler = h
}

func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}

		s.mu.Lock()
		s.conns[conn] = true
		s.mu.Unlock()

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	if s.sec != nil {
		if err := s.sec.Handshake(conn); err != nil {
			return
		}
	}

	if s.httpHandler != nil {
		s.handleHTTP(conn)
		return
	}

	s.handleRaw(conn)
}

func (s *Server) handleHTTP(conn net.Conn) {
	s.httpHandler.ServeHTTP(
		&HijackedResponseWriter{conn: conn},
		&http.Request{},
	)
}

func (s *Server) handleRaw(conn net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data := buf[:n]
			if s.sec != nil && s.sec.Type() != SecurityNone {
				if len(data) < 32 {
					continue
				}
				payload := data[:len(data)-32]
				sig := data[len(data)-32:]
				if !s.sec.Verify(payload, sig) {
					conn.Write([]byte("SECURITY_ERROR"))
					continue
				}
				data = payload
			}

			if s.handler != nil {
				cmd, payload := decodeCommandPayload("raw", data)
				resp, err := s.handler(cmd, payload)
				if err != nil {
					conn.Write([]byte(fmt.Sprintf("ERROR: %v", err)))
					continue
				}
				conn.Write(resp)
			}
		}
		if err != nil {
			break
		}
	}
}

func decodeCommandPayload(defaultCmd string, data []byte) (string, []byte) {
	if len(data) == 0 {
		return defaultCmd, data
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err == nil && msg.Type != "" {
		if msg.Body == nil {
			return msg.Type, []byte{}
		}
		return msg.Type, msg.Body
	}

	return defaultCmd, data
}

func (s *Server) Close() error {
	close(s.done)
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for conn := range s.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.conns = nil

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}
	return s.listener.Close()
}

type HijackedResponseWriter struct {
	conn net.Conn
}

func (w *HijackedResponseWriter) Header() http.Header {
	return make(http.Header)
}

func (w *HijackedResponseWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *HijackedResponseWriter) WriteHeader(int) {}

type Client struct {
	addr    string
	network string
	sec     SecurityProvider
	conn    net.Conn
	mu      sync.Mutex
}

func NewClient(network, addr string) *Client {
	return &Client{
		network: network,
		addr:    addr,
	}
}

func (c *Client) UseSecurity(s SecurityProvider) {
	c.sec = s
}

func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	c.conn, err = net.Dial(c.network, c.addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if c.sec != nil {
		if err := c.sec.Handshake(c.conn); err != nil {
			c.conn.Close()
			return fmt.Errorf("handshake failed: %w", err)
		}
	}

	return nil
}

func (c *Client) Command(cmd string, payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNotConnected
	}

	msg := Message{
		Type:      cmd,
		Body:      payload,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	if c.sec != nil && c.sec.Type() != SecurityNone {
		data = append(data, c.sec.Sign(data)...)
	}

	_, err = c.conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 64*1024)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func (c *Client) Request(method, path string, headers map[string]string, body []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNotConnected
	}

	msg := Message{
		Type:    method,
		Path:    path,
		Headers: headers,
		Body:    body,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	_, err = c.conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 64*1024)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}
