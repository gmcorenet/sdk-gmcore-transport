package gmcore_transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type TCPServerConfig struct {
	Host  string
	Port  int
	Ports []int
}

type TCPServer struct {
	config    TCPServerConfig
	listeners []net.Listener
	sec       SecurityProvider
	handler   CommandHandler
	mu        sync.RWMutex
	closed    bool
}

func NewTCPServer(cfg TCPServerConfig) *TCPServer {
	return &TCPServer{config: cfg}
}

func (s *TCPServer) UseSecurity(sec SecurityProvider) {
	s.sec = sec
}

func (s *TCPServer) SetHandler(h CommandHandler) {
	s.handler = h
}

func (s *TCPServer) Listen(ctx context.Context) error {
	ports := s.config.Ports
	if len(ports) == 0 && s.config.Port > 0 {
		ports = []int{s.config.Port}
	}
	if len(ports) == 0 {
		ports = []int{8080}
	}

	s.mu.Lock()
	s.listeners = make([]net.Listener, 0, len(ports))
	s.mu.Unlock()

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", s.config.Host, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.Close()
			return fmt.Errorf("failed to listen on TCP %s: %w", addr, err)
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.mu.Unlock()
	}

	return s.serve(ctx)
}

func (s *TCPServer) serve(ctx context.Context) error {
	errCh := make(chan error, len(s.listeners))
	stopCh := make(chan struct{})

	for i, ln := range s.listeners {
		go func(listener net.Listener, idx int) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					s.mu.RLock()
					closed := s.closed
					s.mu.RUnlock()

					if closed {
						return
					}
					select {
					case errCh <- fmt.Errorf("listener %d: %w", idx, err):
					case <-stopCh:
						return
					}
					return
				}
				go s.handleConn(conn)
			}
		}(ln, i)
	}

	select {
	case err := <-errCh:
		close(stopCh)
		return err
	case <-ctx.Done():
		close(stopCh)
		return ctx.Err()
	}
}

func (s *TCPServer) handleConn(conn net.Conn) {
	defer conn.Close()

	if s.sec != nil {
		if err := s.sec.Handshake(conn); err != nil {
			return
		}
	}

	if s.handler != nil {
		s.handleRaw(conn)
	}
}

func (s *TCPServer) handleRaw(conn net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

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

			cmd, payload := decodeCommandPayload("tcp", data)
			resp, err := s.handler(cmd, payload)
			if err != nil {
				conn.Write([]byte(fmt.Sprintf("ERROR: %v", err)))
				continue
			}
			conn.Write(resp)
		}
		if err != nil {
			break
		}
	}
}

func (s *TCPServer) Close() error {
	s.mu.Lock()
	s.closed = true
	listeners := s.listeners
	s.listeners = nil
	s.mu.Unlock()

	var errs []error
	for _, ln := range listeners {
		if err := ln.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing listeners: %v", errs)
	}
	return nil
}

func (s *TCPServer) Addrs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	addrs := make([]string, 0, len(s.listeners))
	for _, ln := range s.listeners {
		if ln != nil {
			addrs = append(addrs, ln.Addr().String())
		}
	}
	return addrs
}

func (s *TCPServer) Addr() string {
	addrs := s.Addrs()
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

type TCPClient struct {
	host string
	port int
	sec  SecurityProvider
	conn net.Conn
	mu   sync.Mutex
}

func NewTCPClient(host string, port int) *TCPClient {
	return &TCPClient{host: host, port: port}
}

func (c *TCPClient) UseSecurity(sec SecurityProvider) {
	c.sec = sec
}

func (c *TCPClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr := net.JoinHostPort(c.host, strconv.Itoa(c.port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to TCP: %w", err)
	}
	c.conn = conn

	if c.sec != nil {
		if err := c.sec.Handshake(c.conn); err != nil {
			c.conn.Close()
			return fmt.Errorf("handshake failed: %w", err)
		}
	}

	return nil
}

func (c *TCPClient) Send(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrNotConnected
	}

	if c.sec != nil && c.sec.Type() != SecurityNone {
		data = append(data, c.sec.Sign(data)...)
	}

	_, err := c.conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 64*1024)
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func (c *TCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *TCPClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func ParseHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}

	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", 0, err
	}

	return host, port, nil
}
