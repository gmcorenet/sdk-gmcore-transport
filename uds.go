package gmcore_transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type UDSServerConfig struct {
	Path       string
	Perm       uint32
	Group      string
	AutoRemove bool
}

type UDSServer struct {
	config  UDSServerConfig
	ln      net.Listener
	sec     SecurityProvider
	handler CommandHandler
	mu      sync.RWMutex
	closed  bool
}

func NewUDSServer(cfg UDSServerConfig) *UDSServer {
	return &UDSServer{
		config: cfg,
	}
}

func (s *UDSServer) UseSecurity(sec SecurityProvider) {
	s.sec = sec
}

func (s *UDSServer) SetHandler(h CommandHandler) {
	s.handler = h
}

func (s *UDSServer) Listen(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.config.Path), 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	if err := os.Remove(s.config.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	ln, err := net.Listen("unix", s.config.Path)
	if err != nil {
		return fmt.Errorf("failed to listen on UDS: %w", err)
	}
	s.ln = ln

	if err := os.Chmod(s.config.Path, os.FileMode(s.config.Perm)); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	if s.config.Group != "" {
		if err := setSocketGroup(s.config.Path, s.config.Group); err != nil {
			fmt.Printf("Warning: failed to set socket group: %v\n", err)
		}
	}

	return s.serve(ctx)
}

func (s *UDSServer) serve(ctx context.Context) error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()

			if closed {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}

		go s.handleConn(conn)
	}
}

func (s *UDSServer) handleConn(conn net.Conn) {
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

func (s *UDSServer) handleRaw(conn net.Conn) {
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

			cmd, payload := decodeCommandPayload("uds", data)
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

func (s *UDSServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.ln != nil {
		if err := s.ln.Close(); err != nil {
			return err
		}
	}

	if s.config.AutoRemove {
		os.Remove(s.config.Path)
	}

	return nil
}

type UDSClient struct {
	path string
	sec  SecurityProvider
	conn net.Conn
	mu   sync.Mutex
}

func NewUDSClient(path string) *UDSClient {
	return &UDSClient{path: path}
}

func (c *UDSClient) UseSecurity(sec SecurityProvider) {
	c.sec = sec
}

func (c *UDSClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.Dial("unix", c.path)
	if err != nil {
		return fmt.Errorf("failed to connect to UDS: %w", err)
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

func (c *UDSClient) Send(data []byte) ([]byte, error) {
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

func (c *UDSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *UDSClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func setSocketGroup(socketPath, group string) error {
	if group == "" {
		return nil
	}
	stat, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %w", err)
	}
	sys := stat.Sys()
	if sys == nil {
		return fmt.Errorf("platform not supported for setting socket group")
	}
	gr, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("failed to find group %s: %w", group, err)
	}
	gid, err := strconv.Atoi(gr.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse group id %s: %w", gr.Gid, err)
	}
	return os.Chown(socketPath, -1, gid)
}

func EnsureSocketDir(socketDir string) error {
	return os.MkdirAll(socketDir, 0755)
}

func DefaultSocketPerms() uint32 {
	return 0660
}
