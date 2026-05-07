package gmcore_transport

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	ErrAlreadyPaired    = errors.New("already paired")
	ErrNotPaired        = errors.New("not paired with gateway")
	ErrPairingRejected  = errors.New("pairing rejected")
	ErrInvalidPairingID = errors.New("invalid pairing ID")
	ErrNotPreApproved   = errors.New("app not pre-approved in strict mode")
)

type PairingMode string

const (
	PairingStrict  PairingMode = "strict"
	PairingTrusted PairingMode = "trusted"
	PairingOpen    PairingMode = "open"
)

const (
	PairingPort    = 9090
	PairingTimeout = 30 * time.Second
)

type PairingInfo struct {
	AppID       string `json:"app_id"`
	GatewayID   string `json:"gateway_id"`
	GatewayAddr string `json:"gateway_addr"`
	SocketPath  string `json:"socket_path"`
	Secret      []byte `json:"secret"`
	PairedAt    int64  `json:"paired_at"`
}

type PairingRequest struct {
	Type      string `json:"type"`
	AppID     string `json:"app_id"`
	AppName   string `json:"app_name"`
	SocketPath string `json:"socket_path"`
	CertPEM   string `json:"cert_pem,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type PairingResponse struct {
	Type      string `json:"type"`
	Accepted  bool   `json:"accepted"`
	GatewayID string `json:"gateway_id"`
	Secret    []byte `json:"secret,omitempty"`
	Error     string `json:"error,omitempty"`
}

type PairingManager struct {
	appID    string
	appName  string
	keysDir  string
	info     *PairingInfo
	mu       sync.RWMutex
}

func NewPairingManager(appID, appName, keysDir string) *PairingManager {
	return &PairingManager{
		appID:   appID,
		appName: appName,
		keysDir: keysDir,
	}
}

func (p *PairingManager) Load() error {
	infoPath := filepath.Join(p.keysDir, "pairing.json")

	data, err := os.ReadFile(infoPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotPaired
		}
		return err
	}

	var info PairingInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	p.mu.Lock()
	p.info = &info
	p.mu.Unlock()

	return nil
}

func (p *PairingManager) Save() error {
	p.mu.RLock()
	info := p.info
	p.mu.RUnlock()

	if info == nil {
		return ErrNotPaired
	}

	infoPath := filepath.Join(p.keysDir, "pairing.json")

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return os.WriteFile(infoPath, data, 0600)
}

func (p *PairingManager) IsPaired() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.info != nil
}

func (p *PairingManager) GetInfo() *PairingInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.info == nil {
		return nil
	}

	infoCopy := *p.info
	return &infoCopy
}

func (p *PairingManager) RequestPairing(gatewayHost string) error {
	if p.IsPaired() {
		return ErrAlreadyPaired
	}

	addr := net.JoinHostPort(gatewayHost, strconv.Itoa(PairingPort))
	conn, err := net.DialTimeout("tcp", addr, PairingTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to gateway: %w", err)
	}
	defer conn.Close()

	socketPath := filepath.Join(p.keysDir, "..", "socket", p.appName+".sock")

	req := PairingRequest{
		Type:       "pairing_request",
		AppID:      p.appID,
		AppName:    p.appName,
		SocketPath: socketPath,
		Timestamp:  time.Now().Unix(),
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send pairing request: %w", err)
	}

	respData := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(PairingTimeout))
	n, err := conn.Read(respData)
	if err != nil {
		return fmt.Errorf("failed to read pairing response: %w", err)
	}

	var resp PairingResponse
	if err := json.Unmarshal(respData[:n], &resp); err != nil {
		return fmt.Errorf("failed to parse pairing response: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("%w: %s", ErrPairingRejected, resp.Error)
	}

	p.mu.Lock()
	p.info = &PairingInfo{
		AppID:       p.appID,
		GatewayID:   resp.GatewayID,
		GatewayAddr: gatewayHost,
		SocketPath:  socketPath,
		Secret:      resp.Secret,
		PairedAt:    time.Now().Unix(),
	}
	p.mu.Unlock()

	return p.Save()
}

func (p *PairingManager) Unpair() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.info = nil

	infoPath := filepath.Join(p.keysDir, "pairing.json")
	os.Remove(infoPath)

	return nil
}

type GatewayPairingHandler struct {
	apps        map[string]*PairingInfo
	preApproved map[string][]byte
	mode        PairingMode
	mu          sync.RWMutex
	gatewayID   string
	onPaired    func(appID, socketPath string, secret []byte) error
	onUnpaired  func(appID string)
}

func NewGatewayPairingHandler() *GatewayPairingHandler {
	id := generateGatewayID()
	return &GatewayPairingHandler{
		apps:        make(map[string]*PairingInfo),
		preApproved: make(map[string][]byte),
		mode:        PairingStrict,
		gatewayID:   id,
	}
}

func (h *GatewayPairingHandler) SetMode(mode PairingMode) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mode = mode
}

func (h *GatewayPairingHandler) Mode() PairingMode {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.mode
}

func generateGatewayID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("gateway-%x", b)
}

func (h *GatewayPairingHandler) OnPaired(cb func(appID, socketPath string, secret []byte) error) {
	h.onPaired = cb
}

func (h *GatewayPairingHandler) OnUnpaired(cb func(appID string)) {
	h.onUnpaired = cb
}

func (h *GatewayPairingHandler) PreApprove(appID string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.preApproved[appID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrAlreadyPaired, appID)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	h.preApproved[appID] = secret
	return secret, nil
}

func (h *GatewayPairingHandler) RevokePreApproval(appID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.preApproved[appID]; !exists {
		return fmt.Errorf("%w: %s", ErrNotPreApproved, appID)
	}

	delete(h.preApproved, appID)
	delete(h.apps, appID)

	if h.onUnpaired != nil {
		h.onUnpaired(appID)
	}

	return nil
}

func (h *GatewayPairingHandler) IsPreApproved(appID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.preApproved[appID]
	return ok
}

func (h *GatewayPairingHandler) HandlePairing(conn net.Conn) error {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	var req PairingRequest
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		return err
	}

	h.mu.Lock()
	existing, exists := h.apps[req.AppID]
	h.mu.Unlock()

	if exists {
		resp := PairingResponse{
			Type:      "pairing_response",
			Accepted:  true,
			GatewayID: h.gatewayID,
			Secret:    existing.Secret,
		}
		data, _ := json.Marshal(resp)
		conn.Write(data)
		return nil
	}

	accepted, rejectReason := h.shouldAcceptPairing(req, conn)
	if !accepted {
		resp := PairingResponse{
			Type:     "pairing_response",
			Accepted: false,
			Error:    rejectReason,
		}
		data, _ := json.Marshal(resp)
		conn.Write(data)
		return fmt.Errorf("%w: %s", ErrPairingRejected, rejectReason)
	}

	var secret []byte
	h.mu.RLock()
	if preSecret, ok := h.preApproved[req.AppID]; ok {
		secret = make([]byte, len(preSecret))
		copy(secret, preSecret)
	} else {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			h.mu.RUnlock()
			return err
		}
	}
	h.mu.RUnlock()

	info := &PairingInfo{
		AppID:      req.AppID,
		GatewayID:  h.gatewayID,
		SocketPath: req.SocketPath,
		Secret:     secret,
		PairedAt:   time.Now().Unix(),
	}

	h.mu.Lock()
	h.apps[req.AppID] = info
	h.mu.Unlock()

	if h.onPaired != nil {
		if err := h.onPaired(req.AppID, req.SocketPath, secret); err != nil {
			resp := PairingResponse{
				Type:    "pairing_response",
				Accepted: false,
				Error:   err.Error(),
			}
			data, _ := json.Marshal(resp)
			conn.Write(data)
			return err
		}
	}

	resp := PairingResponse{
		Type:      "pairing_response",
		Accepted:  true,
		GatewayID: h.gatewayID,
		Secret:    secret,
	}
	data, _ := json.Marshal(resp)
	conn.Write(data)

	return nil
}

func (h *GatewayPairingHandler) shouldAcceptPairing(req PairingRequest, conn net.Conn) (bool, string) {
	h.mu.RLock()
	mode := h.mode
	_, preApproved := h.preApproved[req.AppID]
	h.mu.RUnlock()

	switch mode {
	case PairingOpen:
		return true, ""

	case PairingTrusted:
		if isLocalConnection(conn) {
			return true, ""
		}
		if preApproved {
			return true, ""
		}
		return false, fmt.Sprintf("app %q not in trusted network (mode: trusted)", req.AppID)

	case PairingStrict:
		if preApproved {
			return true, ""
		}
		return false, fmt.Sprintf("app %q must be pre-approved via 'gmcore app pair %s'", req.AppID, req.AppName)

	default:
		return false, fmt.Sprintf("unknown pairing mode: %s", mode)
	}
}

func isLocalConnection(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return false
	}

	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	case *net.UnixAddr:
		return true
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		return ip.IsLoopback()
	}
}

func (h *GatewayPairingHandler) GetPairedApps() map[string]*PairingInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make(map[string]*PairingInfo)
	for k, v := range h.apps {
		result[k] = v
	}
	return result
}

func (h *GatewayPairingHandler) UnpairApp(appID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.apps[appID]; !exists {
		return ErrNotPaired
	}

	delete(h.apps, appID)

	if h.onUnpaired != nil {
		h.onUnpaired(appID)
	}

	return nil
}
