package gmcore_transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
)

type LifecycleCommand struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type LifecycleResponse struct {
	Success bool           `json:"success"`
	Status  string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

type LifecycleHandler struct {
	onStart   func() error
	onStop    func() error
	onRestart func() error
	onStatus  func() (map[string]any, error)
	onReload  func() error
}

func NewLifecycleHandler() *LifecycleHandler {
	return &LifecycleHandler{}
}

func (h *LifecycleHandler) OnStart(cb func() error) {
	h.onStart = cb
}

func (h *LifecycleHandler) OnStop(cb func() error) {
	h.onStop = cb
}

func (h *LifecycleHandler) OnRestart(cb func() error) {
	h.onRestart = cb
}

func (h *LifecycleHandler) OnStatus(cb func() (map[string]any, error)) {
	h.onStatus = cb
}

func (h *LifecycleHandler) OnReload(cb func() error) {
	h.onReload = cb
}

func (h *LifecycleHandler) Handle(cmd string, payload []byte) ([]byte, error) {
	action := strings.TrimSpace(cmd)
	if len(payload) > 0 {
		var req LifecycleCommand
		if err := json.Unmarshal(payload, &req); err == nil && strings.TrimSpace(req.Action) != "" {
			action = strings.TrimSpace(req.Action)
		}
	}

	var resp LifecycleResponse

	switch action {
	case "start":
		if h.onStart == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "start handler not set"}
		} else {
			if err := h.onStart(); err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "started"}
			}
		}

	case "stop":
		if h.onStop == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "stop handler not set"}
		} else {
			if err := h.onStop(); err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "stopped"}
			}
		}

	case "restart":
		if h.onRestart == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "restart handler not set"}
		} else {
			if err := h.onRestart(); err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "restarted"}
			}
		}

	case "reload":
		if h.onReload == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "reload handler not set"}
		} else {
			if err := h.onReload(); err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "reloaded"}
			}
		}

	case "status":
		if h.onStatus == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "status handler not set"}
		} else {
			data, err := h.onStatus()
			if err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "ok", Data: data}
			}
		}

	default:
		resp = LifecycleResponse{Success: false, Status: "error", Error: fmt.Sprintf("unknown action: %s", action)}
	}

	return json.Marshal(resp)
}

type AppTransport struct {
	appName   string
	appPath   string
	transport *Transport
	lifecycle *LifecycleHandler
	sec       SecurityProvider
}

func NewAppTransport(appName, appPath string) *AppTransport {
	return &AppTransport{
		appName:   appName,
		appPath:   appPath,
		lifecycle: NewLifecycleHandler(),
	}
}

func (a *AppTransport) UseSecurity(sec SecurityProvider) {
	a.sec = sec
}

func (a *AppTransport) Lifecycle() *LifecycleHandler {
	return a.lifecycle
}

func (a *AppTransport) Listen(ctx context.Context, mode Mode) error {
	socketPath := filepath.Join(a.appPath, "var", "socket", a.appName+".sock")

	cfg := Config{
		Mode:    mode,
		Path:    socketPath,
		KeysDir: filepath.Join(a.appPath, "var", "keys"),
	}

	a.transport = New(cfg)

	if a.sec != nil {
		a.transport.UseSecurity(a.sec)
	}
	a.transport.SetHandler(func(cmd string, payload []byte) ([]byte, error) {
		return a.lifecycle.Handle(cmd, payload)
	})

	return a.transport.Listen(ctx)
}

func (a *AppTransport) Close() error {
	if a.transport != nil {
		return a.transport.Close()
	}
	return nil
}

type GatewayTransport struct {
	gatewayID string
	listener  net.Listener
	sec       SecurityProvider
	pairing   *GatewayPairingHandler
	apps      map[string]*AppConnection
	mu        sync.RWMutex
}

type AppConnection struct {
	AppID      string
	SocketPath string
	Secret     []byte
	Client     *Client
}

func NewGatewayTransport(gatewayID string) *GatewayTransport {
	return &GatewayTransport{
		gatewayID: gatewayID,
		pairing:   NewGatewayPairingHandler(),
		apps:      make(map[string]*AppConnection),
	}
}

func (g *GatewayTransport) UseSecurity(sec SecurityProvider) {
	g.sec = sec
}

func (g *GatewayTransport) StartPairing(ctx context.Context) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":9090"))
	if err != nil {
		return err
	}
	g.listener = ln

	go func() {
		for {
			conn, err := g.listener.Accept()
			if err != nil {
				return
			}
			go g.handlePairing(conn)
		}
	}()

	return nil
}

func (g *GatewayTransport) handlePairing(conn net.Conn) {
	defer conn.Close()

	if err := g.pairing.HandlePairing(conn); err != nil {
		return
	}
}

func (g *GatewayTransport) ConnectApp(appID, socketPath string, secret []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	sec := &HMACSecurity{key: secret}
	client := NewClient("unix", socketPath)
	client.UseSecurity(sec)

	if err := client.Connect(); err != nil {
		return err
	}

	g.apps[appID] = &AppConnection{
		AppID:      appID,
		SocketPath: socketPath,
		Secret:     secret,
		Client:     client,
	}

	return nil
}

func (g *GatewayTransport) SendCommand(appID, action string, payload []byte) ([]byte, error) {
	g.mu.RLock()
	app, exists := g.apps[appID]
	g.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("app not connected: %s", appID)
	}

	return app.Client.Command(action, payload)
}

func (g *GatewayTransport) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, app := range g.apps {
		app.Client.Close()
	}

	if g.listener != nil {
		g.listener.Close()
	}

	return nil
}
