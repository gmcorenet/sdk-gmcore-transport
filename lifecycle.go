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
	onStart        func() error
	onStop         func() error
	onRestart      func() error
	onStatus       func() (map[string]any, error)
	onReload       func() error
	onPair         func(app string) ([]byte, error)
	onUnpair       func(app string) error
	onPairGenerate func() (string, error)
	onPairAccept   func(code, client string) ([]byte, error)
}

func NewLifecycleHandler() *LifecycleHandler {
	return &LifecycleHandler{}
}

func (h *LifecycleHandler) OnStart(cb func() error)               { h.onStart = cb }
func (h *LifecycleHandler) OnStop(cb func() error)                { h.onStop = cb }
func (h *LifecycleHandler) OnRestart(cb func() error)             { h.onRestart = cb }
func (h *LifecycleHandler) OnStatus(cb func() (map[string]any, error)) { h.onStatus = cb }
func (h *LifecycleHandler) OnReload(cb func() error)              { h.onReload = cb }
func (h *LifecycleHandler) OnPair(cb func(app string) ([]byte, error)) { h.onPair = cb }
func (h *LifecycleHandler) OnUnpair(cb func(app string) error)    { h.onUnpair = cb }
func (h *LifecycleHandler) OnPairGenerate(cb func() (string, error)) { h.onPairGenerate = cb }
func (h *LifecycleHandler) OnPairAccept(cb func(code, client string) ([]byte, error)) { h.onPairAccept = cb }

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

	case "pair":
		if h.onPair == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "pair handler not set"}
		} else {
			appName := ""
			if len(payload) > 0 {
				var cmd LifecycleCommand
				if err := json.Unmarshal(payload, &cmd); err == nil {
					var p struct {
						App string `json:"app"`
					}
					if err := json.Unmarshal(cmd.Payload, &p); err == nil && p.App != "" {
						appName = p.App
					}
				}
			}
			if appName == "" {
				resp = LifecycleResponse{Success: false, Status: "error", Error: "app name required for pair command"}
			} else {
				secret, err := h.onPair(appName)
				if err != nil {
					resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
				} else {
					resp = LifecycleResponse{Success: true, Status: "paired", Data: map[string]any{"secret": string(secret)}}
				}
			}
		}

	case "unpair":
		if h.onUnpair == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "unpair handler not set"}
		} else {
			appName := ""
			if len(payload) > 0 {
				var cmd LifecycleCommand
				if err := json.Unmarshal(payload, &cmd); err == nil {
					var p struct {
						App string `json:"app"`
					}
					if err := json.Unmarshal(cmd.Payload, &p); err == nil && p.App != "" {
						appName = p.App
					}
				}
			}
			if appName == "" {
				resp = LifecycleResponse{Success: false, Status: "error", Error: "app name required for unpair command"}
			} else {
				if err := h.onUnpair(appName); err != nil {
					resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
				} else {
					resp = LifecycleResponse{Success: true, Status: "unpaired"}
				}
			}
		}

	case "pair_generate":
		if h.onPairGenerate == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "pair generate handler not set"}
		} else {
			code, err := h.onPairGenerate()
			if err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "code_generated", Data: map[string]any{"code": code}}
			}
		}

	case "pair_accept":
		if h.onPairAccept == nil {
			resp = LifecycleResponse{Success: false, Status: "error", Error: "pair accept handler not set"}
		} else {
			code := ""
			client := ""
			if len(payload) > 0 {
				var cmd LifecycleCommand
				json.Unmarshal(payload, &cmd)
				if cmd.Payload != nil {
					var p struct {
						Code   string `json:"code"`
						Client string `json:"client"`
					}
					json.Unmarshal(cmd.Payload, &p)
					code = p.Code
					client = p.Client
				}
			}
			secret, err := h.onPairAccept(code, client)
			if err != nil {
				resp = LifecycleResponse{Success: false, Status: "error", Error: err.Error()}
			} else {
				resp = LifecycleResponse{Success: true, Status: "paired", Data: map[string]any{"secret": string(secret)}}
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

func HandleDiscoveryCommand(cmd string, discovery *Discovery) string {
	switch strings.TrimSpace(strings.ToLower(cmd)) {
	case "peers", "discover", "list":
		if discovery == nil {
			return `{"error":"discovery not configured"}`
		}
		peers := discovery.Peers()
		data, _ := json.MarshalIndent(peers, "", "  ")
		return string(data)
	default:
		return fmt.Sprintf(`{"error":"unknown discovery command: %s"}`, cmd)
	}
}
