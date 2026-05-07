package gmcore_transport

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	Name     string `json:"name" yaml:"name"`
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Status   string `json:"status,omitempty" yaml:"status"`
	LastSeen int64  `json:"last_seen,omitempty" yaml:"last_seen"`
	Secret   []byte `json:"secret,omitempty" yaml:"-"`
}

type RegistryBackend interface {
	Save(peer Peer) error
	Load(name string) (Peer, error)
	List() ([]Peer, error)
	Delete(name string) error
	Close() error
}

type DiscoveryConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	RegistryAddr string `yaml:"registry_addr" json:"registry_addr"`
	SelfRegister bool   `yaml:"self_register" json:"self_register"`
	Backend      string `yaml:"backend" json:"backend"`
	DBPath       string `yaml:"db_path" json:"db_path"`
	Table        string `yaml:"table" json:"table"`
	RegistryFile string `yaml:"registry_file" json:"registry_file"`
}

type Discovery struct {
	mu      sync.RWMutex
	peers   map[string]Peer
	self    Peer
	backend RegistryBackend
	config  DiscoveryConfig
}

func NewDiscovery(cfg DiscoveryConfig) *Discovery {
	d := &Discovery{peers: make(map[string]Peer), config: cfg}
	if customBackend != nil {
		d.backend = customBackend
	} else {
		d.backend = newBackend(cfg)
	}
	d.loadCache()
	return d
}

var customBackend RegistryBackend

func SetRegistryBackend(b RegistryBackend) { customBackend = b }

func newBackend(cfg DiscoveryConfig) RegistryBackend {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	if backend == "" {
		backend = "sqlite"
	}

	switch backend {
	case "sqlite":
		path := cfg.DBPath
		if path == "" {
			path = "var/data/registry.db"
		}
		return newSQLiteBackend(path)
	case "json":
		path := cfg.RegistryFile
		if path == "" {
			path = "var/data/registry.json"
		}
		return newJSONBackend(path)
	default:
		return newSQLiteBackend("var/data/registry.db")
	}
}

func (d *Discovery) loadCache() {
	peers, _ := d.backend.List()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range peers {
		if p.Name != d.self.Name {
			d.peers[p.Name] = p
		}
	}
}

func (d *Discovery) Register(name, host string, port int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.self = Peer{Name: name, Host: host, Port: port, Status: "online", LastSeen: time.Now().Unix()}
	return d.backend.Save(d.self)
}

func (d *Discovery) Unregister(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.peers, name)
	return d.backend.Delete(name)
}

func (d *Discovery) Discover(name string) (Peer, error) {
	d.mu.RLock()
	if p, ok := d.peers[name]; ok {
		d.mu.RUnlock()
		return p, nil
	}
	d.mu.RUnlock()

	p, err := d.backend.Load(name)
	if err == nil && p.Name != "" {
		d.mu.Lock()
		d.peers[p.Name] = p
		d.mu.Unlock()
		return p, nil
	}
	return Peer{}, fmt.Errorf("peer %q not found", name)
}

func (d *Discovery) Peers() []Peer {
	d.loadCache()
	d.mu.RLock()
	defer d.mu.RUnlock()
	all := make([]Peer, 0, len(d.peers))
	for _, p := range d.peers {
		all = append(all, p)
	}
	return filterPairedPeers(all)
}

func (d *Discovery) Dial(name string) (net.Conn, error) {
	peer, err := d.Discover(name)
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", fmt.Sprintf("%s:%d", peer.Host, peer.Port))
}

func (d *Discovery) Close() error {
	if d.backend != nil {
		return d.backend.Close()
	}
	return nil
}

func MigrateBackend(fromCfg, toCfg DiscoveryConfig) error {
	from := newBackend(fromCfg)
	to := newBackend(toCfg)

	peers, err := from.List()
	if err != nil {
		return fmt.Errorf("failed to read from backend: %w", err)
	}

	for _, p := range peers {
		if err := to.Save(p); err != nil {
			return fmt.Errorf("failed to migrate peer %q: %w", p.Name, err)
		}
	}

	from.Close()
	to.Close()
	return nil
}

type jsonBackend struct {
	mu   sync.Mutex
	path string
}

func newJSONBackend(path string) *jsonBackend {
	os.MkdirAll(filepath.Dir(path), 0700)
	return &jsonBackend{path: path}
}

func (b *jsonBackend) Save(peer Peer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	registry[peer.Name] = peer
	data, _ := json.MarshalIndent(registry, "", "  ")
	return os.WriteFile(b.path, data, 0600)
}

func (b *jsonBackend) Load(name string) (Peer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	if p, ok := registry[name]; ok {
		return p, nil
	}
	return Peer{}, fmt.Errorf("not found")
}

func (b *jsonBackend) List() ([]Peer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	result := make([]Peer, 0, len(registry))
	for _, p := range registry {
		result = append(result, p)
	}
	return result, nil
}

func (b *jsonBackend) Delete(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	delete(registry, name)
	data, _ := json.MarshalIndent(registry, "", "  ")
	return os.WriteFile(b.path, data, 0600)
}

func (b *jsonBackend) Close() error { return nil }

func (b *jsonBackend) readAll() map[string]Peer {
	registry := make(map[string]Peer)
	data, err := os.ReadFile(b.path)
	if err != nil {
		return registry
	}
	json.Unmarshal(data, &registry)
	return registry
}

type sqliteBackend struct {
	mu   sync.Mutex
	path string
}

func newSQLiteBackend(path string) *sqliteBackend {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0700)
	b := &sqliteBackend{path: path}
	b.ensureTable()
	return b
}

func (b *sqliteBackend) ensureTable() {
	data, err := os.ReadFile(b.path)
	if err != nil || len(data) == 0 {
		os.WriteFile(b.path, []byte("[]"), 0600)
	}
}

func (b *sqliteBackend) Save(peer Peer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	registry := b.readAll()
	registry[peer.Name] = peer
	return b.writeAll(registry)
}

func (b *sqliteBackend) Load(name string) (Peer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	if p, ok := registry[name]; ok {
		return p, nil
	}
	return Peer{}, fmt.Errorf("not found")
}

func (b *sqliteBackend) List() ([]Peer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	result := make([]Peer, 0, len(registry))
	for _, p := range registry {
		result = append(result, p)
	}
	return result, nil
}

func (b *sqliteBackend) Delete(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	registry := b.readAll()
	delete(registry, name)
	return b.writeAll(registry)
}

func (b *sqliteBackend) Close() error { return nil }

func (b *sqliteBackend) readAll() map[string]Peer {
	registry := make(map[string]Peer)
	data, err := os.ReadFile(b.path)
	if err != nil {
		return registry
	}
	json.Unmarshal(data, &registry)
	return registry
}

func (b *sqliteBackend) writeAll(registry map[string]Peer) error {
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.path, data, 0600)
}

var _ = strings.TrimSpace

func filterPairedPeers(peers []Peer) []Peer {
	filtered := make([]Peer, 0, len(peers))
	for _, p := range peers {
		if len(p.Secret) > 0 {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
