package gmcore_transport

import (
	"path/filepath"

	"github.com/gmcorenet/sdk-gmcore-config"
)

func LoadConfig(appPath string) (*FullConfig, error) {
	l := gmcore_config.NewLoader[FullConfig](appPath)
	for _, name := range []string{"transport.yaml", "transport.yml", "server.yaml", "server.yml"} {
		if cfg, err := l.LoadDefault(name); cfg != nil || err != nil {
			return cfg, err
		}
	}
	return nil, nil
}

func (c *FullConfig) ToConfig() Config {
	cfg := Config{
		KeysDir: filepath.Join(filepath.Dir(c.Server.UDS.Path), "keys"),
	}

	switch c.Server.Mode {
	case ModeUDS:
		cfg.Mode = ModeUDS
		cfg.Path = c.Server.UDS.Path
	case ModeTCP:
		cfg.Mode = ModeTCP
		cfg.Host = c.Server.TCP.Host
		cfg.Ports = c.Server.TCP.Ports
	case ModeBoth:
		cfg.Mode = ModeBoth
		cfg.Path = c.Server.UDS.Path
		cfg.Host = c.Server.TCP.Host
		cfg.Ports = c.Server.TCP.Ports
	default:
		cfg.Mode = c.Server.Mode
		cfg.Path = c.Server.UDS.Path
		cfg.Host = c.Server.TCP.Host
		cfg.Ports = c.Server.TCP.Ports
	}

	return cfg
}

func (c *FullConfig) ToSecurityProvider() SecurityProvider {
	switch c.Security.Type {
	case "hmac":
		return NewHMACSecurity([]byte(c.Security.Key))
	case "mutual":
		sec, err := NewMutualSecurity(c.Security.CertDir)
		if err != nil {
			return &NoOpSecurity{}
		}
		return sec
	default:
		return &NoOpSecurity{}
	}
}
