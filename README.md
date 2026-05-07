# gmcore-transport

Unified transport layer for gmcore apps supporting both TCP and Unix Domain Sockets.

## Features

- **Multiple transport modes**: UDS, TCP, or Both
- **Built-in security**: HMAC signature and mutual authentication support
- **Automatic pairing**: App-to-gateway secure pairing
- **Lifecycle commands**: Start, stop, restart, reload, status via UDS
- **Pluggable security**: Use HMAC, certificates, or custom security providers
- **YAML configuration**: Load config from YAML files with env variable support

## Configuration

### YAML Configuration

Create `config/transport.yaml` in your app:

```yaml
server:
  mode: uds  # uds, tcp, or both

  uds:
    path: var/socket/app.sock
    perm: 0660
    group: gmcore
    auto_remove: false

  tcp:
    host: 127.0.0.1
    ports:
      - 8080

security:
  type: hmac  # none, hmac, or mutual
  key: %env(TRANSPORT_SECRET)%
  cert_dir: var/keys  # for mutual auth
```

### Environment Variables

Use `%env(VAR_NAME)%` syntax in YAML to inject environment variables:

```yaml
security:
  key: %env(TRANSPORT_SECRET)%
```

Supported env files:
- `.env`
- `.env.local`
- `config/<appname>.env`

### Loading Config

```go
import "github.com/gmcorenet/sdk/gmcore-transport"

cfg, err := gmcore_transport.LoadConfig("/opt/gmcore/myapp")
if err != nil {
    log.Fatal(err)
}

t := gmcore_transport.New(cfg.ToConfig())
t.UseSecurity(cfg.ToSecurityProvider())
t.Listen(ctx)
```

## Quick Start

### Server (App)

```go
import "github.com/gmcorenet/sdk/gmcore-transport"

// Create app transport
cfg, _ := gmcore_transport.LoadConfig("/opt/gmcore/myapp")

app := gmcore_transport.NewAppTransport("myapp", "/opt/gmcore/myapp")
app.UseSecurity(cfg.ToSecurityProvider())

// Add lifecycle handlers
app.Lifecycle().OnStart(func() error { /* start app */ return nil })
app.Lifecycle().OnStop(func() error { /* stop app */ return nil })
app.Lifecycle().OnRestart(func() error { /* restart app */ return nil })
app.Lifecycle().OnStatus(func() (map[string]any, error) {
    return map[string]any{"status": "running"}, nil
})

// Listen
ctx := context.Background()
app.Listen(ctx, cfg.ToConfig().Mode)
```

### Client (Gateway)

```go
// Connect to app UDS
client := gmcore_transport.NewClient("unix", "/opt/gmcore/myapp/var/socket/myapp.sock")
client.UseSecurity(gmcore_transport.NewHMACSecurity(secret))

if err := client.Connect(); err != nil {
    log.Fatal(err)
}

// Send lifecycle command
resp, err := client.Command("restart", nil)
```

## Configuration Options

### Mode Options

| Mode  | Description                    |
|-------|--------------------------------|
| `uds` | Unix Domain Socket only        |
| `tcp` | TCP/IP only                    |
| `both`| Both UDS and TCP simultaneously |

### TCP Ports

```yaml
tcp:
  host: 0.0.0.0
  ports:
    - 8080
```

For internet edge traffic (`80/443`), expose only the dedicated `gateway` app and route upstream apps through UDS whenever possible.

### Security Types

| Type     | Description                        |
|----------|------------------------------------|
| `none`   | No security (development)           |
| `hmac`   | HMAC-SHA256 signature              |
| `mutual` | Mutual TLS authentication          |

## Lifecycle Commands

| Command   | Description                    |
|-----------|--------------------------------|
| `start`   | Start the application          |
| `stop`    | Stop the application           |
| `restart` | Restart the application        |
| `reload`  | Reload configuration           |
| `status`  | Get application status        |

## Socket Permissions

Default permissions: `0660` (owner and group read/write)

The socket is created in `var/socket/` directory. Gateway must be in the same group as apps to access sockets.

## Directory Structure

```
var/
├── socket/
│   └── app.sock      # UDS socket
└── keys/
    ├── cert.pem      # Certificate
    ├── key.pem       # Private key
    ├── pairing.json  # Gateway pairing info
    └── peers/        # Peer certificates
```
