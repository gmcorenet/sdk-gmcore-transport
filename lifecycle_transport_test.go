package gmcore_transport

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodeCommandPayload_Message(t *testing.T) {
	body := []byte(`{"force":true}`)
	msg := Message{Type: "reload", Body: body, Timestamp: time.Now().Unix()}
	encoded, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cmd, payload := decodeCommandPayload("raw", encoded)
	if cmd != "reload" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
	if string(payload) != string(body) {
		t.Fatalf("unexpected payload: %s", string(payload))
	}
}

func TestDecodeCommandPayload_RawFallback(t *testing.T) {
	raw := []byte("plain-text")
	cmd, payload := decodeCommandPayload("raw", raw)
	if cmd != "raw" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
	if string(payload) != "plain-text" {
		t.Fatalf("unexpected payload: %s", string(payload))
	}
}

func TestLifecycleHandler_Handle_UsesCommand(t *testing.T) {
	h := NewLifecycleHandler()
	called := false
	h.OnReload(func() error {
		called = true
		return nil
	})

	resp, err := h.Handle("reload", nil)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !called {
		t.Fatalf("expected reload callback")
	}

	var decoded LifecycleResponse
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !decoded.Success || decoded.Status != "reloaded" {
		t.Fatalf("unexpected response: %+v", decoded)
	}
}

func TestServer_HandleRaw_DecodesMessageType(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "transport.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := NewServer(ln, &NoOpSecurity{})
	called := false
	s.SetHandler(func(cmd string, payload []byte) ([]byte, error) {
		called = true
		if cmd != "reload" {
			t.Fatalf("unexpected cmd %s", cmd)
		}
		if string(payload) != `{"force":true}` {
			t.Fatalf("unexpected payload %s", string(payload))
		}
		return []byte("ok"), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx)
		close(done)
	}()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	msg := Message{Type: "reload", Body: []byte(`{"force":true}`), Timestamp: time.Now().Unix()}
	encoded, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal msg: %v", err)
	}

	if _, err := client.Write(encoded); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("unexpected response: %s", string(buf[:n]))
	}
	if !called {
		t.Fatalf("handler was not called")
	}

	_ = s.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not stop")
	}
}
