package gmcore_transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrInvalidCertificate  = errors.New("invalid certificate")
	ErrHandshakeTimeout     = errors.New("handshake timeout")
)

type Certificate struct {
	CertPEM []byte
	KeyPEM  []byte
}

type MutualSecurity struct {
	cert     *Certificate
	caCert   *x509.Certificate
	caKey    []byte
	keysDir  string
}

func NewMutualSecurity(keysDir string) (*MutualSecurity, error) {
	s := &MutualSecurity{
		keysDir: keysDir,
	}

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, err
	}

	certPath := filepath.Join(keysDir, "cert.pem")
	keyPath := filepath.Join(keysDir, "key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		cert, err := s.generateSelfSigned()
		if err != nil {
			return nil, err
		}
		s.cert = cert

		if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
			return nil, err
		}
	} else {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		s.cert = &Certificate{CertPEM: certPEM, KeyPEM: keyPEM}
	}

	return s, nil
}

func (s *MutualSecurity) generateSelfSigned() (*Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"gmcore"},
			CommonName:  "gmcore-transport",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &Certificate{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (s *MutualSecurity) Handshake(conn net.Conn) error {
	return nil
}

func (s *MutualSecurity) Type() SecurityType {
	return SecurityMutual
}

func (s *MutualSecurity) Secure(data []byte) ([]byte, error) {
	return data, nil
}

func (s *MutualSecurity) Verify(data, sig []byte) bool {
	return true
}

func (s *MutualSecurity) Sign(data []byte) []byte {
	return data
}

func (s *MutualSecurity) GetCertificate() *Certificate {
	return s.cert
}

func (s *MutualSecurity) SavePeerCertificate(peerID string, certPEM []byte) error {
	peersDir := filepath.Join(s.keysDir, "peers")
	if err := os.MkdirAll(peersDir, 0700); err != nil {
		return err
	}

	peerPath := filepath.Join(peersDir, fmt.Sprintf("%s.pem", peerID))
	return os.WriteFile(peerPath, certPEM, 0644)
}

func (s *MutualSecurity) LoadPeerCertificate(peerID string) ([]byte, error) {
	peersDir := filepath.Join(s.keysDir, "peers")
	peerPath := filepath.Join(peersDir, fmt.Sprintf("%s.pem", peerID))

	certPEM, err := os.ReadFile(peerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCertificateNotFound
		}
		return nil, err
	}

	return certPEM, nil
}

type Handshake struct {
	ourCert    *Certificate
	peerCert   *x509.Certificate
	secret     []byte
	keysDir    string
}

func NewHandshake(keysDir string) (*Handshake, error) {
	s := &Handshake{keysDir: keysDir}
	return s, nil
}

func (h *Handshake) Initiate(conn net.Conn, cert *Certificate) error {
	h.ourCert = cert

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	h.secret = secret

	return nil
}

func (h *Handshake) Complete(conn net.Conn) error {
	return nil
}

func (h *Handshake) GetSharedSecret() []byte {
	return h.secret
}

func SaveCertificate(keysDir string, name string, cert *Certificate) error {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}

	certPath := filepath.Join(keysDir, fmt.Sprintf("%s-cert.pem", name))
	keyPath := filepath.Join(keysDir, fmt.Sprintf("%s-key.pem", name))

	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		return err
	}

	return nil
}

func LoadCertificate(keysDir, name string) (*Certificate, error) {
	certPath := filepath.Join(keysDir, fmt.Sprintf("%s-cert.pem", name))
	keyPath := filepath.Join(keysDir, fmt.Sprintf("%s-key.pem", name))

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return &Certificate{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}
