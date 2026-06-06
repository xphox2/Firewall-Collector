package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func genSelfSignedCertKey(t *testing.T, cn string, isCA bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func genCASignedCert(t *testing.T, cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string, ipAddresses []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func writePEMFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	return path
}

func TestNewClient_LoadsClientCertificate(t *testing.T) {
	certPEM, keyPEM := genSelfSignedCertKey(t, "test-client", false)
	dir := t.TempDir()
	certPath := writePEMFile(t, dir, "client.crt", certPEM, 0o600)
	keyPath := writePEMFile(t, dir, "client.key", keyPEM, 0o600)

	c := NewClient(Config{TLSCertFile: certPath, TLSKeyFile: keyPath})
	if c == nil || c.httpClient == nil {
		t.Fatal("NewClient returned incomplete client")
	}
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if got := len(transport.TLSClientConfig.Certificates); got != 1 {
		t.Fatalf("Certificates len = %d, want 1", got)
	}
	if len(transport.TLSClientConfig.Certificates[0].Certificate) == 0 {
		t.Error("Certificate[0].Certificate has no DER bytes")
	}
	if transport.TLSClientConfig.Certificates[0].PrivateKey == nil {
		t.Error("Certificate[0].PrivateKey is nil")
	}
}

func TestNewClient_OnlyOneCertOrKey_Fatals(t *testing.T) {
	if os.Getenv("AUDIT048_FATAL_SUBPROCESS") == "1" {
		certPEM, _ := genSelfSignedCertKey(t, "test-client", false)
		dir := t.TempDir()
		certPath := writePEMFile(t, dir, "client.crt", certPEM, 0o600)
		_ = NewClient(Config{TLSCertFile: certPath, TLSKeyFile: ""})
		fmt.Println("BUG: NewClient did not call log.Fatalf on cert-only misconfiguration")
		os.Exit(2)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewClient_OnlyOneCertOrKey_Fatals$")
	cmd.Env = append(os.Environ(), "AUDIT048_FATAL_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	e, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError from log.Fatalf, got %v. output:\n%s", err, out)
	}
	if e.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 from log.Fatalf, got %d. output:\n%s", e.ExitCode(), out)
	}
	if !strings.Contains(string(out), "PROBE_TLS_CERT") || !strings.Contains(string(out), "PROBE_TLS_KEY") {
		t.Errorf("fatal log should reference both PROBE_TLS_CERT and PROBE_TLS_KEY, got:\n%s", out)
	}
}

func TestNewClient_KeyFileWorldReadable_RefusesToStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not enforced on Windows")
	}
	if os.Getenv("AUDIT048_FATAL_SUBPROCESS") == "1" {
		certPEM, keyPEM := genSelfSignedCertKey(t, "test-client", false)
		dir := t.TempDir()
		certPath := writePEMFile(t, dir, "client.crt", certPEM, 0o600)
		keyPath := writePEMFile(t, dir, "client.key", keyPEM, 0o600)
		if err := os.Chmod(keyPath, 0o644); err != nil {
			fmt.Printf("BUG: chmod failed: %v\n", err)
			os.Exit(2)
		}
		_ = NewClient(Config{TLSCertFile: certPath, TLSKeyFile: keyPath})
		fmt.Println("BUG: NewClient did not call log.Fatalf on world-readable key")
		os.Exit(2)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewClient_KeyFileWorldReadable_RefusesToStart$")
	cmd.Env = append(os.Environ(), "AUDIT048_FATAL_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	e, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError from log.Fatalf, got %v. output:\n%s", err, out)
	}
	if e.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 from log.Fatalf, got %d. output:\n%s", e.ExitCode(), out)
	}
	if !strings.Contains(string(out), "world") && !strings.Contains(string(out), "permissive") {
		t.Errorf("fatal log should mention world-readable/permissive mode, got:\n%s", out)
	}
}

func TestNewClient_KeyFileGroupReadable_RefusesToStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not enforced on Windows")
	}
	if os.Getenv("AUDIT048_FATAL_SUBPROCESS") == "1" {
		certPEM, keyPEM := genSelfSignedCertKey(t, "test-client", false)
		dir := t.TempDir()
		certPath := writePEMFile(t, dir, "client.crt", certPEM, 0o600)
		keyPath := writePEMFile(t, dir, "client.key", keyPEM, 0o600)
		if err := os.Chmod(keyPath, 0o640); err != nil {
			fmt.Printf("BUG: chmod failed: %v\n", err)
			os.Exit(2)
		}
		_ = NewClient(Config{TLSCertFile: certPath, TLSKeyFile: keyPath})
		fmt.Println("BUG: NewClient did not call log.Fatalf on group-readable key")
		os.Exit(2)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewClient_KeyFileGroupReadable_RefusesToStart$")
	cmd.Env = append(os.Environ(), "AUDIT048_FATAL_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	e, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError from log.Fatalf, got %v. output:\n%s", err, out)
	}
	if e.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 from log.Fatalf, got %d. output:\n%s", e.ExitCode(), out)
	}
}

func TestNewClient_MTLSTLSHandshake_PresentsClientCert(t *testing.T) {
	caCertPEM, caKeyPEM := genSelfSignedCertKey(t, "test-ca", true)
	caCert := parseCertPEM(t, caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKeyIface, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	caKey := caKeyIface.(*ecdsa.PrivateKey)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	serverCertPEM, serverKeyPEM := genCASignedCert(t, "test-server", caCert, caKey,
		[]string{"test-server"},
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	)
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server X509KeyPair: %v", err)
	}

	clientCertPEM, clientKeyPEM := genCASignedCert(t, "test-client", caCert, caKey, nil, nil)
	dir := t.TempDir()
	certPath := writePEMFile(t, dir, "client.crt", clientCertPEM, 0o600)
	keyPath := writePEMFile(t, dir, "client.key", clientKeyPEM, 0o600)
	caPath := writePEMFile(t, dir, "ca.crt", caCertPEM, 0o600)

	var mu sync.Mutex
	var peerCN string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			mu.Lock()
			peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	c := NewClient(Config{
		ServerURL:       server.URL,
		RegistrationKey: "test-key",
		TLSCertFile:     certPath,
		TLSKeyFile:      keyPath,
		CACertFile:      caPath,
	})

	resp, err := c.doAuthenticatedRequest("GET", server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("authenticated GET failed: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	cn := peerCN
	mu.Unlock()
	if cn != "test-client" {
		t.Errorf("server saw client cert CN = %q, want %q", cn, "test-client")
	}
}
