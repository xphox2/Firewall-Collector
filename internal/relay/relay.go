package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxReregisterAttempts = 5

type Config struct {
	ServerURL          string
	RegistrationKey    string
	TLSCertFile        string
	TLSKeyFile         string
	CACertFile         string
	SyncInterval       time.Duration
	InsecureSkipVerify bool
}

type Client struct {
	Config               Config
	httpClient           *http.Client
	approved             atomic.Bool
	mu                   sync.Mutex
	stopChan             chan struct{}
	probeID              uint
	probeName            string
	reregisterAttempts   int
}

type RegisterRequest struct {
	RegistrationKey string `json:"registration_key"`
}

type RegisterResponse struct {
	Success   bool   `json:"success"`
	ProbeID   uint   `json:"probe_id"`
	ProbeName string `json:"probe_name"`
	Message   string `json:"message"`
	Approved  bool   `json:"approved"`
}

func NewClient(cfg Config) *Client {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 30 * time.Second
	}

	tlsConfig := &tls.Config{}

	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			log.Fatalf("Failed to read CA certificate file %s: %v", cfg.CACertFile, err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			log.Fatalf("Failed to parse CA certificate from %s", cfg.CACertFile)
		}
		tlsConfig.RootCAs = caPool
	}

	if cfg.InsecureSkipVerify {
		log.Println("WARNING: TLS certificate verification is disabled — do not use in production")
		tlsConfig.InsecureSkipVerify = true
	}

	return &Client{
		Config: cfg,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		stopChan: make(chan struct{}),
	}
}

func generateRandomName() string {
	adjectives := []string{"swift", "bright", "eager", "keen", "active", "bold", "calm", "sharp", "lively", "noble"}
	nouns := []string{"falcon", "eagle", "hawk", "owl", "raven", "wolf", "bear", "lion", "tiger", "dragon"}

	adj := adjectives[randInt(len(adjectives))]
	noun := nouns[randInt(len(nouns))]
	suffix := hex.EncodeToString(randBytes(4))

	return fmt.Sprintf("%s-%s-%s", adj, noun, suffix)
}

func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		log.Printf("Failed to generate random int: %v", err)
		return 0
	}
	return int(n.Int64())
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Printf("Failed to generate random bytes: %v", err)
	}
	return b
}

// doAuthenticatedRequest sends an HTTP request with the registration key as a
// Bearer token so the server can authenticate every call, not just registration.
func (c *Client) doAuthenticatedRequest(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Config.RegistrationKey)
	return c.httpClient.Do(req)
}

func (c *Client) Register() error {
	data := RegisterRequest{
		RegistrationKey: c.Config.RegistrationKey,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", c.Config.ServerURL+"/api/probes/register", jsonData)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with HTTP status %d", resp.StatusCode)
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !result.Success {
		if strings.Contains(result.Message, "unknown") || strings.Contains(result.Message, "invalid") {
			return fmt.Errorf("registration failed: %s - please check your registration key", result.Message)
		}
		return fmt.Errorf("registration failed: %s", result.Message)
	}

	c.mu.Lock()
	c.probeID = result.ProbeID
	c.probeName = result.ProbeName
	c.reregisterAttempts = 0
	c.mu.Unlock()

	c.approved.Store(result.Approved)

	if !result.Approved {
		log.Println("Probe registered but waiting for approval in admin panel...")
	} else {
		log.Println("Probe registered and approved!")
	}

	return nil
}

func (c *Client) GetProbeID() uint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeID
}

func (c *Client) GetProbeName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeName
}

func (c *Client) IsApproved() bool {
	return c.approved.Load()
}

func (c *Client) HeartbeatLoop() error {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.SendHeartbeat(); err != nil {
				log.Printf("Heartbeat error: %v", err)
			}
		case <-c.stopChan:
			return nil
		}
	}
}

func (c *Client) SendHeartbeat() error {
	c.mu.Lock()
	probeID := c.probeID
	c.mu.Unlock()

	data := map[string]interface{}{
		"probe_id":  probeID,
		"status":    "online",
		"timestamp": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat data: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", c.Config.ServerURL+"/api/probes/heartbeat", jsonData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		c.mu.Lock()
		attempts := c.reregisterAttempts
		c.reregisterAttempts++
		c.mu.Unlock()

		if attempts >= maxReregisterAttempts {
			return fmt.Errorf("max re-registration attempts (%d) reached, giving up", maxReregisterAttempts)
		}

		backoff := time.Duration(1<<uint(attempts)) * 10 * time.Second
		log.Printf("Probe unauthorized (attempt %d/%d), retrying registration in %v...",
			attempts+1, maxReregisterAttempts, backoff)
		time.Sleep(backoff)
		return c.Register()
	}

	return nil
}

func (c *Client) DataSendLoop() error {
	ticker := time.NewTicker(c.Config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Placeholder for data sending
		case <-c.stopChan:
			return nil
		}
	}
}

func (c *Client) Stop() {
	close(c.stopChan)
}
