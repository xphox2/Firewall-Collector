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

type Config struct {
	ServerURL       string
	RegistrationKey string
	TLSCertFile     string
	TLSKeyFile      string
	CACertFile      string
	SyncInterval    time.Duration
}

type Client struct {
	Config     Config
	httpClient *http.Client
	running    atomic.Bool
	approved   atomic.Bool
	mu         sync.Mutex
	stopChan   chan struct{}
	probeID    uint
	probeName  string
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

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err == nil {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caPool
			tlsConfig.InsecureSkipVerify = false
		}
	}

	return &Client{
		Config:     cfg,
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		stopChan:   make(chan struct{}),
	}
}

func generateRandomName() string {
	adjectives := []string{"swift", "bright", "eager", "keen", "active", "bold", "calm", "keen", "lively", "noble"}
	nouns := []string{"falcon", "eagle", "hawk", "owl", "raven", "wolf", "bear", "lion", "tiger", "dragon"}

	adj := adjectives[randInt(len(adjectives))]
	noun := nouns[randInt(len(nouns))]
	suffix := hex.EncodeToString(randBytes(4))

	return fmt.Sprintf("%s-%s-%s", adj, noun, suffix)
}

func randInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (c *Client) Register() error {
	data := RegisterRequest{
		RegistrationKey: c.Config.RegistrationKey,
	}

	jsonData, _ := json.Marshal(data)
	resp, err := c.httpClient.Post(c.Config.ServerURL+"/api/probes/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

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

	c.probeID = result.ProbeID
	c.probeName = result.ProbeName
	c.approved.Store(result.Approved)

	if !result.Approved {
		log.Println("Probe registered but waiting for approval in admin panel...")
	} else {
		log.Println("Probe registered and approved!")
	}

	return nil
}

func (c *Client) GetProbeID() uint {
	return c.probeID
}

func (c *Client) GetProbeName() string {
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
	data := map[string]interface{}{
		"probe_id":  c.probeID,
		"status":    "online",
		"timestamp": time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(data)
	resp, err := c.httpClient.Post(c.Config.ServerURL+"/api/probes/heartbeat", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		log.Println("Probe not approved yet, re-registering...")
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
	c.running.Store(false)
	close(c.stopChan)
}
