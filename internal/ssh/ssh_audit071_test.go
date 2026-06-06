package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

type testServerOpts struct {
	acceptedPubKey   cryptossh.PublicKey
	acceptedPassword string
	rejectPassword   bool
}

func startTestSSHServer(t *testing.T, opts testServerOpts) string {
	t.Helper()

	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cfg := &cryptossh.ServerConfig{}
	if opts.acceptedPubKey != nil {
		want := opts.acceptedPubKey.Marshal()
		cfg.PublicKeyCallback = func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			got := key.Marshal()
			if len(got) == len(want) && string(got) == string(want) {
				return nil, nil
			}
			return nil, fmt.Errorf("public key not accepted")
		}
	}
	if opts.rejectPassword {
		cfg.PasswordCallback = func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			return nil, fmt.Errorf("password auth disabled by test server")
		}
	} else if opts.acceptedPassword != "" {
		want := opts.acceptedPassword
		cfg.PasswordCallback = func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			if string(password) == want {
				return nil, nil
			}
			return nil, fmt.Errorf("password not accepted")
		}
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshConn, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go cryptossh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(cryptossh.UnknownChannelType, "no sessions for tests")
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func writeKeyFile(t *testing.T, passphrase string) (path string, pubKey cryptossh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}

	var block *pem.Block
	if passphrase == "" {
		block, err = cryptossh.MarshalPrivateKey(priv, "audit-071-test")
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(priv, "audit-071-test", []byte(passphrase))
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(block)
	path = filepathJoin(t.TempDir(), "id_test")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from priv: %v", err)
	}
	return path, signer.PublicKey()
}

func filepathJoin(dir, name string) string {
	if strings.HasSuffix(dir, string(os.PathSeparator)) {
		return dir + name
	}
	return dir + string(os.PathSeparator) + name
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

func TestSSHClient_PublicKeyAuth(t *testing.T) {
	keyPath, pubKey := writeKeyFile(t, "")
	addr := startTestSSHServer(t, testServerOpts{
		acceptedPubKey: pubKey,
		rejectPassword: true,
	})
	host, port := splitAddr(t, addr)

	client := NewFortiGateClientWithKey(host, port, "audit071", "", keyPath, "")
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect with public key failed: %v", err)
	}
	defer client.Close()

	if client.client == nil {
		t.Fatal("expected ssh.Client to be set after successful Connect")
	}
}

func TestSSHClient_KeyWithPassphrase(t *testing.T) {
	const passphrase = "correct horse battery staple"
	keyPath, pubKey := writeKeyFile(t, passphrase)
	addr := startTestSSHServer(t, testServerOpts{
		acceptedPubKey: pubKey,
		rejectPassword: true,
	})
	host, port := splitAddr(t, addr)

	client := NewFortiGateClientWithKey(host, port, "audit071", "", keyPath, passphrase)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect with passphrase-protected key failed: %v", err)
	}
	defer client.Close()

	wrong := NewFortiGateClientWithKey(host, port, "audit071", "", keyPath, "wrong-passphrase")
	err := wrong.Connect()
	if err == nil {
		wrong.Close()
		t.Fatal("expected Connect to fail with wrong passphrase, got nil error")
	}
	if !strings.Contains(err.Error(), "parse encrypted key") && !strings.Contains(err.Error(), "load ssh key") {
		t.Errorf("expected encrypted-key parse error, got: %v", err)
	}
}

func TestSSHClient_PasswordFallback(t *testing.T) {
	keyPath, pubKey := writeKeyFile(t, "")
	addr := startTestSSHServer(t, testServerOpts{
		acceptedPubKey: pubKey,
		rejectPassword: true,
	})
	host, port := splitAddr(t, addr)

	client := NewFortiGateClientWithKey(host, port, "audit071", "this-password-would-be-rejected", keyPath, "")
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect should have used the key (server rejects passwords): %v", err)
	}
	defer client.Close()

	auth, err := client.buildAuthMethods()
	if err != nil {
		t.Fatalf("buildAuthMethods returned error: %v", err)
	}
	if len(auth) != 1 {
		t.Fatalf("expected exactly 1 auth method (public key), got %d", len(auth))
	}
}

func TestSSHClient_NoAuth_RefusesToConnect(t *testing.T) {
	client := NewFortiGateClientWithKey("127.0.0.1", 1, "audit071", "", "", "")

	err := client.Connect()
	if err == nil {
		client.Close()
		t.Fatal("expected Connect to refuse when neither key nor password is set, got nil error")
	}
	if !strings.Contains(err.Error(), "no auth method configured") {
		t.Errorf("expected 'no auth method configured' error, got: %v", err)
	}

	_, err = client.buildAuthMethods()
	if err == nil {
		t.Fatal("expected buildAuthMethods to error when both creds are empty")
	}
}

func TestSSHClient_PasswordAuth_StillWorksWithWarning(t *testing.T) {
	const password = "fg-password"
	addr := startTestSSHServer(t, testServerOpts{
		acceptedPassword: password,
	})
	host, port := splitAddr(t, addr)

	client := NewFortiGateClient(host, port, "audit071", password)
	if err := client.Connect(); err != nil {
		t.Fatalf("password auth via NewFortiGateClient failed: %v", err)
	}
	defer client.Close()
}
