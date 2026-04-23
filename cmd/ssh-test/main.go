package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: ssh-test <host> <port> <username> <password> <command>")
		fmt.Println("Example: ssh-test 192.168.1.1 22 admin password \"diagnose sys csum\"")
		os.Exit(1)
	}

	host := os.Args[1]
	port := os.Args[2]
	username := os.Args[3]
	password := os.Args[4]
	command := os.Args[5]

	log.Printf("=== SSH FortiGate Test ===")
	log.Printf("Host: %s:%s", host, port)
	log.Printf("User: %s", username)
	log.Printf("Command: %s", command)
	log.Printf("")

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Printf("Host key callback called for %s", hostname)
			return nil
		},
		Timeout: 30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("Dialing %s...", addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()
	log.Printf("Connected successfully!")

	log.Printf("Creating new session...")
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()
	log.Printf("Session created")

	// Try CombinedOutput approach first (simpler)
	log.Printf("")
	log.Printf("=== Test 1: CombinedOutput (no PTY) ===")
	session1, _ := client.NewSession()
	out1, err1 := session1.CombinedOutput(command)
	log.Printf("Output: %q", string(out1))
	log.Printf("Error: %v", err1)
	session1.Close()

	// Try with PTY and Start
	log.Printf("")
	log.Printf("=== Test 2: PTY + Start (exec channel with PTY) ===")
	session2, _ := client.NewSession()
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	err2 := session2.RequestPty("xterm", 80, 40, modes)
	log.Printf("RequestPty error: %v", err2)

	err2 = session2.Start(command)
	log.Printf("Start error: %v", err2)

	var buf bytes.Buffer
	session2.Stdout = &buf
	err2 = session2.Wait()
	log.Printf("Wait error: %v", err2)
	log.Printf("Output: %q", buf.String())
	session2.Close()

	// Try with PTY and Shell
	log.Printf("")
	log.Printf("=== Test 3: PTY + Shell + stdin (shell channel) ===")
	session3, _ := client.NewSession()
	err3 := session3.RequestPty("xterm", 80, 40, modes)
	log.Printf("RequestPty error: %v", err3)

	err3 = session3.Shell()
	log.Printf("Shell error: %v", err3)

	stdin, _ := session3.StdinPipe()
	stdout, _ := session3.StdoutPipe()

	time.Sleep(500 * time.Millisecond)

	_, err3 = stdin.Write([]byte(command + "\n"))
	log.Printf("Write error: %v", err3)

	time.Sleep(1 * time.Second)

	var output bytes.Buffer
	io.Copy(&output, stdout)
	log.Printf("Output: %q", output.String())
	session3.Close()

	log.Printf("")
	log.Printf("=== Tests Complete ===")
}
