// diag-backup is a single-shot diagnostic that exercises the entire FortiGate
// → TFTP-listener config-backup flow against a real firewall and prints a
// definitive verdict on where it succeeds or fails.
//
// Run on the same host as the production collector (or anywhere reachable by
// the firewall on UDP 69 of the chosen --listen-ip). Use Ctrl-C to abort.
//
// Example:
//
//	diag-backup \
//	  -device-host=192.168.5.1 -device-user=admin -device-password='...' \
//	  -listen-port=6969 -tftp-target=192.168.5.25
//
// Notes
//   - --tftp-target is what we tell the firewall to upload to. Often this is
//     just the IP of the collector host as the firewall sees it.
//   - --listen-port can be any port you have permission to bind. The default
//     is 6969 (NOT 69) so you don't need root and don't conflict with a
//     production collector on the same host. The firewall talks to whatever
//     port you choose, so make sure --tftp-target:listen-port is reachable.
//
// Output is plain text with section headers. Search for "VERDICT" at the end
// for the bottom-line result.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"firewall-collector/internal/ssh"
	"firewall-collector/internal/tftp"
)

func main() {
	var (
		deviceHost     = flag.String("device-host", "", "Firewall IP/hostname (required)")
		devicePort     = flag.Int("device-port", 22, "SSH port on the firewall")
		deviceUser     = flag.String("device-user", "", "SSH username (required)")
		devicePassword = flag.String("device-password", "", "SSH password (required)")
		listenIP       = flag.String("listen-ip", "0.0.0.0", "Local IP to bind the TFTP listener on")
		listenPort     = flag.Int("listen-port", 6969, "Local UDP port to bind the TFTP listener on")
		tftpTarget     = flag.String("tftp-target", "", "IP we tell the firewall to upload to (defaults to listen-ip if not set)")
		filename       = flag.String("filename", "diag_test_config", "Filename used in the SSH command and reported by the firewall as the WRQ filename")
		usePty         = flag.Bool("use-pty", true, "Allocate a PTY for the SSH session (recommended)")
		timeout        = flag.Duration("timeout", 90*time.Second, "How long to wait for the firewall to upload after the SSH command returns")
		sshTimeout     = flag.Duration("ssh-timeout", 90*time.Second, "How long to wait for the SSH backup command itself")
	)
	flag.Parse()

	if *deviceHost == "" || *deviceUser == "" || *devicePassword == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --device-host, --device-user, --device-password are required")
		flag.Usage()
		os.Exit(2)
	}
	if *tftpTarget == "" {
		*tftpTarget = *listenIP
		if *tftpTarget == "0.0.0.0" || *tftpTarget == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --tftp-target must be a concrete reachable IP when --listen-ip is 0.0.0.0")
			os.Exit(2)
		}
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	hr := strings.Repeat("─", 60)
	section := func(title string) {
		fmt.Println()
		fmt.Println(hr)
		fmt.Println(" " + title)
		fmt.Println(hr)
	}

	section("PARAMETERS")
	fmt.Printf("  device-host      = %s:%d\n", *deviceHost, *devicePort)
	fmt.Printf("  device-user      = %s\n", *deviceUser)
	fmt.Printf("  device-password  = (%d chars)\n", len(*devicePassword))
	fmt.Printf("  listen-ip:port   = %s:%d\n", *listenIP, *listenPort)
	fmt.Printf("  tftp-target      = %s (passed to FortiGate as the upload IP)\n", *tftpTarget)
	fmt.Printf("  filename         = %s\n", *filename)
	fmt.Printf("  use-pty          = %v\n", *usePty)
	fmt.Printf("  ssh-timeout      = %v\n", *sshTimeout)
	fmt.Printf("  upload-timeout   = %v\n", *timeout)

	// Graceful interrupt
	sigCtx, sigCancel := context.WithCancel(context.Background())
	defer sigCancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("interrupt received")
		sigCancel()
	}()

	verdict := verdictBuilder{}

	// 1) Bind TFTP listener.
	section("STEP 1: Bind TFTP listener")
	listenAddr := fmt.Sprintf("%s:%d", *listenIP, *listenPort)
	srv := tftp.NewServer(&tftp.Config{
		Addr:    listenAddr,
		Timeout: 60 * time.Second,
	})

	type uploadResult struct {
		filename string
		bytes    int
		from     net.Addr
		when     time.Time
	}
	uploadCh := make(chan uploadResult, 4)

	srv.SetWriteHandler(func(name string, data []byte, client net.Addr) error {
		log.Printf("[TFTP] WRITE handler invoked: name=%s bytes=%d client=%s", name, len(data), client)
		uploadCh <- uploadResult{filename: name, bytes: len(data), from: client, when: time.Now()}
		return nil
	})

	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("  RESULT: FAILED to bind %s — %v\n", listenAddr, err)
		fmt.Printf("  HINT: try a higher port (e.g. -listen-port=6969). Ports <1024 require root/CAP_NET_BIND_SERVICE.\n")
		verdict.fail("Cannot bind TFTP listener on " + listenAddr)
		verdict.print()
		os.Exit(1)
	}
	defer srv.Shutdown()
	fmt.Printf("  RESULT: TFTP listener bound on %s\n", listenAddr)

	// 2) SSH connect.
	section("STEP 2: SSH connect")
	sshClient := ssh.NewFortiGateClient(*deviceHost, *devicePort, *deviceUser, *devicePassword)
	sshStart := time.Now()
	if err := sshClient.Connect(); err != nil {
		fmt.Printf("  RESULT: FAILED — %v\n", err)
		verdict.fail("SSH connect failed")
		verdict.print()
		os.Exit(1)
	}
	fmt.Printf("  RESULT: SSH connected to %s:%d in %v\n", *deviceHost, *devicePort, time.Since(sshStart))
	defer sshClient.Close()

	// 3) Send TFTP backup command.
	section("STEP 3: Send TFTP backup command via SSH")
	cmd := fmt.Sprintf("execute backup config tftp %s %s", *filename, *tftpTarget)
	fmt.Printf("  Command: %s\n", cmd)
	fmt.Printf("  PTY:     %v\n", *usePty)
	cmdStart := time.Now()

	var rawOutput string
	var execErr error
	if *usePty {
		rawOutput, execErr = sshClient.ExecuteWithPty(cmd, *sshTimeout)
	} else {
		rawOutput, execErr = sshClient.ExecuteRaw(cmd, *sshTimeout)
	}
	cmdElapsed := time.Since(cmdStart)

	fmt.Printf("  Returned in: %v\n", cmdElapsed)
	fmt.Printf("  Output (%d bytes):\n", len(rawOutput))
	fmt.Println("  ┌──────")
	for _, line := range strings.Split(rawOutput, "\n") {
		fmt.Printf("  │ %s\n", line)
	}
	fmt.Println("  └──────")
	if execErr != nil {
		fmt.Printf("  ERROR: %v\n", execErr)
	}

	// 4) Watch for WRQ / upload arrival.
	section("STEP 4: Wait for firewall to TFTP-upload")
	fmt.Printf("  Waiting up to %v for the firewall to push '%s' to %s ...\n", *timeout, *filename, listenAddr)

	uploadDeadline := time.NewTimer(*timeout)
	defer uploadDeadline.Stop()

	var got *uploadResult
	select {
	case r := <-uploadCh:
		got = &r
	case <-uploadDeadline.C:
		// timed out
	case <-sigCtx.Done():
		fmt.Println("  Interrupted.")
	}

	if got != nil {
		fmt.Printf("  RESULT: Upload received — filename=%q bytes=%d from=%s elapsed=%v\n",
			got.filename, got.bytes, got.from, got.when.Sub(cmdStart))
	} else {
		fmt.Printf("  RESULT: No upload received within %v\n", *timeout)
	}

	// 5) Verdict.
	section("VERDICT")
	switch {
	case got != nil && got.bytes > 0:
		verdict.pass("Full success: SSH command + TFTP upload both worked")
		fmt.Printf("  Filename: %q\n", got.filename)
		fmt.Printf("  Size:     %d bytes\n", got.bytes)
		fmt.Printf("  From:     %s\n", got.from)

	case containsCaseInsensitive(rawOutput, "permission to backup config") ||
		containsCaseInsensitive(rawOutput, "Return code -37"):
		verdict.fail("SSH user lacks permission to backup config (FortiOS code -37). The user's admin profile must include System > Configuration: Read/Write. Either assign accprofile super_admin or grant the equivalent in a custom profile. CLI: `config system admin / edit \"<user>\" / set accprofile \"super_admin\"`.")

	case containsCaseInsensitive(rawOutput, "permission") || containsCaseInsensitive(rawOutput, "Return code -"):
		verdict.fail("FortiGate refused the command — see output above. Check the SSH user's admin profile and whether the firewall is in read-only mode (HA secondary, etc.).")

	case execErr != nil && cmdElapsed < 5*time.Second && len(rawOutput) == 0:
		verdict.fail("SSH session closed almost immediately with no output. Likely a FortiOS PTY/CLI mode issue or auth fallthrough. Try -use-pty=true (default), or check that the SSH user has CLI access.")

	case len(rawOutput) == 0 && cmdElapsed < 5*time.Second:
		verdict.fail("SSH command returned in <5s with EMPTY output. The firewall almost certainly didn't run `execute backup config tftp` at all. Most likely cause: SSH session closed before the command was processed (PTY needed, or CLI requires interactive shell).")

	case got == nil && len(rawOutput) > 0 && containsCaseInsensitive(rawOutput, "Send config file to tftp server failed"):
		verdict.fail("FortiGate tried but couldn't reach the TFTP server. The firewall has no route or is blocked from reaching " + *tftpTarget + ":" + fmt.Sprintf("%d", *listenPort) + " UDP. Check: 1) is the listener actually open on " + listenAddr + " (run `ss -ulnp | grep " + fmt.Sprintf("%d", *listenPort) + "` on the host), 2) host firewall (iptables/nftables/Windows Firewall) is allowing inbound UDP " + fmt.Sprintf("%d", *listenPort) + ", 3) any in-path firewall between firewall and collector permits TFTP, 4) you can `execute ping " + *tftpTarget + "` from this firewall.")

	case got == nil && len(rawOutput) > 0 && containsCaseInsensitive(rawOutput, "Send config file to tftp server OK"):
		verdict.fail("FortiGate reports success but no WRQ landed on our listener. The firewall is sending TFTP packets to a different IP/port than we're listening on, or NAT/PAT is rewriting them away. Check what address the firewall actually sent to (sniff UDP " + fmt.Sprintf("%d", *listenPort) + " on this host: `tcpdump -i any udp port " + fmt.Sprintf("%d", *listenPort) + "`).")

	case got == nil && len(rawOutput) > 0:
		verdict.fail("Firewall returned output but no upload arrived. Read the output above for the actual reason. If output looks truncated, re-run with -use-pty=false to compare.")

	case got == nil:
		verdict.fail("No upload arrived and SSH output was empty. Try -use-pty=false to compare; verify host firewall rules are not blocking UDP " + fmt.Sprintf("%d", *listenPort) + " inbound.")
	}

	verdict.print()
	if !verdict.ok {
		os.Exit(1)
	}

	// Wait briefly to let the listener handle any straggling cleanup.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(200 * time.Millisecond)
	}()
	wg.Wait()
}

type verdictBuilder struct {
	ok      bool
	summary string
}

func (v *verdictBuilder) pass(msg string) { v.ok = true; v.summary = "PASS: " + msg }
func (v *verdictBuilder) fail(msg string) { v.ok = false; v.summary = "FAIL: " + msg }
func (v *verdictBuilder) print() {
	if v.summary == "" {
		fmt.Println("  (no verdict)")
		return
	}
	fmt.Println()
	fmt.Println("  " + v.summary)
}

func containsCaseInsensitive(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
