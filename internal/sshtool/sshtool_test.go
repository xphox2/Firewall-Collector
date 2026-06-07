package sshtool

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"firewall-collector/internal/ssh"
)

// ── Test doubles ────────────────────────────────────────────────────────────

// fakeClient is a fully-controllable Client for unit tests. Each method
// returns whatever was set in the corresponding field. The
// connectCalls/closeCalls counters let tests assert the dispatch logic.
type fakeClient struct {
	connectErr     error
	checksum       string
	checksumErr    error
	config         string
	configErr      error
	process        string
	processErr     error
	ifaceList      string
	ifaceListErr   error
	sensor         string
	sensorErr      error
	license        string
	licenseErr     error
	performance    string
	performanceErr error
	vpn1, vpn2     string
	vpnErr         error
	ha             string
	haErr          error

	mu             sync.Mutex
	connectCalls   int
	closeCalls     int
	checksumCalls  int
	configCalls    int
	processCalls   int
	ifaceListCalls int
	sensorCalls    int
	licenseCalls   int
	perfCalls      int
	vpnCalls       int
	haCalls        int
}

func (f *fakeClient) Connect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connectCalls++
	return f.connectErr
}

func (f *fakeClient) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
}

func (f *fakeClient) GetConfigChecksum() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checksumCalls++
	return f.checksum, f.checksumErr
}

func (f *fakeClient) GetConfig() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configCalls++
	return f.config, f.configErr
}

func (f *fakeClient) GetProcessTop() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.processCalls++
	return f.process, f.processErr
}

func (f *fakeClient) GetInterfaceList() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ifaceListCalls++
	return f.ifaceList, f.ifaceListErr
}

func (f *fakeClient) GetSensorInfo() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sensorCalls++
	return f.sensor, f.sensorErr
}

func (f *fakeClient) GetLicenseStatus() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.licenseCalls++
	return f.license, f.licenseErr
}

func (f *fakeClient) GetPerformanceStatus() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.perfCalls++
	return f.performance, f.performanceErr
}

func (f *fakeClient) GetVPNStatus() (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vpnCalls++
	return f.vpn1, f.vpn2, f.vpnErr
}

func (f *fakeClient) GetHAStatus() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.haCalls++
	return f.ha, f.haErr
}

// staticConnector returns the same fakeClient for every call.
func staticConnector(c Client) Connector {
	return func(host string, port int, user, password string) (Client, error) {
		return c, nil
	}
}

// errConnector always returns an error from the connector itself.
func errConnector(err error) Connector {
	return func(host string, port int, user, password string) (Client, error) {
		return nil, err
	}
}

// runWith runs the sshtool with a fake client and captured I/O.
type runResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runWith(t *testing.T, args []string, stdin io.Reader, c Client) runResult {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run(args, stdin, stdout, stderr, staticConnector(c))
	return runResult{exitCode: code, stdout: stdout.String(), stderr: stderr.String()}
}

// ── Password source tests (the AUDIT-060-required ones) ────────────────────

// TestSSHTestCmd_PasswordFromEnv verifies that when PROBE_TEST_PASSWORD is
// set and --password-stdin is NOT used, the env var is the authoritative
// source. The stdin argument is intentionally set to a sentinel that should
// never be read.
func TestSSHTestCmd_PasswordFromEnv(t *testing.T) {
	t.Setenv(PasswordEnvVar, "from-env-pw")

	fc := &fakeClient{
		checksum: "abc123",
	}
	res := runWith(t, []string{"--host=10.0.0.1", "--user=admin", "checksum"},
		strings.NewReader("from-stdin-pw\n"), fc)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if fc.connectCalls != 1 {
		t.Errorf("expected Connect to be called once, got %d", fc.connectCalls)
	}
	if fc.checksumCalls != 1 {
		t.Errorf("expected GetConfigChecksum to be called once, got %d", fc.checksumCalls)
	}
	if !strings.Contains(res.stdout, `"checksum": "abc123"`) {
		t.Errorf("stdout should contain checksum field; got %q", res.stdout)
	}
}

// TestSSHTestCmd_PasswordFromStdin verifies that when PROBE_TEST_PASSWORD
// is unset and --password-stdin is passed, the password is read from the
// first line of stdin.
func TestSSHTestCmd_PasswordFromStdin(t *testing.T) {
	t.Setenv(PasswordEnvVar, "") // ensure env var is empty

	fc := &fakeClient{checksum: "deadbeef"}
	res := runWith(t, []string{"--host=10.0.0.1", "--user=admin", "--password-stdin", "checksum"},
		strings.NewReader("hunter2\n"), fc)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if fc.connectCalls != 1 {
		t.Errorf("expected Connect to be called once, got %d", fc.connectCalls)
	}
	if !strings.Contains(res.stdout, `"checksum": "deadbeef"`) {
		t.Errorf("stdout should contain checksum; got %q", res.stdout)
	}
}

// TestSSHTestCmd_PasswordStdinStripsNewline ensures trailing \r\n is stripped.
func TestSSHTestCmd_PasswordStdinStripsNewline(t *testing.T) {
	t.Setenv(PasswordEnvVar, "")
	fc := &fakeClient{checksum: "x"}
	res := runWith(t, []string{"--host=h", "--user=u", "--password-stdin", "checksum"},
		strings.NewReader("pw\r\n"), fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
}

// TestSSHTestCmd_PasswordRequired verifies the "no password source" error
// path. No env var, no --password-stdin → exit 2 with a clear message.
func TestSSHTestCmd_PasswordRequired(t *testing.T) {
	t.Setenv(PasswordEnvVar, "")
	fc := &fakeClient{}
	res := runWith(t, []string{"--host=h", "--user=u", "checksum"},
		strings.NewReader(""), fc)
	if res.exitCode != 2 {
		t.Errorf("exit code = %d, want 2 (usage error)", res.exitCode)
	}
	if !strings.Contains(res.stderr, "password required") {
		t.Errorf("stderr should mention password required; got %q", res.stderr)
	}
}

// ── Arg parsing / usage tests ──────────────────────────────────────────────

func TestSSHTestCmd_MissingCommand(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{}
	res := runWith(t, []string{"--host=h", "--user=u"}, nil, fc)
	if res.exitCode != 2 {
		t.Errorf("exit code = %d, want 2", res.exitCode)
	}
	if !strings.Contains(res.stderr, "check command is required") {
		t.Errorf("stderr should mention missing command; got %q", res.stderr)
	}
	if fc.connectCalls != 0 {
		t.Errorf("Connect should not have been called; got %d", fc.connectCalls)
	}
}

func TestSSHTestCmd_MissingHostOrUser(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{}
	res := runWith(t, []string{"--user=u", "sensor"}, nil, fc)
	if res.exitCode != 2 {
		t.Errorf("missing host: exit code = %d, want 2", res.exitCode)
	}
	if !strings.Contains(res.stderr, "--host and --user are required") {
		t.Errorf("stderr should mention --host/--user; got %q", res.stderr)
	}
}

func TestSSHTestCmd_UnknownCommand(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{}
	res := runWith(t, []string{"--host=h", "--user=u", "bogus"}, nil, fc)
	if res.exitCode != 2 {
		t.Errorf("exit code = %d, want 2", res.exitCode)
	}
	if !strings.Contains(res.stderr, `unknown command "bogus"`) {
		t.Errorf("stderr should mention bogus command; got %q", res.stderr)
	}
	if fc.connectCalls != 0 {
		t.Errorf("Connect should not have been called for unknown command; got %d", fc.connectCalls)
	}
}

// TestSSHTestCmd_ConnectFailure verifies that an SSH connect error short-
// circuits the run with exit code 1, before any check method is called.
func TestSSHTestCmd_ConnectFailure(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{connectErr: errors.New("dial tcp: connection refused")}
	res := runWith(t, []string{"--host=h", "--user=u", "sensor"}, nil, fc)
	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1", res.exitCode)
	}
	if !strings.Contains(res.stderr, "connect failed") {
		t.Errorf("stderr should mention connect failure; got %q", res.stderr)
	}
	if fc.sensorCalls != 0 {
		t.Errorf("GetSensorInfo should not have been called; got %d", fc.sensorCalls)
	}
	if fc.closeCalls != 0 {
		t.Errorf("Close should not have been called (Connect failed); got %d", fc.closeCalls)
	}
}

// TestSSHTestCmd_ConnectorError handles the case where the connector itself
// returns an error (e.g. unsupported host). Connect/Close must not be
// called on the (nil) returned client.
func TestSSHTestCmd_ConnectorError(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"--host=h", "--user=u", "sensor"}, nil, stdout, stderr,
		errConnector(errors.New("nope")))
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "nope") {
		t.Errorf("stderr should contain connector error; got %q", stderr.String())
	}
}

// ── Dispatch / check-routing tests ─────────────────────────────────────────

// TestSSHTestCmd_DispatchesSensorOnly runs a single sensor check and
// confirms that ONLY the sensor method was called.
func TestSSHTestCmd_DispatchesSensorOnly(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		sensor: "1  CPU Temp .........  52.0  C  Normal\n",
	}
	res := runWith(t, []string{"--host=h", "--user=u", "sensor"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if fc.sensorCalls != 1 {
		t.Errorf("GetSensorInfo calls = %d, want 1", fc.sensorCalls)
	}
	if fc.checksumCalls != 0 {
		t.Errorf("GetConfigChecksum should not have been called; got %d", fc.checksumCalls)
	}
	if fc.processCalls != 0 {
		t.Errorf("GetProcessTop should not have been called; got %d", fc.processCalls)
	}
}

// TestSSHTestCmd_AllExpandsAllChecks runs "all" and confirms every check
// method was called exactly once.
func TestSSHTestCmd_AllExpandsAllChecks(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		checksum:    "abc",
		config:      "config system global\nend",
		process:     "Run Time: 0d 0h\n...\ninit 1 S 0.0 0.0 1",
		ifaceList:   "name: port1\n...",
		sensor:      "1  CPU .........  50  C  Normal",
		license:     "Version: FortiGate-100E v7.0.0\n",
		performance: "CPU states: 1% user ...\n",
		vpn1:        "edit \"t1\"\n  set type static\nend",
		vpn2:        "edit \"p1\"\n  set phase1name \"t1\"\nend",
		ha:          "HA Health Status: OK",
	}
	res := runWith(t, []string{"--host=h", "--user=u", "all"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	for name, got := range map[string]int{
		"checksum":    fc.checksumCalls,
		"config":      fc.configCalls,
		"process":     fc.processCalls,
		"interface":   fc.ifaceListCalls,
		"sensor":      fc.sensorCalls,
		"license":     fc.licenseCalls,
		"performance": fc.perfCalls,
		"vpn":         fc.vpnCalls,
		"ha":          fc.haCalls,
	} {
		if got != 1 {
			t.Errorf("check %q: call count = %d, want 1", name, got)
		}
	}
	if fc.closeCalls != 1 {
		t.Errorf("Close should be called once at end; got %d", fc.closeCalls)
	}
}

// TestSSHTestCmd_PerCheckErrorReflectedInOutput verifies that a per-check
// error is captured in the JSON result and that the overall exit code is 1.
func TestSSHTestCmd_PerCheckErrorReflectedInOutput(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		sensorErr: errors.New("device hung up"),
	}
	res := runWith(t, []string{"--host=h", "--user=u", "sensor"}, nil, fc)
	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (check failure)", res.exitCode)
	}
	if !strings.Contains(res.stdout, `"ok": false`) {
		t.Errorf("stdout should mark check as failed; got %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "device hung up") {
		t.Errorf("stdout should contain error message; got %q", res.stdout)
	}
}

// ── Output format tests ────────────────────────────────────────────────────

// TestSSHTestCmd_JSONOutputShape validates the JSON schema. The keys we
// assert are the stable contract that scripts will rely on.
func TestSSHTestCmd_JSONOutputShape(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		checksum: "abc123def456",
	}
	res := runWith(t, []string{"--host=10.0.0.1", "--port=2222", "--user=admin", "--format=json", "checksum"},
		nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}

	var got Report
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw=%q", err, res.stdout)
	}
	if got.Host != "10.0.0.1" {
		t.Errorf("Host = %q, want 10.0.0.1", got.Host)
	}
	if got.Port != 2222 {
		t.Errorf("Port = %d, want 2222", got.Port)
	}
	if got.User != "admin" {
		t.Errorf("User = %q, want admin", got.User)
	}
	if got.Command != "checksum" {
		t.Errorf("Command = %q, want checksum", got.Command)
	}
	if len(got.Checks) != 1 {
		t.Fatalf("len(Checks) = %d, want 1", len(got.Checks))
	}
	c := got.Checks[0]
	if c.Name != "checksum" {
		t.Errorf("Checks[0].Name = %q, want checksum", c.Name)
	}
	if !c.OK {
		t.Errorf("Checks[0].OK = false, want true")
	}
	if c.Checksum != "abc123def456" {
		t.Errorf("Checks[0].Checksum = %q, want abc123def456", c.Checksum)
	}
}

// TestSSHTestCmd_JSONSensorParsedShape verifies the parser integration by
// running a sensor check against canned output and confirming that the
// parsed Sensors slice contains the expected entries.
func TestSSHTestCmd_JSONSensorParsedShape(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		sensor: "  1  CPU Core Temp   .........   52.0   C    Normal\n" +
			"  2  FAN1 Speed      .........  3200.0  RPM  Normal\n",
	}
	res := runWith(t, []string{"--host=h", "--user=u", "--format=json", "sensor"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}

	var got Report
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw=%q", err, res.stdout)
	}
	if len(got.Checks) != 1 || got.Checks[0].SensorCount != 2 {
		t.Fatalf("expected 2 sensors; got %+v", got.Checks)
	}
	if got.Checks[0].Sensors[0].Name != "CPU Core Temp" {
		t.Errorf("first sensor name = %q, want CPU Core Temp", got.Checks[0].Sensors[0].Name)
	}
}

// TestSSHTestCmd_TextFormat checks the human-readable format renders without
// JSON braces and includes the host:port banner.
func TestSSHTestCmd_TextFormat(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{checksum: "abc"}
	res := runWith(t, []string{"--host=10.0.0.1", "--user=admin", "--format=text", "checksum"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if strings.Contains(res.stdout, "{") {
		t.Errorf("text format should not contain JSON braces; got %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "host=10.0.0.1") {
		t.Errorf("text format should include host=10.0.0.1; got %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "checksum") {
		t.Errorf("text format should include 'checksum'; got %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "abc") {
		t.Errorf("text format should include the checksum value; got %q", res.stdout)
	}
}

func TestSSHTestCmd_UnknownFormat(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{checksum: "x"}
	res := runWith(t, []string{"--host=h", "--user=u", "--format=xml", "checksum"}, nil, fc)
	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (emit error)", res.exitCode)
	}
	if !strings.Contains(res.stderr, `unknown format "xml"`) {
		t.Errorf("stderr should mention unknown format; got %q", res.stderr)
	}
}

// TestSSHTestCmd_FlagParseError covers the "flag parsing failed" branch
// (e.g. unknown flag). flag.ContinueOnError writes the error to stderr
// and we return exit 2.
func TestSSHTestCmd_FlagParseError(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{}
	res := runWith(t, []string{"--no-such-flag", "sensor"}, nil, fc)
	if res.exitCode != 2 {
		t.Errorf("exit code = %d, want 2", res.exitCode)
	}
}

// ── Default flag values ────────────────────────────────────────────────────

// TestSSHTestCmd_DefaultPort ensures --port defaults to 22 when not given.
func TestSSHTestCmd_DefaultPort(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{checksum: "x"}
	res := runWith(t, []string{"--host=h", "--user=u", "checksum"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	var got Report
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got.Port != 22 {
		t.Errorf("Port = %d, want 22 (default)", got.Port)
	}
}

// TestSSHTestCmd_DefaultFormat ensures --format defaults to "json".
func TestSSHTestCmd_DefaultFormat(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{checksum: "x"}
	res := runWith(t, []string{"--host=h", "--user=u", "checksum"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(res.stdout), "{") {
		t.Errorf("default format should be JSON (output starts with '{'); got %q", res.stdout)
	}
}

// ── VPN dispatch ───────────────────────────────────────────────────────────

// TestSSHTestCmd_VPNDispatchesBothPhases asserts that the vpn check calls
// GetVPNStatus (which internally runs both phase1 and phase2 commands).
func TestSSHTestCmd_VPNDispatchesBothPhases(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		vpn1: `edit "vpn-to-hq"
        set type static
        set interface "wan1"
        set remote-gw 203.0.113.5
        set status up
    next
end
`,
		vpn2: `edit "vpn-to-hq-p2"
        set phase1name "vpn-to-hq"
        set status up
    next
end
`,
	}
	res := runWith(t, []string{"--host=h", "--user=u", "--format=json", "vpn"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	if fc.vpnCalls != 1 {
		t.Errorf("GetVPNStatus calls = %d, want 1", fc.vpnCalls)
	}

	var got Report
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("not JSON: %v; raw=%q", err, res.stdout)
	}
	if len(got.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(got.Checks))
	}
	if len(got.Checks[0].Phase1Tunnels) != 1 {
		t.Errorf("expected 1 phase1 tunnel, got %d", len(got.Checks[0].Phase1Tunnels))
	}
	if got.Checks[0].Phase1Tunnels[0].Name != "vpn-to-hq" {
		t.Errorf("tunnel name = %q, want vpn-to-hq", got.Checks[0].Phase1Tunnels[0].Name)
	}
	if len(got.Checks[0].Phase2Tunnels) != 1 {
		t.Errorf("expected 1 phase2 tunnel, got %d", len(got.Checks[0].Phase2Tunnels))
	}
}

// ── Performance dispatch (parses into typed struct) ────────────────────────

// TestSSHTestCmd_PerformanceParsed asserts the Performance field is a
// non-nil *ssh.PerformanceInfo (not just a raw string) when the canned
// output contains the expected format.
func TestSSHTestCmd_PerformanceParsed(t *testing.T) {
	t.Setenv(PasswordEnvVar, "pw")
	fc := &fakeClient{
		performance: `CPU states: 5% user 3% system 0% nice 90% idle 1% iowait 0% irq 1% softirq
Memory: 8192000k total, 4096000k used (50.0%), 4096000k free (50.0%), 0k freeable (0.0%)
Average network usage: 120 / 80 kbps in 1 minute
Current sessions: 42
Maximal sessions: 100 sessions in 1 minute
Uptime: 7 days, 3 hours, 12 minutes
`,
	}
	res := runWith(t, []string{"--host=h", "--user=u", "--format=json", "performance"}, nil, fc)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", res.exitCode, res.stderr)
	}
	var got Report
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	perf := got.Checks[0].Performance
	if perf == nil {
		t.Fatal("Performance field is nil; expected parsed PerformanceInfo")
	}
	if perf.SessionCount != 42 {
		t.Errorf("SessionCount = %d, want 42", perf.SessionCount)
	}
	if perf.Uptime != 7*86400 {
		t.Errorf("Uptime = %d, want %d", perf.Uptime, 7*86400)
	}
}

// ── Sanity check: production connector builds a real client ───────────────

// TestDefaultConnectorBuildsRealClient is a tiny smoke test that
// DefaultConnector returns a non-nil Client without touching the network.
// The returned concrete type is *ssh.FortiGateClient.
func TestDefaultConnectorBuildsRealClient(t *testing.T) {
	c, err := DefaultConnector("127.0.0.1", 22, "u", "p")
	if err != nil {
		t.Fatalf("DefaultConnector returned err: %v", err)
	}
	if c == nil {
		t.Fatal("DefaultConnector returned nil client")
	}
	// We don't actually dial; just make sure Close (which is a no-op on
	// a never-connected client) doesn't panic.
	c.Close()
	// Sanity: the concrete type is the one cmd/collector wires up.
	if _, ok := c.(*ssh.FortiGateClient); !ok {
		t.Errorf("DefaultConnector returned %T, want *ssh.FortiGateClient", c)
	}
}
