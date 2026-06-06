// Package sshtool implements the `collector ssh-test` operator subcommand.
// It is a thin wrapper around internal/ssh that prints results in a
// structured (JSON by default) form suitable for scripting and CI.
//
// All SSH primitives (Connect, Execute, GetConfigChecksum, GetSensorInfo,
// GetProcessTop, GetInterfaceList, GetLicenseStatus, GetPerformanceStatus,
// GetVPNStatus, GetHAStatus) and all parsers live in internal/ssh. This
// package adds only:
//
//   - flag parsing (--host, --port, --user, --password-stdin, --format)
//   - password resolution (PROBE_TEST_PASSWORD env var, then --password-stdin)
//   - command dispatch (all | sensor | process | interface | license |
//     performance | vpn | ha | checksum | config)
//   - JSON or text output formatting
//
// Bug fixes in internal/ssh are automatically picked up by this tool —
// there is no duplicate SSH or parser code.
package sshtool

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"firewall-collector/internal/ssh"
)

// PasswordEnvVar is the environment variable the ssh-test subcommand reads
// for the device SSH password. Falls back to --password-stdin if unset.
const PasswordEnvVar = "PROBE_TEST_PASSWORD"

// Client is the subset of *ssh.FortiGateClient that sshtool needs. Defined
// as an interface so tests can inject a fake without spinning up a real
// SSH server.
type Client interface {
	Connect() error
	Close()
	GetConfigChecksum() (string, error)
	GetConfig() (string, error)
	GetProcessTop() (string, error)
	GetInterfaceList() (string, error)
	GetSensorInfo() (string, error)
	GetLicenseStatus() (string, error)
	GetPerformanceStatus() (string, error)
	GetVPNStatus() (string, string, error)
	GetHAStatus() (string, error)
}

// Connector creates a Client. Production wires this to ssh.NewFortiGateClient;
// tests inject a fake.
type Connector func(host string, port int, user, password string) (Client, error)

// DefaultConnector is the production connector — it builds a real
// *ssh.FortiGateClient.
func DefaultConnector(host string, port int, user, password string) (Client, error) {
	return ssh.NewFortiGateClient(host, port, user, password), nil
}

// CheckResult is the per-check result emitted in the JSON output. Only one
// of Parsed, RawOutput, Phase1Tunnels, Phase2Tunnels, or Sensors is populated
// depending on the check.
type CheckResult struct {
	Name           string      `json:"name"`
	OK             bool        `json:"ok"`
	Error          string      `json:"error,omitempty"`
	RawOutputBytes int         `json:"raw_output_bytes,omitempty"`
	Parsed         interface{} `json:"parsed,omitempty"`
	// Checks that produce more than one parsed value use these dedicated fields.
	Checksum       string                   `json:"checksum,omitempty"`
	ProcessCount   int                      `json:"process_count,omitempty"`
	InterfaceCount int                      `json:"interface_count,omitempty"`
	SensorCount    int                      `json:"sensor_count,omitempty"`
	LineCount      int                      `json:"line_count,omitempty"`
	RawOutput      string                   `json:"raw_output,omitempty"`
	Phase1Tunnels  []ssh.VPNPhase1Info      `json:"phase1_tunnels,omitempty"`
	Phase2Tunnels  []ssh.VPNPhase2Info      `json:"phase2_tunnels,omitempty"`
	Interfaces     []ssh.InterfaceErrorInfo `json:"interfaces,omitempty"`
	Sensors        []ssh.SensorDetailInfo   `json:"sensors,omitempty"`
	Processes      []ssh.ProcessInfo        `json:"processes,omitempty"`
	Performance    *ssh.PerformanceInfo     `json:"performance,omitempty"`
}

// Report is the top-level structure emitted to JSON.
type Report struct {
	Host    string        `json:"host"`
	Port    int           `json:"port"`
	User    string        `json:"user"`
	Command string        `json:"command"`
	Checks  []CheckResult `json:"checks"`
}

// Run is the production entry point. It parses args, resolves the password,
// connects, runs the requested check(s), and writes the output.
//
// args are the command-line arguments after the subcommand name (so
// "ssh-test --host=... sensor" becomes ["--host=...", "sensor"]).
// stdin is used when --password-stdin is passed.
//
// Returns a process exit code (0 = success, 1 = check failure, 2 = usage error).
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return run(args, stdin, stdout, stderr, DefaultConnector)
}

// run is the testable core — it accepts an injected Connector so tests can
// run without an SSH server.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, connector Connector) int {
	fs := flag.NewFlagSet("ssh-test", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		host          = fs.String("host", "", "FortiGate IP/hostname (required)")
		port          = fs.Int("port", 22, "SSH port")
		user          = fs.String("user", "", "SSH username (required)")
		passwordStdin = fs.Bool("password-stdin", false, "Read password from stdin (one line)")
		format        = fs.String("format", "json", "Output format: json|text")
	)

	if err := fs.Parse(args); err != nil {
		// flag already wrote the error
		return 2
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "ERROR: a check command is required")
		fmt.Fprintf(stderr, "Usage: ssh-test --host=<ip> --user=<user> [--port=22] [--password-stdin] [--format=json|text] <command>\n")
		fmt.Fprintln(stderr, "Commands: all | sensor | process | interface | license | performance | vpn | ha | checksum | config")
		return 2
	}
	command := fs.Arg(0)

	if *host == "" || *user == "" {
		fmt.Fprintln(stderr, "ERROR: --host and --user are required")
		return 2
	}

	password, err := resolvePassword(*passwordStdin, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if password == "" {
		fmt.Fprintf(stderr, "ERROR: password required (set %s env var or use --password-stdin)\n", PasswordEnvVar)
		return 2
	}

	checks := selectedChecks(command)
	if len(checks) == 0 {
		fmt.Fprintf(stderr, "ERROR: unknown command %q (want: all | sensor | process | interface | license | performance | vpn | ha | checksum | config)\n", command)
		return 2
	}

	report := &Report{
		Host:    *host,
		Port:    *port,
		User:    *user,
		Command: command,
		Checks:  []CheckResult{},
	}

	client, err := connector(*host, *port, *user, password)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: failed to build client: %v\n", err)
		return 1
	}

	if err := client.Connect(); err != nil {
		fmt.Fprintf(stderr, "ERROR: SSH connect failed: %v\n", err)
		return 1
	}
	defer client.Close()

	overallOK := true
	for _, name := range checks {
		result := runCheck(client, name)
		report.Checks = append(report.Checks, result)
		if !result.OK {
			overallOK = false
		}
	}

	if err := emit(report, *format, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "ERROR: emit: %v\n", err)
		return 1
	}

	if !overallOK {
		return 1
	}
	return 0
}

// resolvePassword returns the SSH password from PROBE_TEST_PASSWORD or
// --password-stdin (in that order). It does NOT consult os.Args — the env
// var is the authoritative source, --password-stdin just selects stdin as
// the fallback.
//
// If passwordStdin is true, exactly one line is read from stdin (trailing
// newline stripped). Empty stdin → empty password → caller reports the
// "password required" error.
func resolvePassword(passwordStdin bool, stdin io.Reader, stderr io.Writer) (string, error) {
	if pw := os.Getenv(PasswordEnvVar); pw != "" {
		return pw, nil
	}
	if !passwordStdin {
		return "", nil
	}
	if stdin == nil {
		return "", nil
	}
	scanner := bufio.NewScanner(stdin)
	if scanner.Scan() {
		return strings.TrimRight(scanner.Text(), "\r\n"), nil
	}
	return "", nil
}

// selectedChecks maps a top-level command name to the list of check names
// to run. "all" expands to every check.
func selectedChecks(command string) []string {
	switch command {
	case "all":
		return []string{"checksum", "config", "process", "interface", "sensor", "license", "performance", "vpn", "ha"}
	case "checksum", "config", "process", "interface", "sensor", "license", "performance", "vpn", "ha":
		return []string{command}
	default:
		return nil
	}
}

// runCheck executes one named check against the connected client and
// returns the structured result. Any error is captured in CheckResult.Error
// and reflected in CheckResult.OK — runCheck itself does not return errors.
func runCheck(client Client, name string) CheckResult {
	res := CheckResult{Name: name, OK: true}
	switch name {
	case "checksum":
		out, err := client.GetConfigChecksum()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.Checksum = out
			res.RawOutputBytes = len(out)
		}
	case "config":
		out, err := client.GetConfig()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.RawOutput = out
			res.RawOutputBytes = len(out)
			res.LineCount = len(strings.Split(out, "\n"))
		}
	case "process":
		out, err := client.GetProcessTop()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			parsed := ssh.ParseProcessTop(out)
			res.Processes = parsed
			res.ProcessCount = len(parsed)
			res.RawOutputBytes = len(out)
		}
	case "interface":
		out, err := client.GetInterfaceList()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			parsed := ssh.ParseInterfaceList(out)
			res.Interfaces = parsed
			res.InterfaceCount = len(parsed)
			res.RawOutputBytes = len(out)
		}
	case "sensor":
		out, err := client.GetSensorInfo()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			parsed := ssh.ParseSensorInfo(out)
			res.Sensors = parsed
			res.SensorCount = len(parsed)
			res.RawOutputBytes = len(out)
		}
	case "license":
		out, err := client.GetLicenseStatus()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.RawOutput = out
			res.RawOutputBytes = len(out)
			res.LineCount = len(strings.Split(out, "\n"))
		}
	case "performance":
		out, err := client.GetPerformanceStatus()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			parsed := ssh.ParsePerformanceStatus(out)
			res.Performance = parsed
			res.RawOutput = out
			res.RawOutputBytes = len(out)
		}
	case "vpn":
		phase1, phase2, err := client.GetVPNStatus()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.Phase1Tunnels = ssh.ParseVPNPhase1(phase1)
			res.Phase2Tunnels = ssh.ParseVPNPhase2(phase2)
			res.RawOutputBytes = len(phase1) + len(phase2)
		}
	case "ha":
		out, err := client.GetHAStatus()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.RawOutput = out
			res.RawOutputBytes = len(out)
			res.LineCount = len(strings.Split(out, "\n"))
		}
	default:
		res.OK = false
		res.Error = fmt.Sprintf("unknown check %q", name)
	}
	return res
}

// emit serializes the report to stdout in the requested format.
func emit(report *Report, format string, stdout, stderr io.Writer) error {
	switch format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "text":
		fmt.Fprintf(stdout, "host=%s port=%d user=%s command=%s\n",
			report.Host, report.Port, report.User, report.Command)
		for _, c := range report.Checks {
			if c.OK {
				switch c.Name {
				case "checksum":
					fmt.Fprintf(stdout, "  %s: ok (checksum=%s, raw_bytes=%d)\n", c.Name, c.Checksum, c.RawOutputBytes)
				case "config":
					fmt.Fprintf(stdout, "  %s: ok (lines=%d, raw_bytes=%d)\n", c.Name, c.LineCount, c.RawOutputBytes)
				case "process":
					fmt.Fprintf(stdout, "  %s: ok (processes=%d, raw_bytes=%d)\n", c.Name, c.ProcessCount, c.RawOutputBytes)
				case "interface":
					fmt.Fprintf(stdout, "  %s: ok (interfaces=%d, raw_bytes=%d)\n", c.Name, c.InterfaceCount, c.RawOutputBytes)
				case "sensor":
					fmt.Fprintf(stdout, "  %s: ok (sensors=%d, raw_bytes=%d)\n", c.Name, c.SensorCount, c.RawOutputBytes)
				case "license":
					fmt.Fprintf(stdout, "  %s: ok (lines=%d, raw_bytes=%d)\n", c.Name, c.LineCount, c.RawOutputBytes)
				case "performance":
					fmt.Fprintf(stdout, "  %s: ok (raw_bytes=%d)\n", c.Name, c.RawOutputBytes)
				case "vpn":
					fmt.Fprintf(stdout, "  %s: ok (phase1=%d, phase2=%d, raw_bytes=%d)\n",
						c.Name, len(c.Phase1Tunnels), len(c.Phase2Tunnels), c.RawOutputBytes)
				case "ha":
					fmt.Fprintf(stdout, "  %s: ok (lines=%d, raw_bytes=%d)\n", c.Name, c.LineCount, c.RawOutputBytes)
				default:
					fmt.Fprintf(stdout, "  %s: ok\n", c.Name)
				}
			} else {
				fmt.Fprintf(stdout, "  %s: FAILED (%s)\n", c.Name, c.Error)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text)", format)
	}
}
