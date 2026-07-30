package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"firewall-collector/internal/fwapi"
	"firewall-collector/internal/relay"
)

// commandExecutor executes server→collector commands delivered on the
// heartbeat response (relay schema v4) and reports each outcome to
// POST /api/probes/:id/command-result.
//
// Semantics:
//   - The server delivers at-least-once (it re-sends a command whose result
//     it hasn't received), so the executor DEDUPES by CommandID: an in-flight
//     command is skipped, and a redelivered already-completed command is NOT
//     re-executed — its CACHED result is re-POSTed instead (this is what
//     recovers from a lost result POST). The server is idempotent by
//     CommandID, so duplicate result POSTs are safe.
//   - Unknown command types report `failed` immediately — better a crisp
//     failure than a command sitting dispatched until the server expires it.
//   - A command already past its ExpiresAt is not executed (defense in depth;
//     the server also refuses to deliver expired commands).
//
// SECURITY: command payloads may carry credentials for future command types
// (IPSec PSKs, API secrets). NEVER log a payload — log CommandID + Type only.
type commandExecutor struct {
	sink commandResultSink

	mu sync.Mutex
	// inFlight tracks CommandIDs currently executing.
	inFlight map[string]bool
	// completed caches the result of recently-finished commands by CommandID
	// so a redelivery re-POSTs the cached result instead of re-executing.
	// Bounded by pruning entries older than completedTTL.
	completed map[string]completedCommand
	// deviceMu serializes config-WRITE commands per device. A batch runs its
	// commands sequentially, but the relay dispatches one goroutine PER heartbeat
	// (relay.HandleCommands off the heartbeat path), so an apply and a rollback
	// delivered on different heartbeats could otherwise interleave POST/DELETE on
	// the same firewall. Each write handler holds its device's lock for the whole
	// apply/verify (or remove).
	deviceMu map[uint]*sync.Mutex

	// handlers maps a command type to its implementation. A handler returns
	// the result text (echoed to the server, capped there) or an error.
	handlers map[string]func(cmd relay.PendingCommand) (string, error)
}

type completedCommand struct {
	result relay.CommandResult
	at     time.Time
}

// commandResultSink is the slice of *relay.Client the executor needs —
// injectable so tests can capture results without a live relay.
type commandResultSink interface {
	SendCommandResult(res relay.CommandResult) error
}

// completedTTL bounds the completed-result cache. Longer than any plausible
// server redelivery horizon (commands expire server-side at 15 min default).
const completedTTL = time.Hour

func newCommandExecutor(sink commandResultSink) *commandExecutor {
	e := &commandExecutor{
		sink:      sink,
		inFlight:  make(map[string]bool),
		completed: make(map[string]completedCommand),
		deviceMu:  make(map[uint]*sync.Mutex),
		handlers:  make(map[string]func(relay.PendingCommand) (string, error)),
	}
	// noop: the end-to-end proof command (PR-1). Executes as an immediate
	// success so the enqueue → heartbeat delivery → execution → result-ingest
	// round-trip can be verified before any command type that writes device
	// configuration exists.
	e.handlers["noop"] = func(cmd relay.PendingCommand) (string, error) {
		return "noop executed", nil
	}
	// ipsec_preflight (PR-C1): a READ-ONLY REST preflight for an IPSec deploy —
	// authenticate to the device API and GET the objects a deploy would create
	// (collision checks). Performs NO device writes. Returns the structured
	// report as JSON. The payload carries the API token — NEVER log it.
	e.handlers["ipsec_preflight"] = func(cmd relay.PendingCommand) (string, error) {
		var p fwapi.PreflightPayload
		if err := json.Unmarshal([]byte(cmd.Payload), &p); err != nil {
			return "", fmt.Errorf("invalid preflight payload: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		report := fwapi.RunPreflight(ctx, p)
		out, err := json.Marshal(report)
		if err != nil {
			return "", fmt.Errorf("marshal preflight report: %w", err)
		}
		return string(out), nil
	}
	// apply_ipsec / remove_ipsec (C2b-1): WRITE one IPSec tunnel end to the device
	// (FortiGate only). The handler checksum-verifies, collision-prechecks, writes,
	// and verifies (apply) or ownership-checks + deletes (remove). The payload
	// carries the PSK — NEVER log it. Writes are serialized per device.
	e.handlers["apply_ipsec"] = func(cmd relay.PendingCommand) (string, error) {
		return e.runIPSecWrite(cmd, false)
	}
	e.handlers["remove_ipsec"] = func(cmd relay.PendingCommand) (string, error) {
		return e.runIPSecWrite(cmd, true)
	}
	// ipsec_status (C2b-2b): READ-ONLY SA-liveness probe of one deployed tunnel
	// end. Runs the server-rendered GET steps and returns the raw device
	// documents; the SERVER parses them (vendor ParseStatus stays server-side).
	// Read-only — no device mutex (consistent with ipsec_preflight).
	e.handlers["ipsec_status"] = runIPSecRead
	// ipsec_telemetry: the SAME read-only mechanism, but recurring rather than
	// one-shot, and carrying several GETs whose documents the server correlates
	// into per-child-SA telemetry rows. It is a distinct type because
	// ipsec_status is deploy verification — first-result-wins, single step — and
	// polling must not inherit those semantics.
	e.handlers["ipsec_telemetry"] = runIPSecRead
	return e
}

// runIPSecRead executes server-rendered read-only GET steps and returns the raw
// device documents. The SERVER parses them: vendor parsing stays server-side, so
// the collector needs no vendor knowledge and no release when parsing changes.
// Read-only, so no device mutex (consistent with ipsec_preflight).
func runIPSecRead(cmd relay.PendingCommand) (string, error) {
	var p fwapi.StatusPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &p); err != nil {
		return "", fmt.Errorf("invalid status payload: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report := fwapi.RunStatusProbe(ctx, p)
	out, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("marshal status report: %w", err)
	}
	return string(out), nil
}

// runIPSecWrite executes an apply_ipsec (remove=false) or remove_ipsec
// (remove=true). C2b-1 supports FortiGate only; any other vendor is rejected
// before any device contact. The whole apply/verify (or remove) holds the
// device's write lock so concurrent commands can't interleave on one firewall.
func (e *commandExecutor) runIPSecWrite(cmd relay.PendingCommand, remove bool) (string, error) {
	var p fwapi.ApplyPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &p); err != nil {
		return "", fmt.Errorf("invalid apply payload: %w", err)
	}
	if p.Vendor != "fortigate" && p.Vendor != "opnsense" {
		return "", fmt.Errorf("apply not supported for vendor %q", p.Vendor)
	}
	unlock := e.lockDevice(p.DeviceID)
	defer unlock()

	// Generous timeout: writes + collision precheck + verify GETs against a busy
	// firewall REST API.
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	var report fwapi.ApplyReport
	if remove {
		report = fwapi.RunRemove(ctx, p)
	} else {
		report = fwapi.RunApply(ctx, p)
	}
	out, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("marshal apply report: %w", err)
	}
	return string(out), nil
}

// lockDevice acquires (creating if needed) the per-device write mutex and returns
// its unlock func.
func (e *commandExecutor) lockDevice(deviceID uint) func() {
	e.mu.Lock()
	m := e.deviceMu[deviceID]
	if m == nil {
		m = &sync.Mutex{}
		e.deviceMu[deviceID] = m
	}
	e.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// HandleCommands is the relay.Client command-handler callback: executes each
// deliverable command and reports its result. Runs on the relay's dispatch
// goroutine (already off the heartbeat path); commands within a batch run
// sequentially — ordering within one heartbeat is deterministic, and future
// config-write commands must not run concurrently against the same device.
func (e *commandExecutor) HandleCommands(cmds []relay.PendingCommand) {
	for _, cmd := range cmds {
		e.handleOne(cmd)
	}
}

func (e *commandExecutor) handleOne(cmd relay.PendingCommand) {
	if cmd.CommandID == "" {
		return
	}

	e.mu.Lock()
	if e.inFlight[cmd.CommandID] {
		e.mu.Unlock()
		return // still executing — redelivery raced a long-running command
	}
	e.pruneCompletedLocked()
	if done, ok := e.completed[cmd.CommandID]; ok {
		e.mu.Unlock()
		// Already executed: the redelivery means the server never got the
		// result (lost POST). Re-send the CACHED result — never re-execute.
		if err := e.sink.SendCommandResult(done.result); err != nil {
			log.Printf("[Commands] cached result re-POST for %s failed: %v", cmd.CommandID, err)
		}
		return
	}
	e.inFlight[cmd.CommandID] = true
	e.mu.Unlock()

	status := "succeeded"
	var resultText string

	switch {
	case !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt):
		// Defense in depth — the server shouldn't deliver an expired command,
		// but a stale one must never execute (future types write config).
		status = "failed"
		resultText = "command expired before execution"
	default:
		handler, ok := e.handlers[cmd.Type]
		if !ok {
			status = "failed"
			resultText = fmt.Sprintf("unknown command type %q", cmd.Type)
		} else if out, err := handler(cmd); err != nil {
			status = "failed"
			resultText = err.Error()
		} else {
			resultText = out
		}
	}

	res := relay.CommandResult{
		CommandID: cmd.CommandID,
		Status:    status,
		Result:    resultText,
	}

	e.mu.Lock()
	delete(e.inFlight, cmd.CommandID)
	e.completed[cmd.CommandID] = completedCommand{result: res, at: time.Now()}
	e.mu.Unlock()

	// Log type + id + outcome ONLY — never the payload or result detail
	// (future command output may echo device configuration).
	log.Printf("[Commands] %s command %s -> %s", cmd.Type, cmd.CommandID, status)

	if err := e.sink.SendCommandResult(res); err != nil {
		// Best-effort: the server re-delivers after its redelivery window and
		// the cached-result branch above re-POSTs without re-executing.
		log.Printf("[Commands] result POST for %s failed: %v", cmd.CommandID, err)
	}
}

// pruneCompletedLocked drops completed-result cache entries older than
// completedTTL. Caller holds e.mu.
func (e *commandExecutor) pruneCompletedLocked() {
	cutoff := time.Now().Add(-completedTTL)
	for id, done := range e.completed {
		if done.at.Before(cutoff) {
			delete(e.completed, id)
		}
	}
}
