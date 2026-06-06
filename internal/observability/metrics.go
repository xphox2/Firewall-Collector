// Package observability exposes the collector's internal state over HTTP
// for orchestrators (Kubernetes, Nomad, systemd) and SREs.
//
// Three endpoints are served on a single bind address (PROBE_METRICS_ADDR,
// default "127.0.0.1:9090" — loopback only, so a Prometheus scraper on
// another host must opt in via PROBE_METRICS_ADDR=0.0.0.0:9090):
//
//   - GET /healthz — process liveness. Returns 200 whenever the metrics
//     server itself is reachable, regardless of collector state. Used by
//     orchestrators to decide whether to restart the process.
//
//   - GET /readyz — probe readiness. Returns 200 only when the collector
//     is actually usable as a data source: approved by the central server,
//     last heartbeat within 2*HeartbeatInterval, and every enabled
//     listener is bound. Returns 503 otherwise (with a short reason body).
//     Used by orchestrators to decide whether to route traffic.
//
//   - GET /metrics — Prometheus text exposition. All gauges / counters
//     listed in AUDIT-057 §3 (queue depth, drop count, last-successful-poll,
//     listener bind state, heartbeat success/failure, etc.) are exposed
//     here with the firewall_collector_ prefix.
//
// Why a separate package: the collector's main loop (cmd/collector) is
// allowed to know about metrics, but the metrics package must not import
// it — that would create an import cycle once any listener started
// importing metrics. The callback pattern (Config.ApprovedFn etc.) keeps
// the dependency direction one-way: main → observability, never the
// reverse.
package observability

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config wires the observability server to the live collector state.
// All callbacks are invoked synchronously from the /readyz and /metrics
// handlers, so they must be cheap and non-blocking.
//
// Version / Vendor populate the firewall_collector_build_info gauge
// labels. Set them at startup; they're read-only thereafter.
type Config struct {
	// Addr is the bind address for the metrics server (e.g. ":9090",
	// "127.0.0.1:9090", "0.0.0.0:9090"). Required.
	Addr string

	// Version / Vendor populate the firewall_collector_build_info labels.
	// Version is the collector's build version (e.g. "1.2.99"); Vendor is
	// the deployment vendor string (e.g. "community"). Both are required
	// for build_info to render a single series.
	Version string
	Vendor  string

	// HeartbeatInterval is the configured heartbeat period. /readyz uses
	// it (×2) to decide whether the last heartbeat is fresh enough.
	HeartbeatInterval time.Duration

	// ApprovedFn returns whether the probe is currently approved by the
	// central server. /readyz fails when this returns false. Required.
	ApprovedFn func() bool

	// LastHeartbeatFn returns the time of the last successful heartbeat
	// to the central server (or the zero time if never). /readyz fails
	// when it's more than 2*HeartbeatInterval in the past. Required.
	LastHeartbeatFn func() time.Time

	// ListenerBoundFn returns whether a given named listener is bound.
	// Names are "snmp_trap", "syslog_tcp", "syslog_udp", "sflow", "tftp".
	// /readyz fails when a listener is enabled in config but not bound.
	// Required.
	ListenerBoundFn func(name string) bool

	// EnabledListenersFn returns the set of listener names that are
	// configured to be on. /readyz requires every enabled listener to
	// also be bound. Required.
	EnabledListenersFn func() []string
}

// Metrics is the collection of registered Prometheus instruments plus
// the bookkeeping needed by the /metrics and /readyz handlers. One
// instance is created at startup and shared for the process lifetime.
//
// All Set/Inc/Observe methods are safe for concurrent use; the
// underlying Prometheus client_golang collectors are already goroutine-
// safe, and our own mutexes (lastSuccessfulPoll) follow the same rules.
type Metrics struct {
	registry *prometheus.Registry
	cfg      Config

	uptime    prometheus.Gauge
	buildInfo *prometheus.GaugeVec

	heartbeatSuccess prometheus.Counter
	heartbeatFailure prometheus.Counter

	dataBatchSent *prometheus.CounterVec

	queueDepth   *prometheus.GaugeVec
	queueDropped *prometheus.CounterVec

	pollDuration    *prometheus.HistogramVec
	pollFailures    *prometheus.CounterVec
	lastPollSuccess *prometheus.GaugeVec

	listenerBound *prometheus.GaugeVec

	configRevisionsSent *prometheus.CounterVec
	reregisterAttempts  prometheus.Counter

	startTime time.Time

	// lastSuccessfulPoll maps deviceID → time.Time of the most recent
	// successful poll. Read by the /metrics handler to publish the
	// firewall_collector_last_successful_poll_timestamp gauge; written
	// by OnPollSuccess. Guarded by lastPollMu.
	lastPollMu         sync.RWMutex
	lastSuccessfulPoll map[uint]time.Time
	lastPollPublished  *prometheus.GaugeVec

	// queueDepthSource, if set, is consulted on every /metrics scrape to
	// pull the current queue depth into the gauge. This lets production
	// code wire a closure that reads from the relay client's internal
	// state without the observability package needing to import relay.
	queueDepthSource   func(queue string) int
	queueDroppedSource func(queue string) uint64

	// scrapes counts how many times /metrics has been served. Exposed
	// for tests as a cheap health signal (one scrape == one record).
	scrapes atomic.Uint64
}

// New constructs a Metrics with all collectors pre-registered against
// a private registry (we do NOT use the default registry — that would
// cause re-registration panics if any test imports this package twice
// and pull in package-level metrics from transitive deps).
//
// Build_info is set to 1 immediately so the series exists even before
// the first /metrics scrape; uptime is computed from startTime.
func New(cfg Config) *Metrics {
	if cfg.ApprovedFn == nil {
		cfg.ApprovedFn = func() bool { return false }
	}
	if cfg.LastHeartbeatFn == nil {
		cfg.LastHeartbeatFn = func() time.Time { return time.Time{} }
	}
	if cfg.ListenerBoundFn == nil {
		cfg.ListenerBoundFn = func(string) bool { return true }
	}
	if cfg.EnabledListenersFn == nil {
		cfg.EnabledListenersFn = func() []string { return nil }
	}

	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry:           reg,
		cfg:                cfg,
		startTime:          time.Now(),
		lastSuccessfulPoll: make(map[uint]time.Time),
	}

	m.uptime = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "firewall_collector_uptime_seconds",
		Help: "Seconds since the collector process started.",
	})

	m.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firewall_collector_build_info",
		Help: "Build metadata. Value is always 1; labels carry version/vendor.",
	}, []string{"version", "vendor"})
	m.buildInfo.WithLabelValues(cfg.Version, cfg.Vendor).Set(1)

	m.heartbeatSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "firewall_collector_heartbeat_success_total",
		Help: "Number of successful heartbeats sent to the central server.",
	})
	m.heartbeatFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "firewall_collector_heartbeat_failures_total",
		Help: "Number of failed heartbeat attempts to the central server.",
	})

	m.dataBatchSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firewall_collector_data_batch_sent_total",
		Help: "Number of data batches sent to the central server, labeled by queue and outcome (success|failure).",
	}, []string{"queue", "outcome"})

	m.queueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firewall_collector_queue_depth",
		Help: "Current depth of each outbound queue. Persistent growth indicates the collector cannot keep up with the central server.",
	}, []string{"queue"})

	m.queueDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firewall_collector_queue_dropped_total",
		Help: "Number of items dropped because a queue was full. Non-zero values mean silent data loss — investigate immediately.",
	}, []string{"queue"})

	m.pollDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "firewall_collector_poll_duration_seconds",
		Help: "Histogram of SNMP poll cycle durations per device.",
		// Buckets tuned for typical firewall SNMP responses: a healthy
		// device responds in <100ms; degraded devices 1-10s; broken 10s+.
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"device_id", "vendor"})

	m.pollFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firewall_collector_poll_failures_total",
		Help: "Number of failed polls per device, labeled by reason (timeout|conn_refused|auth|other).",
	}, []string{"device_id", "vendor", "reason"})

	m.lastPollPublished = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firewall_collector_last_successful_poll_timestamp",
		Help: "Unix timestamp of the last successful poll for each device. 0 means the device has never polled successfully.",
	}, []string{"device_id"})

	m.listenerBound = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firewall_collector_listener_bound",
		Help: "1 if the named listener is bound and accepting packets, 0 otherwise.",
	}, []string{"listener"})

	m.configRevisionsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firewall_collector_config_revisions_sent_total",
		Help: "Number of config revision backups sent, labeled by trigger (poll|syslog|manual) and quality (full|masked|unknown).",
	}, []string{"trigger", "quality"})

	m.reregisterAttempts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "firewall_collector_reregister_attempts_total",
		Help: "Number of times the probe attempted to re-register with the central server (e.g. after losing approval).",
	})

	reg.MustRegister(
		m.uptime,
		m.buildInfo,
		m.heartbeatSuccess,
		m.heartbeatFailure,
		m.dataBatchSent,
		m.queueDepth,
		m.queueDropped,
		m.pollDuration,
		m.pollFailures,
		m.lastPollPublished,
		m.listenerBound,
		m.configRevisionsSent,
		m.reregisterAttempts,
	)
	return m
}

// SetQueueDepthSource installs a callback that the /metrics handler
// invokes to refresh the firewall_collector_queue_depth gauge from
// live state. The callback must be cheap and non-blocking.
//
// Pass nil to disable auto-refresh; the gauge then only updates when
// SetQueueDepth is called directly (used by tests).
func (m *Metrics) SetQueueDepthSource(fn func(queue string) int) {
	m.queueDepthSource = fn
}

// SetQueueDroppedSource installs a callback for refreshing the
// firewall_collector_queue_dropped_total counter from live state. The
// counter is cumulative so this is normally a no-op; provided for
// symmetry with the depth source so production code can route both
// values through the same wiring point.
func (m *Metrics) SetQueueDroppedSource(fn func(queue string) uint64) {
	m.queueDroppedSource = fn
}

// OnHeartbeatSuccess increments the heartbeat success counter. Call
// after every successful sendHeartbeatWithStatus return.
func (m *Metrics) OnHeartbeatSuccess() {
	m.heartbeatSuccess.Inc()
}

// OnHeartbeatFailure increments the heartbeat failure counter. Call
// after every failed sendHeartbeatWithStatus return.
func (m *Metrics) OnHeartbeatFailure() {
	m.heartbeatFailure.Inc()
}

// OnDataBatchSent increments the data-batch counter for the given
// queue and outcome. Outcome is typically "success" or "failure".
func (m *Metrics) OnDataBatchSent(queue, outcome string) {
	m.dataBatchSent.WithLabelValues(queue, outcome).Inc()
}

// SetQueueDepth sets the firewall_collector_queue_depth gauge for the
// given queue. Used by tests and as a fallback when no source callback
// is installed.
func (m *Metrics) SetQueueDepth(queue string, depth int) {
	m.queueDepth.WithLabelValues(queue).Set(float64(depth))
}

// IncQueueDropped increments firewall_collector_queue_dropped_total
// for the given queue. Call from the SendXxx queue-full branches.
func (m *Metrics) IncQueueDropped(queue string) {
	m.queueDropped.WithLabelValues(queue).Inc()
}

// MarkPollSucceeded records the wall-clock instant of a successful
// poll: stores it in the internal map (for any future in-process
// readers) and publishes it on the
// firewall_collector_last_successful_poll_timestamp gauge.
//
// The poll duration is NOT observed here — call OnPollDuration
// separately (typically via a deferred call so success and failure
// paths both contribute to the histogram).
func (m *Metrics) MarkPollSucceeded(deviceID uint) {
	now := time.Now()
	m.lastPollMu.Lock()
	m.lastSuccessfulPoll[deviceID] = now
	m.lastPollMu.Unlock()
	m.lastPollPublished.WithLabelValues(deviceIDString(deviceID)).Set(float64(now.Unix()))
}

// OnPollFailure increments the per-device failure counter. Reason is
// free-form but should be one of a small set ("timeout", "conn_refused",
// "auth", "other") to keep label cardinality low.
func (m *Metrics) OnPollFailure(deviceID uint, vendor, reason string) {
	if vendor == "" {
		vendor = "unknown"
	}
	if reason == "" {
		reason = "other"
	}
	m.pollFailures.WithLabelValues(deviceIDString(deviceID), vendor, reason).Inc()
}

// OnPollDuration records the wall-clock duration of a poll attempt
// into the histogram, regardless of whether the poll succeeded. This
// is split out from OnPollSuccess so callers can defer the histogram
// observation (capturing both success and failure paths) and only
// invoke OnPollSuccess on the success path.
func (m *Metrics) OnPollDuration(deviceID uint, vendor string, duration time.Duration) {
	if vendor == "" {
		vendor = "unknown"
	}
	m.pollDuration.WithLabelValues(deviceIDString(deviceID), vendor).Observe(duration.Seconds())
}

// SetListenerBound sets the firewall_collector_listener_bound gauge
// for a named listener. Call after the listener's Start() returns
// successfully (bound=true) and after Stop() (bound=false).
func (m *Metrics) SetListenerBound(name string, bound bool) {
	v := 0.0
	if bound {
		v = 1.0
	}
	m.listenerBound.WithLabelValues(name).Set(v)
}

// OnConfigRevisionSent increments the config-revision counter for a
// given trigger and backup quality.
func (m *Metrics) OnConfigRevisionSent(trigger, quality string) {
	if trigger == "" {
		trigger = "unknown"
	}
	if quality == "" {
		quality = "unknown"
	}
	m.configRevisionsSent.WithLabelValues(trigger, quality).Inc()
}

// OnReregisterAttempt increments the re-registration counter. Call
// from the relay client whenever it begins a re-registration cycle.
func (m *Metrics) OnReregisterAttempt() {
	m.reregisterAttempts.Inc()
}

// Handler returns the http.Handler serving /healthz, /readyz, and
// /metrics. The handler is safe for concurrent use.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", m.handleHealthz)
	mux.HandleFunc("/readyz", m.handleReadyz)
	mux.Handle("/metrics", m.wrapMetricsHandler())
	return mux
}

// wrapMetricsHandler returns a handler that refreshes the
// callback-driven gauges just before delegating to the Prometheus
// exposition handler. This way the /metrics snapshot reflects live
// state at scrape time, not stale data from the last call to SetXxx.
func (m *Metrics) wrapMetricsHandler() http.Handler {
	inner := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		Registry: m.registry,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.refreshDynamic()
		m.scrapes.Add(1)
		m.uptime.Set(time.Since(m.startTime).Seconds())
		inner.ServeHTTP(w, r)
	})
}

// refreshDynamic pulls the latest depth values from the source
// callback (if installed) and updates the corresponding Prometheus
// gauges. Cheap when the source is nil.
//
// The dropped counter is intentionally not auto-refreshed: a
// Counter in Prometheus is monotonic, and overwriting it with Set is
// not allowed by the client_golang API. Production code should call
// IncQueueDropped at each drop site; this callback is provided for
// symmetry and may be wired in a future revision.
func (m *Metrics) refreshDynamic() {
	if m.queueDepthSource != nil {
		for _, q := range allQueueNames {
			m.queueDepth.WithLabelValues(q).Set(float64(m.queueDepthSource(q)))
		}
	}
}

// handleHealthz is a process-liveness probe. Returns 200 as long as
// the metrics server itself is running. Orchestrators should treat
// 200 as "the process exists, do not restart it."
func (m *Metrics) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz returns 200 only when the probe is fully ready to
// serve traffic: approved by the central server, last heartbeat fresh,
// and every enabled listener bound. Returns 503 with a one-line reason
// otherwise.
//
// Reason bodies are stable text so orchestrators can grep them.
func (m *Metrics) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.uptime.Set(time.Since(m.startTime).Seconds())

	checks := []struct {
		ok    bool
		why   string
		label string
	}{
		{m.cfg.ApprovedFn(), "not approved by central server", "approved"},
		{heartbeatFresh(m.cfg.LastHeartbeatFn(), m.cfg.HeartbeatInterval), "heartbeat stale or never sent", "heartbeat"},
		{allEnabledListenersBound(m.cfg.EnabledListenersFn(), m.cfg.ListenerBoundFn), "an enabled listener is not bound", "listeners"},
	}

	for _, c := range checks {
		if !c.ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Ready-Reason", c.label)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "not ready: %s\n", c.why)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// allQueueNames is the fixed set of queue names the metrics know
// about. Order matches the relay package's queue slice fields so the
// label values are stable across scrapes.
var allQueueNames = []string{"traps", "pings", "syslog", "flows"}

// heartbeatFresh returns true if `t` is within 2× interval of now.
// A zero time (never sent) is considered stale.
func heartbeatFresh(t time.Time, interval time.Duration) bool {
	if t.IsZero() {
		return false
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return time.Since(t) <= 2*interval
}

// allEnabledListenersBound returns true iff every name in the
// enabled slice is also bound according to bound. An empty enabled
// slice counts as "all bound" (vacuously true).
func allEnabledListenersBound(enabled []string, bound func(string) bool) bool {
	for _, name := range enabled {
		if !bound(name) {
			return false
		}
	}
	return true
}

// deviceIDString formats a device ID for use as a Prometheus label.
// uint is enough for this codebase but we keep the conversion in one
// place in case the format ever needs to change.
func deviceIDString(id uint) string {
	return fmt.Sprintf("%d", id)
}
