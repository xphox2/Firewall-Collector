package relay

import (
	"path/filepath"
	"testing"

	"firewall-collector/internal/relay/queue"
)

// TestEnsureQueues_AUDIT058 pins the disk-spillover wiring: an empty
// QueueDiskPath leaves the queues disabled (nil — Send* drops safely), while a
// configured path opens all five spools and creates the directory on demand.
func TestEnsureQueues_AUDIT058(t *testing.T) {
	// Empty path → queues stay disabled (nil).
	cEmpty := &Client{Config: Config{QueueDiskPath: ""}}
	cEmpty.ensureQueues()
	if cEmpty.trapQueue != nil || cEmpty.revisionQueue != nil {
		t.Error("empty QueueDiskPath should leave queues disabled (nil)")
	}

	// Configured path → all five spools open. The subdir does not exist yet, so
	// this also exercises the MkdirAll-on-demand path.
	dir := filepath.Join(t.TempDir(), "created-on-demand")
	c := &Client{Config: Config{QueueDiskPath: dir}}
	c.ensureQueues()

	queues := map[string]*queue.SpilloverQueue{
		"trap":          c.trapQueue,
		"ping":          c.pingQueue,
		"syslog":        c.syslogQueue,
		"flow":          c.flowQueue,
		"flow-counters": c.flowCounterQueue, // R5: sFlow interface counters (schema v2)
		"revision":      c.revisionQueue,
		"metric":        c.metricQueue, // H9: primary-metric spillover queue
	}
	for name, q := range queues {
		if q == nil {
			t.Errorf("%s queue is nil; want opened for path %s", name, dir)
		}
	}
	for _, q := range queues {
		if q != nil {
			_ = q.Close()
		}
	}
}
