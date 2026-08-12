package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("test_total", "A test counter.")
	c.Inc()
	c.Add(4)
	if got := c.Value(); got != 5 {
		t.Fatalf("counter = %d, want 5", got)
	}
	// The same name must return the same instrument, not a fresh one.
	if r.Counter("test_total", "").Value() != 5 {
		t.Fatal("re-registering a counter reset it")
	}
}

func TestGauge(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("test_gauge", "A test gauge.")
	g.Set(10)
	g.Add(-3)
	if got := g.Value(); got != 7 {
		t.Fatalf("gauge = %d, want 7", got)
	}
}

func TestHistogramBuckets(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("test_seconds", "A test histogram.", []float64{1, 5, 10})

	for _, v := range []float64{0.5, 2, 7, 100} {
		h.Observe(v)
	}
	out := r.Render()

	// Buckets are cumulative: each includes everything below it.
	for _, want := range []string{
		`test_seconds_bucket{le="1"} 1`,
		`test_seconds_bucket{le="5"} 2`,
		`test_seconds_bucket{le="10"} 3`,
		`test_seconds_bucket{le="+Inf"} 4`,
		`test_seconds_count 4`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHistogramDuration(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("test_latency", "", nil)
	h.ObserveDuration(250 * time.Millisecond)
	out := r.Render()
	if !strings.Contains(out, "test_latency_count 1") {
		t.Fatalf("duration was not recorded:\n%s", out)
	}
}

func TestPrometheusFormat(t *testing.T) {
	r := NewRegistry()
	r.Counter("layer1_blocks_total", "Blocks seen.").Add(3)
	r.Gauge("layer1_peers", "Connected peers.").Set(5)

	out := r.Render()
	for _, want := range []string{
		"# HELP layer1_blocks_total Blocks seen.",
		"# TYPE layer1_blocks_total counter",
		"layer1_blocks_total 3",
		"# TYPE layer1_peers gauge",
		"layer1_peers 5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputIsStable(t *testing.T) {
	// A scrape must produce the same ordering every time, or diffing two
	// scrapes becomes useless.
	r := NewRegistry()
	for _, name := range []string{"z_total", "a_total", "m_total"} {
		r.Counter(name, "")
	}
	if r.Render() != r.Render() {
		t.Fatal("metric output is not deterministic")
	}
	out := r.Render()
	if strings.Index(out, "a_total") > strings.Index(out, "z_total") {
		t.Fatal("metrics are not sorted by name")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	m := NewNodeMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.BlocksImported.Inc()
				m.PeerCount.Set(int64(j))
				m.BlockExecution.Observe(0.01)
			}
		}()
	}
	wg.Wait()

	if got := m.BlocksImported.Value(); got != 2000 {
		t.Fatalf("counter lost updates under concurrency: %d, want 2000", got)
	}
	if !strings.Contains(m.Render(), "layer1_block_execution_seconds_count 2000") {
		t.Fatal("histogram lost observations under concurrency")
	}
}

func TestNodeMetricsAreNamedConsistently(t *testing.T) {
	out := NewNodeMetrics().Render()
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "layer1_") {
			t.Errorf("metric is missing the layer1_ prefix: %q", line)
		}
	}
}
