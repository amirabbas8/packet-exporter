package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"packet-exporter/internal/flow"
)

type fake struct {
	series []flow.Series
}

func (f fake) Snapshot() ([]flow.Series, error) { return f.series, nil }

func TestCollectSumsDuplicateLabelSets(t *testing.T) {
	names := []string{"interface", "src_ip", "dst_ip", "src_port", "dst_port", "type"}
	c := NewCollector(names, map[string]string{"node": "n1"}, fake{series: []flow.Series{
		{Labels: []string{"eth0", "10.0.0.1", "10.0.0.2", "12345", "80", "syn"}, Packets: 1, Bytes: 60},
		{Labels: []string{"eth0", "10.0.0.1", "10.0.0.2", "12345", "80", "syn"}, Packets: 1, Bytes: 40},
	}})
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestCollectSkipsBadLabelCount(t *testing.T) {
	names := []string{"type"}
	c := NewCollector(names, nil, fake{series: []flow.Series{
		{Labels: []string{"syn"}, Packets: 3, Bytes: 90},
		{Labels: []string{"too", "many"}, Packets: 9, Bytes: 1},
	}})
	if err := testutil.CollectAndCompare(c, strings.NewReader(skipExpected)); err != nil {
		t.Fatal(err)
	}
}

const expected = `
# HELP packet_bytes_total Bytes observed on the attached interface, using the length reported by the traffic-control hook (L2 included).
# TYPE packet_bytes_total counter
packet_bytes_total{dst_ip="10.0.0.2",dst_port="80",interface="eth0",node="n1",src_ip="10.0.0.1",src_port="12345",type="syn"} 100
# HELP packet_scrape_errors Map entries skipped in this scrape because labels could not be rendered.
# TYPE packet_scrape_errors gauge
packet_scrape_errors{node="n1"} 0
# HELP packet_snapshot_errors_total Times reading the packet map failed.
# TYPE packet_snapshot_errors_total counter
packet_snapshot_errors_total{node="n1"} 0
# HELP packet_total Packets observed on the attached interface.
# TYPE packet_total counter
packet_total{dst_ip="10.0.0.2",dst_port="80",interface="eth0",node="n1",src_ip="10.0.0.1",src_port="12345",type="syn"} 2
`

const skipExpected = `
# HELP packet_bytes_total Bytes observed on the attached interface, using the length reported by the traffic-control hook (L2 included).
# TYPE packet_bytes_total counter
packet_bytes_total{type="syn"} 90
# HELP packet_scrape_errors Map entries skipped in this scrape because labels could not be rendered.
# TYPE packet_scrape_errors gauge
packet_scrape_errors 1
# HELP packet_snapshot_errors_total Times reading the packet map failed.
# TYPE packet_snapshot_errors_total counter
packet_snapshot_errors_total 0
# HELP packet_total Packets observed on the attached interface.
# TYPE packet_total counter
packet_total{type="syn"} 3
`
