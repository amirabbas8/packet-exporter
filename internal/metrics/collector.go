// Package metrics exports packet_total and packet_bytes_total.
package metrics

import (
	"log"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"packet-exporter/internal/flow"
)

// Source is the live BPF map.
type Source interface {
	Snapshot() ([]flow.Series, error)
}

// DropSource is optional; collectors export packet_drop_total when present.
type DropSource interface {
	Drops() (map[string]uint64, error)
}

// MapSource is optional; collectors export current LRU occupancy when present.
type MapSource interface {
	MapInfo() (used, max uint64)
}

// Collector aggregates flows that render to the same label set.
type Collector struct {
	source         Source
	names          []string
	snapshotFails  atomic.Uint64
	packets        *prometheus.Desc
	bytes          *prometheus.Desc
	drops          *prometheus.Desc
	scrapeErrors   *prometheus.Desc
	snapshotErrors *prometheus.Desc
	mapEntries     *prometheus.Desc
	mapMax         *prometheus.Desc
}

// NewCollector builds the two counters. names are the dynamic labels.
// static labels are attached to every series.
func NewCollector(names []string, static map[string]string, source Source) *Collector {
	constLabels := prometheus.Labels(static)
	return &Collector{
		source: source,
		names:  names,
		packets: prometheus.NewDesc(
			"packet_total",
			"Packets observed on the attached interface.",
			names,
			constLabels,
		),
		bytes: prometheus.NewDesc(
			"packet_bytes_total",
			"Bytes observed on the attached interface, using the length reported by the traffic-control hook (L2 included).",
			names,
			constLabels,
		),
		drops: prometheus.NewDesc(
			"packet_drop_total",
			"Packets the parser skipped (not_ip, truncated, fragment, ext_hdr, vlan, update_race, l4).",
			[]string{"reason"},
			constLabels,
		),
		scrapeErrors: prometheus.NewDesc(
			"packet_scrape_errors",
			"Map entries skipped in this scrape because labels could not be rendered.",
			nil,
			constLabels,
		),
		snapshotErrors: prometheus.NewDesc(
			"packet_snapshot_errors_total",
			"Times reading the packet map failed.",
			nil,
			constLabels,
		),
		mapEntries: prometheus.NewDesc(
			"packet_map_entries",
			"Keys currently in the kernel LRU hash. Eviction starts when this reaches packet_map_max_entries.",
			nil,
			constLabels,
		),
		mapMax: prometheus.NewDesc(
			"packet_map_max_entries",
			"Capacity of the kernel LRU hash.",
			nil,
			constLabels,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packets
	ch <- c.bytes
	ch <- c.drops
	ch <- c.scrapeErrors
	ch <- c.snapshotErrors
	ch <- c.mapEntries
	ch <- c.mapMax
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	series, err := c.source.Snapshot()
	if err != nil {
		log.Printf("scrape packet map: %v", err)
		c.snapshotFails.Add(1)
		ch <- prometheus.MustNewConstMetric(c.scrapeErrors, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.snapshotErrors, prometheus.CounterValue, float64(c.snapshotFails.Load()))
		return
	}
	type sum struct {
		packets uint64
		bytes   uint64
		labels  []string
	}
	agg := make(map[string]*sum, len(series))
	var skipped float64
	for _, s := range series {
		if len(s.Labels) != len(c.names) {
			log.Printf("scrape packet map: got %d labels, want %d", len(s.Labels), len(c.names))
			skipped++
			continue
		}
		k := strings.Join(s.Labels, "\xff")
		cur := agg[k]
		if cur == nil {
			cur = &sum{labels: s.Labels}
			agg[k] = cur
		}
		cur.packets += s.Packets
		cur.bytes += s.Bytes
	}
	for _, s := range agg {
		ch <- prometheus.MustNewConstMetric(c.packets, prometheus.CounterValue, float64(s.packets), s.labels...)
		ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.CounterValue, float64(s.bytes), s.labels...)
	}
	ch <- prometheus.MustNewConstMetric(c.scrapeErrors, prometheus.GaugeValue, skipped)
	ch <- prometheus.MustNewConstMetric(c.snapshotErrors, prometheus.CounterValue, float64(c.snapshotFails.Load()))

	if m, ok := c.source.(MapSource); ok {
		used, max := m.MapInfo()
		ch <- prometheus.MustNewConstMetric(c.mapEntries, prometheus.GaugeValue, float64(used))
		ch <- prometheus.MustNewConstMetric(c.mapMax, prometheus.GaugeValue, float64(max))
	}

	if d, ok := c.source.(DropSource); ok {
		counts, err := d.Drops()
		if err != nil {
			log.Printf("scrape drop map: %v", err)
			return
		}
		for reason, n := range counts {
			ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, float64(n), reason)
		}
	}
}
