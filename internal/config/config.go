// Package config loads the label set exported by the packet counters.
package config

import (
	"fmt"
	"os"
	"regexp"
)

// Label bits must match bpf/packet.bpf.c.
const (
	LabelInterface uint32 = 1 << 0
	LabelSrcIP     uint32 = 1 << 1
	LabelDstIP     uint32 = 1 << 2
	LabelSrcPort   uint32 = 1 << 3
	LabelDstPort   uint32 = 1 << 4
	LabelType      uint32 = 1 << 5
	LabelDirection uint32 = 1 << 6
)

// DefaultLabels is the series identity used when config omits the labels key.
var DefaultLabels = []string{
	"interface",
	"src_ip",
	"dst_ip",
	"src_port",
	"dst_port",
	"type",
}

var known = map[string]uint32{
	"interface": LabelInterface,
	"src_ip":    LabelSrcIP,
	"dst_ip":    LabelDstIP,
	"src_port":  LabelSrcPort,
	"dst_port":  LabelDstPort,
	"type":      LabelType,
	"direction": LabelDirection,
}

var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Config is the label set for packet_total and packet_bytes_total.
type Config struct {
	Labels       []string
	StaticLabels map[string]string
	mask         uint32
}

// Parse decodes YAML. A missing labels key uses DefaultLabels. An empty
// labels list keeps no dynamic labels.
func Parse(data []byte) (Config, error) {
	var raw struct {
		Labels       *[]string         `yaml:"labels"`
		StaticLabels map[string]string `yaml:"static_labels"`
	}
	if err := unmarshal(data, &raw); err != nil {
		return Config{}, err
	}

	labels := append([]string(nil), DefaultLabels...)
	if raw.Labels != nil {
		labels = append([]string(nil), (*raw.Labels)...)
	}

	seen := make(map[string]struct{}, len(labels))
	var mask uint32
	for _, name := range labels {
		bit, ok := known[name]
		if !ok {
			return Config{}, fmt.Errorf("unknown label %q", name)
		}
		if _, dup := seen[name]; dup {
			return Config{}, fmt.Errorf("duplicate label %q", name)
		}
		seen[name] = struct{}{}
		mask |= bit
	}

	static := raw.StaticLabels
	if static == nil {
		static = map[string]string{}
	}
	for name := range static {
		if !labelName.MatchString(name) || len(name) >= 2 && name[0] == '_' && name[1] == '_' {
			return Config{}, fmt.Errorf("invalid static label %q", name)
		}
		if _, ok := known[name]; ok {
			return Config{}, fmt.Errorf("static label %q duplicates a dynamic label", name)
		}
		if _, dup := seen[name]; dup {
			return Config{}, fmt.Errorf("duplicate label %q", name)
		}
		seen[name] = struct{}{}
	}

	return Config{Labels: labels, StaticLabels: static, mask: mask}, nil
}

// Load reads a YAML file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Mask is the bitmask written into the BPF label_mask map.
func (c Config) Mask() uint32 {
	return c.mask
}
