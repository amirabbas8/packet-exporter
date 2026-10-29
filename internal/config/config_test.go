package config

import "testing"

func TestParseDefaultLabels(t *testing.T) {
	cfg, err := Parse([]byte("static_labels:\n  node: compute-1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.Mask(), uint32(0x3f); got != want {
		t.Fatalf("mask %#x, want %#x", got, want)
	}
	if cfg.StaticLabels["node"] != "compute-1" {
		t.Fatalf("static labels: %#v", cfg.StaticLabels)
	}
	if len(cfg.Labels) != len(DefaultLabels) {
		t.Fatalf("labels: %#v", cfg.Labels)
	}
}

func TestParseDropAndAdd(t *testing.T) {
	cfg, err := Parse([]byte(`
labels:
  - interface
  - src_ip
  - dst_ip
  - dst_port
  - type
  - direction
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mask()&LabelSrcPort != 0 {
		t.Fatal("src_port still set")
	}
	if cfg.Mask()&LabelDirection == 0 {
		t.Fatal("direction not set")
	}
	if cfg.Labels[len(cfg.Labels)-1] != "direction" {
		t.Fatalf("order: %#v", cfg.Labels)
	}
}

func TestParseEmptyDynamicLabels(t *testing.T) {
	cfg, err := Parse([]byte("labels: []\nstatic_labels:\n  node: n1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mask() != 0 || len(cfg.Labels) != 0 {
		t.Fatalf("cfg: %#v mask %#x", cfg.Labels, cfg.Mask())
	}
}

func TestShippedConfig(t *testing.T) {
	cfg, err := Load("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mask() != 0x3f {
		t.Fatalf("mask %#x", cfg.Mask())
	}
	if len(cfg.StaticLabels) != 0 {
		t.Fatalf("static labels: %#v", cfg.StaticLabels)
	}
}

func TestMaskBitsMatchNames(t *testing.T) {
	for name, bit := range known {
		cfg, err := Parse([]byte("labels: [" + name + "]\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Mask() != bit {
			t.Fatalf("%s mask %#x want %#x", name, cfg.Mask(), bit)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := []string{
		"labels: [vlan]",
		"labels: [src_ip, src_ip]",
		"labels: [src_ip]\nstatic_labels:\n  src_ip: x",
		"static_labels:\n  __name__: x",
		"static_labels:\n  \"bad-name\": x",
	}
	for _, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}
