package flow

import (
	"net"
	"testing"
)

func TestLabels(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], net.ParseIP("10.0.0.1").To4())
	copy(dst[:], net.ParseIP("10.0.0.2").To4())
	key := Key{
		Ifindex:   2,
		Direction: 1,
		Type:      2,
		Family:    4,
		SrcPort:   40000,
		DstPort:   443,
		Src:       src,
		Dst:       dst,
	}
	names := []string{"interface", "src_ip", "dst_ip", "src_port", "dst_port", "type", "direction"}
	got, err := Labels(key, names, func(uint32) string { return "eth0" })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"eth0", "10.0.0.1", "10.0.0.2", "40000", "443", "synack", "egress"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("label %s: got %q want %q", names[i], got[i], want[i])
		}
	}
}

func TestFormatIPv6(t *testing.T) {
	var addr [16]byte
	copy(addr[:], net.ParseIP("2001:db8::1").To16())
	got, err := Labels(Key{Family: 6, Src: addr, Type: 6}, []string{"src_ip", "type"}, func(uint32) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "2001:db8::1" || got[1] != "udp" {
		t.Fatalf("%#v", got)
	}
}

func TestUnknownFamily(t *testing.T) {
	got, err := Labels(Key{Family: 0, Type: 1}, []string{"src_ip", "type"}, func(uint32) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "unknown" || got[1] != "syn" {
		t.Fatalf("%#v", got)
	}
}

func TestTypeAndDirectionNames(t *testing.T) {
	types := map[uint8]string{1: "syn", 2: "synack", 3: "rst", 4: "fin", 5: "ack", 6: "udp", 7: "icmp", 9: "unknown"}
	for n, name := range types {
		if TypeName(n) != name {
			t.Fatalf("%d -> %s", n, TypeName(n))
		}
	}
	if DirectionName(0) != "ingress" || DirectionName(1) != "egress" || DirectionName(3) != "unknown" {
		t.Fatal(DirectionName(0), DirectionName(1), DirectionName(3))
	}
}
