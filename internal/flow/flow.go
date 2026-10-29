// Package flow turns a packet map key into Prometheus label values.
package flow

import (
	"fmt"
	"net"
	"strconv"
)

// Key is the identity stored in the BPF map, after dropped fields are zeroed.
type Key struct {
	Ifindex   uint32
	Direction uint8
	Type      uint8
	Family    uint8
	SrcPort   uint16
	DstPort   uint16
	Src       [16]byte
	Dst       [16]byte
}

// Series is one aggregated flow.
type Series struct {
	Labels  []string
	Packets uint64
	Bytes   uint64
}

// Labels returns values in the same order as names.
func Labels(k Key, names []string, ifName func(uint32) string) ([]string, error) {
	out := make([]string, len(names))
	for i, name := range names {
		switch name {
		case "interface":
			out[i] = ifName(k.Ifindex)
		case "src_ip":
			out[i] = formatIP(k.Family, k.Src)
		case "dst_ip":
			out[i] = formatIP(k.Family, k.Dst)
		case "src_port":
			out[i] = strconv.FormatUint(uint64(k.SrcPort), 10)
		case "dst_port":
			out[i] = strconv.FormatUint(uint64(k.DstPort), 10)
		case "type":
			out[i] = TypeName(k.Type)
		case "direction":
			out[i] = DirectionName(k.Direction)
		default:
			return nil, fmt.Errorf("unknown label %q", name)
		}
	}
	return out, nil
}

// TypeName maps the BPF type byte to the Prometheus label value.
func TypeName(v uint8) string {
	switch v {
	case 1:
		return "syn"
	case 2:
		return "synack"
	case 3:
		return "rst"
	case 4:
		return "fin"
	case 5:
		return "ack"
	case 6:
		return "udp"
	case 7:
		return "icmp"
	default:
		return "unknown"
	}
}

// DirectionName maps the hook that saw the packet.
func DirectionName(v uint8) string {
	switch v {
	case 0:
		return "ingress"
	case 1:
		return "egress"
	default:
		return "unknown"
	}
}

func formatIP(family uint8, addr [16]byte) string {
	switch family {
	case 4:
		return net.IP(addr[:4]).String()
	case 6:
		return net.IP(addr[:]).String()
	default:
		return "unknown"
	}
}
