//go:build linux

package probe

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"packet-exporter/internal/config"
	"packet-exporter/internal/flow"
	"packet-exporter/internal/route"
)

// statKey matches struct packet_key in bpf/packet.bpf.c.
type statKey struct {
	Ifindex   uint32
	Direction uint8
	Type      uint8
	Family    uint8
	Pad       uint8
	SrcPort   uint16
	DstPort   uint16
	Src       [16]byte
	Dst       [16]byte
}

// statValue matches struct packet_value.
type statValue struct {
	Packets uint64
	Bytes   uint64
}

// Program is a loaded counter attached to one interface.
type Program struct {
	objs    packetObjects
	links   []link.Link
	filters []*netlink.BpfFilter
	labels  []string
	iface   string
	mapMax  uint32
	mapUsed atomic.Uint64
}

// Open loads the program, applies cfg, and attaches it to iface.
// An empty iface uses the host default route.
func Open(cfg config.Config, iface string, mapEntries uint32) (*Program, error) {
	if mapEntries == 0 {
		return nil, errors.New("map entries must be greater than zero")
	}
	if iface == "" {
		name, err := route.DefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("IFACE is empty: %w", err)
		}
		iface = name
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	raiseMemlock()

	spec, err := loadPacket()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	stats := spec.Maps["packet_stats"]
	if stats == nil {
		return nil, errors.New("packet_stats map missing from program")
	}
	if ks, vs := uint32(unsafe.Sizeof(statKey{})), uint32(unsafe.Sizeof(statValue{})); stats.KeySize != ks || stats.ValueSize != vs {
		return nil, fmt.Errorf("packet_stats layout: bpf key/value %d/%d, go %d/%d", stats.KeySize, stats.ValueSize, ks, vs)
	}
	stats.MaxEntries = mapEntries

	var objs packetObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		objs.Close()
		return nil, fmt.Errorf("load program: %w", err)
	}

	mask := cfg.Mask()
	if err := objs.LabelMask.Put(uint32(0), mask); err != nil {
		objs.Close()
		return nil, fmt.Errorf("set label mask: %w", err)
	}

	p := &Program{objs: objs, labels: cfg.Labels, iface: iface, mapMax: mapEntries}
	if err := p.attach(ifi.Index); err != nil {
		p.Close()
		return nil, err
	}
	log.Printf("counting on %s with labels %v", iface, cfg.Labels)
	return p, nil
}

func (p *Program) attach(ifindex int) error {
	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.PacketIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Printf("tcx attach failed (%v); using clsact", err)
		return p.attachClsact(ifindex)
	}
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.PacketEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		ingress.Close()
		log.Printf("tcx egress failed (%v); using clsact", err)
		return p.attachClsact(ifindex)
	}
	p.links = []link.Link{ingress, egress}
	log.Printf("attached tcx ingress and egress")
	return nil
}

func (p *Program) attachClsact(ifindex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("clsact qdisc on %s: %w", p.iface, err)
	}
	in, err := addFilter(ifindex, netlink.HANDLE_MIN_INGRESS, "pkt-ing", p.objs.PacketIngress)
	if err != nil {
		return err
	}
	eg, err := addFilter(ifindex, netlink.HANDLE_MIN_EGRESS, "pkt-eg", p.objs.PacketEgress)
	if err != nil {
		_ = netlink.FilterDel(in)
		return err
	}
	p.filters = []*netlink.BpfFilter{in, eg}
	log.Printf("attached clsact ingress and egress")
	return nil
}

const clsactPriority = 49151
const clsactHandle = 0x70c3

func addFilter(ifindex int, parent uint32, name string, prog *ebpf.Program) (*netlink.BpfFilter, error) {
	dev, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, fmt.Errorf("link %d: %w", ifindex, err)
	}
	if err := delOwnFilters(dev, parent); err != nil {
		return nil, err
	}
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    clsactHandle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  clsactPriority,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(f); err != nil {
		return nil, fmt.Errorf("tc filter %s: %w", name, err)
	}
	runtime.KeepAlive(prog)
	return f, nil
}

func delOwnFilters(dev netlink.Link, parent uint32) error {
	filters, err := netlink.FilterList(dev, parent)
	if err != nil {
		return fmt.Errorf("list tc filters: %w", err)
	}
	for _, f := range filters {
		a := f.Attrs()
		if a.Priority != clsactPriority || a.Handle != clsactHandle {
			continue
		}
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("delete leftover tc filter: %w", err)
		}
	}
	return nil
}

// Snapshot reads the map and renders the configured labels.
func (p *Program) Snapshot() ([]flow.Series, error) {
	var key statKey
	var val statValue
	names := map[uint32]string{}
	iter := p.objs.PacketStats.Iterate()
	var out []flow.Series
	var used uint64
	for iter.Next(&key, &val) {
		used++
		labels, err := flow.Labels(flow.Key{
			Ifindex:   key.Ifindex,
			Direction: key.Direction,
			Type:      key.Type,
			Family:    key.Family,
			SrcPort:   key.SrcPort,
			DstPort:   key.DstPort,
			Src:       key.Src,
			Dst:       key.Dst,
		}, p.labels, func(idx uint32) string {
			if n, ok := names[idx]; ok {
				return n
			}
			n := strconv.FormatUint(uint64(idx), 10)
			if ifi, err := net.InterfaceByIndex(int(idx)); err == nil {
				n = ifi.Name
			}
			names[idx] = n
			return n
		})
		if err != nil {
			log.Printf("skip map entry: %v", err)
			continue
		}
		out = append(out, flow.Series{Labels: labels, Packets: val.Packets, Bytes: val.Bytes})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	p.mapUsed.Store(used)
	return out, nil
}

// MapInfo is LRU occupancy after the last Snapshot.
func (p *Program) MapInfo() (used, max uint64) {
	return p.mapUsed.Load(), uint64(p.mapMax)
}

var dropReasons = []string{
	"",
	"not_ip",
	"truncated",
	"fragment",
	"ext_hdr",
	"vlan",
	"update_race",
	"l4",
}

// Drops reads parser skip counters. Index 0 is unused.
func (p *Program) Drops() (map[string]uint64, error) {
	out := make(map[string]uint64, len(dropReasons)-1)
	for i := uint32(1); i < uint32(len(dropReasons)); i++ {
		var n uint64
		if err := p.objs.DropReasons.Lookup(i, &n); err != nil {
			return nil, err
		}
		out[dropReasons[i]] = n
	}
	return out, nil
}

// Close detaches the program and releases the maps.
func (p *Program) Close() error {
	var errs []error
	for _, f := range p.filters {
		if err := netlink.FilterDel(f); err != nil {
			errs = append(errs, err)
		}
	}
	p.filters = nil
	for _, l := range p.links {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	p.links = nil
	if err := p.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func raiseMemlock() {
	r := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &r); err != nil && !errors.Is(err, syscall.EPERM) {
		log.Printf("set memlock rlimit: %v", err)
	}
}
