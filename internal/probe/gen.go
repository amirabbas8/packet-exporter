package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.19.0 -tags linux packet ../../bpf/packet.bpf.c -- -O2 -g -Wall
