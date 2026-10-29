# Packet counters

eBPF counters for traffic on one Linux interface. Each flow is `packet_total` and `packet_bytes_total` with the labels in [`config.yaml`](config.yaml). `docker compose up` attaches the program, scrapes it into VictoriaMetrics, and opens a Grafana dashboard.

## Requirements

- Linux kernel 5.15 or newer, with eBPF and `clsact` support. Kernels 6.6 and newer attach with TCX; older kernels fall back to a clsact qdisc.
- Docker with host networking and a privileged container.

The program uses the stable traffic-control packet context. It sees packets that traverse the interface you attach to. Same-host flows that stay inside an Open vSwitch datapath show up only when `IFACE` is the netdev that carries them.

## Run

```sh
docker compose up --build
```

Set the interface when the default route is not the NIC you care about:

```sh
IFACE=eth0 docker compose up --build
```

Then generate traffic on that host (`curl`, `nc`). `rate()` needs about a minute of scrapes before it is non-zero.

- Metrics: `http://127.0.0.1:9435/metrics`
- VictoriaMetrics: `http://127.0.0.1:8428`
- Grafana: `http://127.0.0.1:3000` (anonymous view, or `admin` / `admin`)

On Colima, Grafana’s published port is on the VM. If `127.0.0.1:3000` does not load, use the VM address from `colima status` (for example `http://192.168.106.4:3000`).

## Labels

`config.yaml` lists the dynamic labels to keep. Delete a line to drop that label. Add `direction` to split ingress and egress. `static_labels` are constants added to every series and are not stored in the kernel map.

Supported dynamic labels: `interface`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `type`, `direction`.

`type` is one of `syn`, `synack`, `rst`, `fin`, `ack`, `udp`, `icmp`. `ack` is every TCP packet that is not SYN, SYN-ACK, FIN, or RST, so data segments and pure ACKs share that class.

Dropped fields are cleared in the kernel before the counter is updated, so two flows that differ only in a dropped label share one map entry. The map holds 65536 flows by default (`MAP_ENTRIES` or `-map-entries`) and evicts the least recently used entry after that. An evicted flow that returns starts at 1 again: Prometheus treats that as a counter reset. `rate()` still works; long-range `increase()` under-counts. Keeping `src_port` fills the map on a busy NIC. Drop it when you do not need the ephemeral port.

Without `direction`, ingress and egress share one key. A forwarded packet is counted on both hooks and looks like one flow with roughly twice the packets. A locally generated packet is egress only.

The Grafana dashboards use `rate()` / `increase()`. A series is counted once: source IP first, destination only if source did not match. The **Port (src or dst)** box is the same on ports, not a single-side exact filter: `443` keeps source port 443 and dest-only 443. With `$port` at `.*`, series that have no `src_port` / `dst_port` labels still match (the cardinality advice to drop `src_port` does not blank the panels).

```promql
sum by (type) (rate((
  (packet_total{src_ip=~"$ip"} or packet_total{dst_ip=~"$ip",src_ip!~"$ip"})
    unless packet_total{src_port=~".+"} unless packet_total{dst_port=~".+"}
  or packet_total{src_ip=~"$ip",src_port=~"$port"}
  or packet_total{src_ip=~"$ip",dst_port=~"$port",src_port!~"$port"}
  or packet_total{dst_ip=~"$ip",src_ip!~"$ip",src_port=~"$port"}
  or packet_total{dst_ip=~"$ip",src_ip!~"$ip",dst_port=~"$port",src_port!~"$port"}
  or (packet_total{src_ip=~"$ip",dst_port=~"$port"} or packet_total{dst_ip=~"$ip",src_ip!~"$ip",dst_port=~"$port"})
      unless packet_total{src_port=~".+"}
)[1m]))
```

`packet_bytes_total` uses `skb->len` from the traffic-control hook, which includes Ethernet (and VLAN) headers. It will not match IP-layer or SNMP interface counters.

`packet_drop_total{reason=...}` counts parser skips: `not_ip`, `truncated`, `fragment`, `ext_hdr` (any IPv6 next header other than TCP/UDP/ICMPv6, including hop-by-hop, routing, and fragment), `vlan`, `update_race` (insert lost a race with LRU reclaim; the map still evicts at capacity instead of failing), `l4`.

`packet_map_entries` / `packet_map_max_entries` are the LRU occupancy. When they meet, old flows are evicted and later packets start the counter at 1. `packet_scrape_errors` is a gauge of bad keys in the current scrape. `packet_snapshot_errors_total` counts failed map reads.

## Limits

- One interface per process.
- IPv6 packets whose first next header is not TCP, UDP, or ICMPv6 are not counted (`ext_hdr`). There is no extension-header walk.
- IPv4 fragments (More Fragments or a non-zero offset) are not counted.
- Non-IP traffic is ignored.
- On kernels older than 6.6 the process installs a clsact qdisc and a filter at priority 49151 handle `0x70c3`. That pair is this exporter’s. A restart deletes only that leftover handle before adding a new filter. Stopping the process leaves the qdisc in place.

## Build without Docker

On the Linux host, with clang and libbpf headers:

```sh
go generate ./internal/probe
CGO_ENABLED=0 go build -o packet-exporter ./cmd/packet-exporter
sudo ./packet-exporter -config config.yaml
```
