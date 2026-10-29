// Package route finds the interface of the host default route.
package route

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultInterface returns the IPv4 default-route device, or the IPv6 one
// when the host has no IPv4 default route.
func DefaultInterface() (string, error) {
	v4, err4 := os.ReadFile("/proc/net/route")
	v6, err6 := os.ReadFile("/proc/net/ipv6_route")
	if err4 != nil && err6 != nil {
		return "", fmt.Errorf("read routes: %w", err4)
	}
	return Choose(string(v4), string(v6))
}

// Choose picks the lowest-metric default route from the text of
// /proc/net/route and /proc/net/ipv6_route.
func Choose(v4, v6 string) (string, error) {
	if name, ok := lowest(parseV4(v4)); ok {
		return name, nil
	}
	if name, ok := lowest(parseV6(v6)); ok {
		return name, nil
	}
	return "", errors.New("no default route")
}

func lowest(cands []candidate) (string, bool) {
	if len(cands) == 0 {
		return "", false
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.metric < best.metric {
			best = c
		}
	}
	return best.name, true
}

type candidate struct {
	name   string
	metric uint64
}

func parseV4(text string) []candidate {
	var out []candidate
	for i, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 8 {
			continue
		}
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		metric, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, candidate{name: fields[0], metric: metric})
	}
	return out
}

func parseV6(text string) []candidate {
	var out []candidate
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[0] != strings.Repeat("0", 32) || fields[1] != "00" {
			continue
		}
		metric, err := strconv.ParseUint(fields[5], 16, 64)
		if err != nil {
			continue
		}
		out = append(out, candidate{name: fields[9], metric: metric})
	}
	return out
}
