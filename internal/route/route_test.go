package route

import "testing"

func TestChooseIPv4LowestMetric(t *testing.T) {
	v4 := "" +
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"wlan0\t0001020A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000001 00000000 00000000 00000001 eth2\n"
	got, err := Choose(v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth0" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseIPv6WhenNoIPv4Default(t *testing.T) {
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000100 00000000 00000000 00000001 eth1\n"
	got, err := Choose("", v6)
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth1" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseNone(t *testing.T) {
	if _, err := Choose("", ""); err == nil {
		t.Fatal("expected error")
	}
}
