package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// ipv4 wraps an L4 segment into an IPv4 packet from src to dst.
func ipv4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	h[8], h[9] = 64, proto
	copy(h[12:], src[:])
	copy(h[16:], dst[:])
	return append(h, l4...)
}

func udp(sp, dp uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sp)
	binary.BigEndian.PutUint16(h[2:], dp)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func tcp(sp, dp uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sp)
	binary.BigEndian.PutUint16(h[2:], dp)
	h[12] = 5 << 4
	h[13] = flags
	return append(h, payload...)
}

func dnsQuery(name string) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func lastPacket(t *testing.T) Packet {
	pkMu.Lock()
	defer pkMu.Unlock()
	if len(pkRing) == 0 {
		t.Fatal("no packet recorded")
	}
	return pkRing[len(pkRing)-1]
}

var (
	me   = [4]byte{192, 168, 1, 10}
	peer = [4]byte{93, 184, 216, 34}
)

func TestDNSQuery(t *testing.T) {
	parsePacket(ipv4(17, me, [4]byte{8, 8, 8, 8}, udp(50000, 53, dnsQuery("example.com"))), "192.168.1.10")
	p := lastPacket(t)
	if p.Dir != "out" || p.Proto != "UDP" || p.DPort != 53 || p.Info != "DNS запрос: example.com" {
		t.Fatalf("unexpected: %+v", p)
	}
	if q := dnsQueries(); len(q) == 0 || q[len(q)-1].Name != "example.com" {
		t.Fatalf("query not recorded: %+v", q)
	}
}

func TestDNSResponseLearnsHost(t *testing.T) {
	q := dnsQuery("learned.example.org")
	q[2] = 0x81 // response
	q[7] = 1    // one answer
	ans := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7}
	parsePacket(ipv4(17, [4]byte{8, 8, 8, 8}, me, udp(53, 50000, append(q, ans...))), "192.168.1.10")
	p := lastPacket(t)
	if p.Dir != "in" || !strings.Contains(p.Info, "203.0.113.7") {
		t.Fatalf("unexpected: %+v", p)
	}
	if n := hostFor("203.0.113.7"); n != "learned.example.org" {
		t.Fatalf("host not learned, got %q", n)
	}
}

func TestTLSSNI(t *testing.T) {
	name := "secure.example.net"
	sni := append([]byte{0, 0, 0, byte(len(name) + 5), 0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	ext := append([]byte{0, byte(len(sni))}, sni...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0) // compression
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	parsePacket(ipv4(6, me, peer, tcp(50001, 443, 0x18, rec)), "192.168.1.10")
	p := lastPacket(t)
	if p.Info != "TLS → "+name {
		t.Fatalf("unexpected: %+v", p)
	}
	if hostFor("93.184.216.34") != name {
		t.Fatal("SNI not remembered for the IP")
	}
}

func TestHTTPPlainPassword(t *testing.T) {
	req := "POST /login HTTP/1.1\r\nHost: shop.example.com\r\n\r\nuser=a&password=secret"
	parsePacket(ipv4(6, me, peer, tcp(50002, 80, 0x18, []byte(req))), "192.168.1.10")
	p := lastPacket(t)
	if !strings.Contains(p.Info, "HTTP POST shop.example.com/login") || !strings.Contains(p.Info, "⚠") {
		t.Fatalf("unexpected: %+v", p)
	}
	found := false
	for _, a := range snifferAlerts() {
		if a.Kind == "plain" {
			found = true
		}
	}
	if !found {
		t.Fatal("no plaintext-password alert")
	}
}

func TestPortScanAlert(t *testing.T) {
	scanner := [4]byte{198, 51, 100, 9}
	for port := uint16(1000); port < 1020; port++ {
		parsePacket(ipv4(6, scanner, me, tcp(40000, port, 0x02, nil)), "192.168.1.10")
	}
	found := false
	for _, a := range snifferAlerts() {
		if a.Kind == "scan" && strings.Contains(a.Text, "198.51.100.9") {
			found = true
		}
	}
	if !found {
		t.Fatal("port scan not detected")
	}
}

func TestFlowAccounting(t *testing.T) {
	parsePacket(ipv4(6, me, peer, tcp(50003, 8081, 0x10, make([]byte, 100))), "192.168.1.10")
	parsePacket(ipv4(6, peer, me, tcp(8081, 50003, 0x10, make([]byte, 400))), "192.168.1.10")
	var f *Flow
	for _, x := range flowsSnapshot() {
		x := x
		if x.RPort == 8081 {
			f = &x
		}
	}
	if f == nil || f.Out != 140 || f.In != 440 {
		t.Fatalf("bad flow: %+v", f)
	}
}

func hasIncident(kind, keyPart string) *Incident {
	for _, x := range incidentsSnapshot() {
		if x.Kind == kind && strings.Contains(x.Key, keyPart) {
			c := x
			return &c
		}
	}
	return nil
}

func synPacket(pid int32, remote string, port uint16, t int64) *Packet {
	return &Packet{T: t, Dir: "out", Proto: "TCP", Flags: "SYN", Src: "192.168.1.10", Dst: remote, SPort: 50000, DPort: port,
		Remote: remote, PID: pid, Proc: "test.exe", Len: 60}
}

func TestPasswordIsRedactedInEvidence(t *testing.T) {
	req := "POST /login HTTP/1.1\r\nHost: redact.example.com\r\n\r\nuser=bob&password=TopSecret123&x=1"
	parsePacket(ipv4(6, me, peer, tcp(50010, 80, 0x18, []byte(req))), "192.168.1.10")
	in := hasIncident("plain", "redact.example.com")
	if in == nil || len(in.Evidence) == 0 {
		t.Fatalf("no plain-password incident: %+v", in)
	}
	for _, e := range in.Evidence {
		if strings.Contains(e.Dump, "TopSecret123") || strings.Contains(strings.ToLower(e.Dump), "topsecret") {
			t.Fatalf("secret leaked into dump:\n%s", e.Dump)
		}
		if !strings.Contains(e.Dump, "ord=****") {
			t.Fatalf("dump should show masked value:\n%s", e.Dump)
		}
	}
	if in.What == "" || in.Advice == "" {
		t.Fatal("incident has no explanation")
	}
}

func TestHTTPExecutableDownload(t *testing.T) {
	req := "GET /files/setup.exe HTTP/1.1\r\nHost: dl.example.com\r\n\r\n"
	parsePacket(ipv4(6, me, peer, tcp(50011, 80, 0x18, []byte(req))), "192.168.1.10")
	if hasIncident("httpexe", "dl.example.com") == nil {
		t.Fatal("exe download over http not reported")
	}
}

func TestRATPort(t *testing.T) {
	pkMu.Lock()
	detectPacket(synPacket(321, "203.0.113.77", 4444, 1000), 4444, nil)
	pkMu.Unlock()
	if hasIncident("ratport", "203.0.113.77") == nil {
		t.Fatal("known backdoor port not reported")
	}
}

func TestBeaconDetection(t *testing.T) {
	pkMu.Lock()
	for i := 0; i < 8; i++ {
		detectPacket(synPacket(555, "203.0.113.50", 8443, 1_000_000+int64(i)*5000), 8443, nil)
	}
	pkMu.Unlock()
	in := hasIncident("beacon", "203.0.113.50")
	if in == nil || in.Severity != "bad" {
		t.Fatalf("beacon not detected: %+v", in)
	}
}

func TestIrregularTrafficIsNotBeacon(t *testing.T) {
	offsets := []int64{0, 2000, 9000, 11000, 30000, 31500, 52000, 70000}
	pkMu.Lock()
	for _, o := range offsets {
		detectPacket(synPacket(556, "203.0.113.51", 8443, 2_000_000+o), 8443, nil)
	}
	pkMu.Unlock()
	if hasIncident("beacon", "203.0.113.51") != nil {
		t.Fatal("irregular connections wrongly flagged as beacon")
	}
}

func TestWormSweep(t *testing.T) {
	pkMu.Lock()
	for i := 0; i < 16; i++ {
		detectPacket(synPacket(888, fmt.Sprintf("203.0.113.%d", 100+i), 445, 3_000_000+int64(i)*100), 445, nil)
	}
	pkMu.Unlock()
	if hasIncident("worm", "worm|888") == nil {
		t.Fatal("worm-like sweep not detected")
	}
}

func TestSuspiciousDomains(t *testing.T) {
	for _, n := range []string{"xkqzjwvbtrnpmhdl.top", "q8w7e6r5t4y3u2i1o0p9.xyz", strings.Repeat("a", 90) + ".example.com"} {
		if suspiciousDomain(n) == "" {
			t.Errorf("should be suspicious: %s", n)
		}
	}
	for _, n := range []string{"google.com", "www.microsoft.com", "d1234abcd.cloudfront.net", "github.githubassets.com", "update.googleapis.com", "yandex.ru"} {
		if r := suspiciousDomain(n); r != "" {
			t.Errorf("false positive %s: %s", n, r)
		}
	}
}

func TestHexDump(t *testing.T) {
	d := hexDump([]byte("GET / HTTP/1.1\r\n"))
	if !strings.Contains(d, "47 45 54") || !strings.Contains(d, "|GET / HTTP/1.1..|") {
		t.Fatalf("bad dump:\n%s", d)
	}
}
