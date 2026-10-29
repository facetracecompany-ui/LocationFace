package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vpnFixture installs the routing table of a full-tunnel VPN as found on a real machine:
// two /1 routes through the tunnel beat the /0 route, a host route keeps the VPN server reachable.
func vpnFixture(active bool) {
	mk := func(c string, metric, idx int) routeEnt {
		_, n, _ := net.ParseCIDR(c)
		ones, _ := n.Mask.Size()
		return routeEnt{Net: n, Ones: ones, Metric: metric, IfIndex: idx}
	}
	vpnMu.Lock()
	vpnIf = map[int]*VPNAdapter{
		10: {Name: "Ethernet", Desc: "Realtek Gaming 2.5GbE", IP: "192.168.0.101", Status: "Up", Index: 10, Metric: 25},
		8:  {Name: "wwan99", Desc: "Wintun Tunnel", IP: "198.18.0.1", Status: "Up", Index: 8, Tunnel: true},
	}
	vpnRoutes = []routeEnt{
		mk("0.0.0.0/0", 0, 10), mk("0.0.0.0/0", 0, 8), mk("0.0.0.0/1", 1, 8), mk("128.0.0.0/1", 1, 8),
		mk("192.168.0.0/24", 0, 10), mk("203.0.113.9/32", 0, 10),
	}
	st := &VPNState{Active: active, DefaultViaVPN: true, DefaultIface: "wwan99"}
	if active {
		st.Adapters = []VPNAdapter{*vpnIf[8]}
	}
	vpnSt = st
	vpnMu.Unlock()
}

func TestTunnelAdapterRecognition(t *testing.T) {
	cases := []struct {
		name, desc, ip string
		want           bool
	}{
		{"wwan99", "Wintun Tunnel", "198.18.0.1", true},
		{"Подключение по локальной сети", "TAP-Windows Adapter V9 for OpenVPN Connect", "", true},
		{"WireGuard Tunnel", "WireGuard Tunnel", "10.0.0.2", true},
		{"mystery", "Unknown", "198.19.4.1", true}, // address block used by tun2socks-style clients
		{"Ethernet", "Realtek Gaming 2.5GbE Family Controller", "192.168.0.101", false},
		{"Подключение по локальной сети* 6", "WAN Miniport (IP)", "", false},
		{"Teredo", "Microsoft Teredo Tunneling Adapter", "", false},
		{"vEthernet", "Hyper-V Virtual Ethernet Adapter", "172.20.0.1", false},
		{"Bluetooth", "Bluetooth Device (Personal Area Network)", "", false},
	}
	for _, c := range cases {
		if got := isTunnelAdapter(c.name, c.desc, c.ip); got != c.want {
			t.Errorf("%s / %s: got %v want %v", c.name, c.desc, got, c.want)
		}
	}
}

func TestRouteLookupFollowsLongestPrefix(t *testing.T) {
	vpnFixture(true)
	check := func(ip string, wantName string, wantTunnel bool) {
		ad, tun := routeVia(ip)
		if ad == nil || ad.Name != wantName || tun != wantTunnel {
			t.Errorf("%s: got %+v tunnel=%v, want %s tunnel=%v", ip, ad, tun, wantName, wantTunnel)
		}
	}
	check("93.184.216.34", "wwan99", true)   // 0.0.0.0/1 beats 0.0.0.0/0
	check("198.51.100.7", "wwan99", true)    // 128.0.0.0/1
	check("203.0.113.9", "Ethernet", false)  // host route: the VPN server itself
	check("192.168.0.50", "Ethernet", false) // local network
}

func TestIncidentVPNVerdicts(t *testing.T) {
	vpnFixture(true)
	dir := t.TempDir()
	clientExe := filepath.Join(dir, "examplevpn.exe")
	_ = os.WriteFile(clientExe, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "wintun.dll"), []byte("x"), 0o600)
	vpnMu.Lock()
	vpnSt.Clients = []VPNClient{{Name: "examplevpn.exe", PID: 5, Endpoints: []VPNEndpoint{{Remote: "203.0.113.9", Port: 443}}}}
	vpnMu.Unlock()

	cases := []struct {
		name string
		in   Incident
		want string
	}{
		{"traffic through the tunnel", Incident{Kind: "upload", Remote: "93.184.216.34", Proc: "mystery.exe", Exe: `C:\x\mystery.exe`}, "via"},
		{"captured on the VPN adapter", Incident{Kind: "ratport", Remote: "192.168.0.50", Via: "tunnel"}, "via"},
		{"the VPN client itself", Incident{Kind: "conn", Remote: "203.0.113.9", Proc: "examplevpn.exe", Exe: clientExe}, "client"},
		{"the server a VPN client talks to", Incident{Kind: "conn", Remote: "203.0.113.9", Proc: "other.exe", Exe: `C:\x\other.exe`}, "server"},
		{"goes around the VPN", Incident{Kind: "conn", Remote: "192.168.0.50", Proc: "other.exe", Exe: `C:\x\other.exe`}, "direct"},
		{"a file on disk has nothing to do with it", Incident{Kind: "defender", Title: "x"}, "na"},
	}
	for _, c := range cases {
		a := assessVPN(&c.in)
		if a.Verdict != c.want || a.Title == "" || len(a.Details) == 0 {
			t.Errorf("%s: got %q (%s), want %q", c.name, a.Verdict, a.Title, c.want)
		}
	}

	vpnFixture(false)
	if a := assessVPN(&Incident{Kind: "conn", Remote: "93.184.216.34", Proc: "x.exe", Exe: `C:\x\x.exe`}); a.Verdict != "none" || !strings.Contains(a.Title, "напрямую") {
		t.Errorf("without VPN the verdict must be 'none': %+v", a)
	}
}

func TestVPNScanFindsProgramsOutsideTheTunnel(t *testing.T) {
	vpnFixture(true)
	vpnMu.Lock()
	vpnSt.Clients = []VPNClient{{Name: "examplevpn.exe", PID: 5}}
	vpnMu.Unlock()
	stMu.Lock()
	curConns = []Conn{
		{PID: 5, Proc: "examplevpn.exe", Proto: "TCP", Remote: "203.0.113.9", RPort: 443, Dir: "out", Scope: "public"},
		{PID: 6, Proc: "chrome.exe", Proto: "TCP", Remote: "93.184.216.34", RPort: 443, Dir: "out", Scope: "public"},
		{PID: 7, Proc: "leaky.exe", Proto: "TCP", Remote: "203.0.113.9", RPort: 8443, Dir: "out", Scope: "public", Host: "host.example"},
		{PID: 7, Proc: "leaky.exe", Proto: "TCP", Remote: "93.184.216.34", RPort: 443, Dir: "out", Scope: "public"},
	}
	stMu.Unlock()
	defer func() { stMu.Lock(); curConns = nil; stMu.Unlock() }()

	got := map[string]VPNScanRow{}
	for _, r := range vpnScan() {
		got[r.Proc] = r
	}
	if got["chrome.exe"].Verdict != "vpn" || got["chrome.exe"].ViaVPN != 1 {
		t.Errorf("chrome should be fully inside the VPN: %+v", got["chrome.exe"])
	}
	if got["examplevpn.exe"].Verdict != "client" {
		t.Errorf("the VPN client is its own category: %+v", got["examplevpn.exe"])
	}
	l := got["leaky.exe"]
	if l.Verdict != "mixed" || l.Direct != 1 || l.ViaVPN != 1 || len(l.Examples) != 1 || !strings.Contains(l.Examples[0], "host.example") {
		t.Errorf("a program with one connection outside must be reported with the example: %+v", l)
	}
	if first := vpnScan()[0]; first.Verdict == "vpn" {
		t.Errorf("programs bypassing the VPN must be listed first")
	}
}

func TestSnapshotCarriesVPNVerdictButStoresNone(t *testing.T) {
	vpnFixture(true)
	addIncident(Incident{Key: "vpn|snap", Kind: "conn", Severity: "warn", Title: "t", Remote: "93.184.216.34", Proc: "p.exe", Exe: `C:\x\p.exe`}, nil)
	in := hasIncident("conn", "vpn|snap")
	if in == nil || in.VPN == nil || in.VPN.Verdict != "via" {
		t.Fatalf("snapshot should carry the verdict: %+v", in)
	}
	incMu.Lock()
	stored := incByKey["vpn|snap"]
	incMu.Unlock()
	if stored.VPN != nil {
		t.Error("the verdict is derived from the current state and must not be persisted")
	}
}
