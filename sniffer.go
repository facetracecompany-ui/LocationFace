package main

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Packet capture without a driver: one raw IPv4 socket per interface address
// with SIO_RCVALL. Needs administrator rights; IPv6 and loopback are not seen.

type Packet struct {
	ID     int64  `json:"id"`
	T      int64  `json:"t"`
	Dir    string `json:"dir"` // in | out
	Proto  string `json:"proto"`
	Src    string `json:"src"`
	SPort  uint16 `json:"sport"`
	Dst    string `json:"dst"`
	DPort  uint16 `json:"dport"`
	Len    int    `json:"len"`
	Flags  string `json:"flags"`
	Info   string `json:"info"`
	PID    int32  `json:"pid"`
	Proc   string `json:"proc"`
	Remote string `json:"remote"`
	Host   string `json:"host"`
	TTL    int    `json:"ttl"`
	Raw    []byte `json:"-"`

	// filled by harvest() for outgoing plain-text payloads
	Tunnel  bool     `json:"-"` // captured on a VPN/tunnel adapter
	TLS     bool     `json:"-"`
	Req     string   `json:"-"`
	UA      string   `json:"-"`
	UpFiles []UpFile `json:"-"`
	Fields  []string `json:"-"`
}

type Flow struct {
	PID    int32  `json:"pid"`
	Proc   string `json:"proc"`
	Proto  string `json:"proto"`
	Remote string `json:"remote"`
	RPort  uint16 `json:"rport"`
	Host   string `json:"host"`
	Scope  string `json:"scope"`
	In     uint64 `json:"in"`
	Out    uint64 `json:"out"`
	Pkts   int    `json:"pkts"`
	First  int64  `json:"first"`
	Last   int64  `json:"last"`

	// what was visible about the content (plain-text protocols only; values are never kept)
	TLS     bool     `json:"tls"`
	Tunnel  bool     `json:"tunnel"`
	UA      string   `json:"ua"`
	Reqs    []string `json:"reqs"`
	UpFiles []UpFile `json:"upFiles"`
	Fields  []string `json:"fields"`
}

type UpFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Alert struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	Text string `json:"text"`
	PID  int32  `json:"pid"`
	Proc string `json:"proc"`
}

type DNSQuery struct {
	T    int64  `json:"t"`
	Name string `json:"name"`
	PID  int32  `json:"pid"`
	Proc string `json:"proc"`
}

var (
	pkMu     sync.Mutex
	pkRing   []Packet
	pkID     int64
	pkTotal  atomic.Int64
	flows    = map[string]*Flow{}
	pidTraf  = map[int32][2]uint64{}
	alerts   []Alert
	queries  []DNSQuery
	scans    = map[string]*scanTrack{}
	alertMu  sync.Mutex
	beacons  = map[string]*beaconTrack{}
	brutes   = map[string]*scanTrack{}
	worms    = map[int32]*wormTrack{}
	snifErrs []string
	snifIf   []string

	pidNames atomic.Pointer[map[int32]string]
)

type scanTrack struct {
	start int64
	ports map[uint16]struct{}
	n     int
	done  bool
}

type beaconTrack struct {
	times   []int64
	flagged bool
	checked bool
}

type wormTrack struct {
	start int64
	dsts  map[string]struct{}
	done  bool
}

var (
	wormPorts = map[uint16]bool{445: true, 139: true, 135: true, 3389: true, 22: true, 23: true, 5900: true}
	bruteDst  = map[uint16]bool{22: true, 23: true, 445: true, 3389: true, 5900: true, 1433: true, 3306: true, 5432: true}
)

func startSniffer() {
	var d windows.WSAData
	_ = windows.WSAStartup(0x202, &d)
	if !isAdmin() {
		snifErrs = append(snifErrs, "Нужны права администратора для перехвата пакетов")
		return
	}
	ifs, _ := net.Interfaces()
	tunNames := tunnelAdapterNames()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			ip := ipn.IP.To4()
			if tunNames[ifc.Name] {
				tunnelIPs[ip.String()] = true
			}
			snifIf = append(snifIf, ifc.Name+" "+ip.String())
			go sniff(ip)
		}
	}
	if len(snifIf) == 0 {
		snifErrs = append(snifErrs, "Не найдено активных сетевых интерфейсов IPv4")
	}
}

var (
	tunnelIPs    = map[string]bool{}
	_, tunNet, _ = net.ParseCIDR("198.18.0.0/15") // address block tun2socks-style VPN clients use
)

func isTunnelIP(ip string) bool {
	if tunnelIPs[ip] {
		return true
	}
	p := net.ParseIP(ip)
	return p != nil && tunNet.Contains(p)
}

// tunnelAdapterNames lists virtual VPN adapters (Wintun, TAP, WireGuard...).
func tunnelAdapterNames() map[string]bool {
	out := map[string]bool{}
	for _, r := range psJSON(`Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wintun|TAP|WireGuard|OpenVPN|VPN|Tunnel' } | Select-Object Name | ConvertTo-Json -Compress`, 10*time.Second) {
		out[str(r["Name"])] = true
	}
	return out
}

func sniff(local net.IP) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		addSnifErr("socket " + local.String() + ": " + err.Error())
		return
	}
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], local)
	if err := windows.Bind(fd, sa); err != nil {
		addSnifErr("bind " + local.String() + ": " + err.Error())
		return
	}
	on, ret := uint32(1), uint32(0)
	if err := windows.WSAIoctl(fd, 0x98000001, (*byte)(unsafe.Pointer(&on)), 4, nil, 0, &ret, nil, 0); err != nil {
		addSnifErr("SIO_RCVALL " + local.String() + ": " + err.Error())
		return
	}
	buf := make([]byte, 65536)
	for {
		n, _, err := windows.Recvfrom(fd, buf, 0)
		if err != nil {
			addSnifErr("recv " + local.String() + ": " + err.Error())
			return
		}
		parsePacket(buf[:n], local.String())
	}
}

func addSnifErr(s string) {
	pkMu.Lock()
	snifErrs = append(snifErrs, s)
	pkMu.Unlock()
}

func parsePacket(b []byte, local string) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&15) * 4
	total := int(b[2])<<8 | int(b[3])
	if total > len(b) || total < ihl {
		total = len(b)
	}
	proto := b[9]
	src := net.IP(b[12:16]).String()
	dst := net.IP(b[16:20]).String()
	pk := Packet{T: time.Now().UnixMilli(), Src: src, Dst: dst, Len: total, TTL: int(b[8]), Tunnel: isTunnelIP(local)}
	if src == local {
		pk.Dir, pk.Remote = "out", dst
	} else {
		pk.Dir, pk.Remote = "in", src
	}
	var payload []byte
	pstr := ""
	switch proto {
	case 6:
		if total < ihl+20 {
			return
		}
		t := b[ihl:total]
		pk.Proto, pstr = "TCP", "tcp"
		pk.SPort, pk.DPort = uint16(t[0])<<8|uint16(t[1]), uint16(t[2])<<8|uint16(t[3])
		pk.Flags = tcpFlags(t[13])
		off := int(t[12]>>4) * 4
		if off >= 20 && off <= len(t) {
			payload = t[off:]
		}
	case 17:
		if total < ihl+8 {
			return
		}
		t := b[ihl:total]
		pk.Proto, pstr = "UDP", "udp"
		pk.SPort, pk.DPort = uint16(t[0])<<8|uint16(t[1]), uint16(t[2])<<8|uint16(t[3])
		payload = t[8:]
	case 1:
		pk.Proto = "ICMP"
		if total > ihl {
			pk.Info = icmpName(b[ihl])
			payload = nil
			pk.Raw = redact(b[ihl:min(total, ihl+160)])
		}
	default:
		pk.Proto = "IP/" + strconv.Itoa(int(proto))
	}

	localPort, remotePort := pk.SPort, pk.DPort
	if pk.Dir == "in" {
		localPort, remotePort = pk.DPort, pk.SPort
	}
	if pstr != "" {
		pk.PID = pidForPort(pstr, localPort)
		if m := pidNames.Load(); m != nil {
			pk.Proc = (*m)[pk.PID]
		}
	}
	if len(payload) > 0 {
		pk.Raw = redact(payload[:min(len(payload), 160)]) // secrets never reach memory or reports
	}
	analyze(&pk, payload, pstr, remotePort)

	pkMu.Lock()
	pkID++
	pk.ID = pkID
	pkRing = append(pkRing, pk)
	if len(pkRing) > 6000 {
		pkRing = append([]Packet(nil), pkRing[len(pkRing)-5000:]...)
	}
	pkTotal.Add(1)

	key := fmt.Sprintf("%d|%s|%s|%d", pk.PID, pk.Proto, pk.Remote, remotePort)
	f := flows[key]
	if f == nil {
		if len(flows) > 6000 {
			trimFlows()
		}
		f = &Flow{PID: pk.PID, Proc: pk.Proc, Proto: pk.Proto, Remote: pk.Remote, RPort: remotePort, Scope: ipScope(pk.Remote), First: pk.T}
		flows[key] = f
	}
	if pk.Dir == "in" {
		f.In += uint64(total)
	} else {
		f.Out += uint64(total)
	}
	f.Pkts++
	f.Last = pk.T
	f.TLS = f.TLS || pk.TLS
	f.Tunnel = f.Tunnel || pk.Tunnel
	if f.UA == "" {
		f.UA = pk.UA
	}
	if pk.Req != "" {
		f.Reqs = addUniq(f.Reqs, pk.Req, 12)
	}
	for _, x := range pk.Fields {
		f.Fields = addUniq(f.Fields, x, 25)
	}
	for _, u := range pk.UpFiles {
		if len(f.UpFiles) < 20 {
			dup := false
			for _, e := range f.UpFiles {
				dup = dup || e == u
			}
			if !dup {
				f.UpFiles = append(f.UpFiles, u)
			}
		}
	}
	if f.Proc == "" {
		f.Proc = pk.Proc
	}
	tr := pidTraf[pk.PID]
	if pk.Dir == "in" {
		tr[0] += uint64(total)
	} else {
		tr[1] += uint64(total)
	}
	pidTraf[pk.PID] = tr

	// inbound port scan: many SYNs from one address to different ports
	if pk.Dir == "in" && pk.Proto == "TCP" && pk.Flags == "SYN" && ipScope(pk.Remote) == "public" {
		s := scans[pk.Remote]
		if s == nil || pk.T-s.start > 10000 {
			s = &scanTrack{start: pk.T, ports: map[uint16]struct{}{}}
			scans[pk.Remote] = s
			if len(scans) > 2000 {
				scans = map[string]*scanTrack{pk.Remote: s}
			}
		}
		s.ports[pk.DPort] = struct{}{}
		if len(s.ports) >= 15 && !s.done {
			s.done = true
			txt := "Сканирование портов с адреса " + pk.Remote + " (" + strconv.Itoa(len(s.ports)) + " портов за 10 с)"
			pushAlert(Alert{T: pk.T, Kind: "scan", Text: txt})
			raise("scan", "warn", txt, "scan|"+pk.Remote, &pk,
				fmt.Sprintf("С адреса %s за 10 секунд пришли SYN-запросы на %d разных портов", pk.Remote, len(s.ports)),
				"Обычный пользователь так не подключается: это поиск открытых служб")
		}
	}
	detectPacket(&pk, remotePort, f)
	pkMu.Unlock()
}

// detectPacket looks for attack and malware patterns; called with pkMu held.
func detectPacket(pk *Packet, remotePort uint16, f *Flow) {
	public := ipScope(pk.Remote) == "public"
	syn := pk.Proto == "TCP" && pk.Flags == "SYN"

	if syn && pk.Dir == "out" && public {
		if why, ok := ratPorts[uint32(remotePort)]; ok {
			raise("ratport", "bad", fmt.Sprintf("Подключение на порт %d (%s) — %s:%d", remotePort, why, pk.Remote, remotePort),
				fmt.Sprintf("ratport|%d|%s|%d", pk.PID, pk.Remote, remotePort), pk,
				fmt.Sprintf("Порт %d известен как порт «%s»", remotePort, why))
		}
		// beaconing: the same destination at near-constant intervals
		key := fmt.Sprintf("%d|%s|%d", pk.PID, pk.Remote, remotePort)
		b := beacons[key]
		if b == nil {
			if len(beacons) > 3000 {
				beacons = map[string]*beaconTrack{}
			}
			b = &beaconTrack{}
			beacons[key] = b
		}
		if n := len(b.times); n == 0 || pk.T-b.times[n-1] > 1500 {
			b.times = append(b.times, pk.T)
			if len(b.times) > 12 {
				b.times = b.times[1:]
			}
		}
		if len(b.times) >= 7 && !b.flagged && !b.checked {
			b.checked = true // judge once: the program and name are known by now
			if idx := procIndex.Load(); idx != nil && actorExpected((*idx)[pk.PID], hostFor(pk.Remote), pk.Remote) {
				b.flagged = true // heartbeat of a known program (messenger, updater, browser)
			}
		}
		if len(b.times) >= 7 && !b.flagged {
			var iv []float64
			for i := 1; i < len(b.times); i++ {
				iv = append(iv, float64(b.times[i]-b.times[i-1]))
			}
			var sum float64
			for _, v := range iv {
				sum += v
			}
			mean := sum / float64(len(iv))
			var sq float64
			for _, v := range iv {
				sq += (v - mean) * (v - mean)
			}
			cv := math.Sqrt(sq/float64(len(iv))) / mean
			if mean >= 4000 && mean <= 900000 && cv < 0.12 {
				b.flagged = true
				sev := "warn"
				if m := pidSigs.Load(); m == nil || (*m)[pk.PID] != "signed" {
					sev = "bad"
				}
				raise("beacon", sev, fmt.Sprintf("Регулярные соединения с %s:%d каждые ~%d с", pk.Remote, remotePort, int(mean/1000)),
					"beacon|"+key, pk,
					fmt.Sprintf("%d подключений подряд с интервалом около %d с (разброс %.0f%%)", len(b.times), int(mean/1000), cv*100),
					"Люди так не работают: ровный ритм характерен для программ, которые «стучатся» на сервер")
			}
		}
		// worm-like sweep of many hosts
		if wormPorts[remotePort] {
			w := worms[pk.PID]
			if w == nil || pk.T-w.start > 10000 {
				if len(worms) > 500 {
					worms = map[int32]*wormTrack{}
				}
				w = &wormTrack{start: pk.T, dsts: map[string]struct{}{}}
				worms[pk.PID] = w
			}
			w.dsts[pk.Remote] = struct{}{}
			if len(w.dsts) >= 15 && !w.done {
				w.done = true
				raise("worm", "bad", fmt.Sprintf("Массовые подключения на порт %d: %d адресов за 10 с", remotePort, len(w.dsts)),
					fmt.Sprintf("worm|%d|%d", pk.PID, remotePort), pk,
					"Процесс обращается к десяткам разных компьютеров по порту удалённого доступа — так распространяются черви и ботнеты")
			}
		}
	}

	// repeated connection attempts to remote-access services from one address
	if syn && pk.Dir == "in" && public && bruteDst[pk.DPort] {
		s := brutes[pk.Remote]
		if s == nil || pk.T-s.start > 60000 {
			if len(brutes) > 2000 {
				brutes = map[string]*scanTrack{}
			}
			s = &scanTrack{start: pk.T}
			brutes[pk.Remote] = s
		}
		s.n++
		if s.n >= 10 && !s.done {
			s.done = true
			raise("bruteforce", "warn", fmt.Sprintf("Попытки подключиться к порту %d с адреса %s", pk.DPort, pk.Remote),
				fmt.Sprintf("brute|%s|%d", pk.Remote, pk.DPort), pk,
				fmt.Sprintf("%d попыток за минуту на порт %d (служба удалённого доступа)", s.n, pk.DPort))
		}
	}

	// ping carrying a lot of data
	if pk.Proto == "ICMP" && pk.Dir == "out" && pk.Len > 300 && strings.HasPrefix(pk.Info, "Echo request") {
		raise("icmp", "warn", "Необычно большой ping на "+pk.Remote, "icmp|"+pk.Remote, pk,
			fmt.Sprintf("Размер пакета %d байт (обычный ping — 60–100 байт)", pk.Len))
	}
}

func fmtBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f МБ", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d КБ", n>>10)
}

func trimFlows() {
	type kv struct {
		k string
		t int64
	}
	var all []kv
	for k, f := range flows {
		all = append(all, kv{k, f.Last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
	for i := 0; i < len(all)/3; i++ {
		delete(flows, all[i].k)
	}
}

func pushAlert(a Alert) {
	alertMu.Lock()
	defer alertMu.Unlock()
	for _, x := range alerts {
		if x.Text == a.Text {
			return
		}
	}
	alerts = append(alerts, a)
	if len(alerts) > 200 {
		alerts = alerts[len(alerts)-150:]
	}
}

func tcpFlags(f byte) string {
	var s []string
	for _, x := range []struct {
		m byte
		n string
	}{{2, "SYN"}, {16, "ACK"}, {8, "PSH"}, {1, "FIN"}, {4, "RST"}, {32, "URG"}} {
		if f&x.m != 0 {
			s = append(s, x.n)
		}
	}
	if len(s) == 2 && s[0] == "SYN" && s[1] == "ACK" {
		return "SYN+ACK"
	}
	if f&18 == 2 {
		return "SYN"
	}
	return strings.Join(s, "+")
}

func icmpName(t byte) string {
	switch t {
	case 0:
		return "Echo reply (ответ на ping)"
	case 3:
		return "Destination unreachable"
	case 8:
		return "Echo request (ping)"
	case 11:
		return "Time exceeded"
	}
	return "ICMP type " + strconv.Itoa(int(t))
}

// analyze fills pk.Info from the payload and records observed names.
func analyze(pk *Packet, p []byte, proto string, remotePort uint16) {
	if len(p) == 0 {
		return
	}
	// DNS
	if proto == "udp" && (pk.DPort == 53 || pk.SPort == 53) {
		name, ips, resp := parseDNS(p)
		if name == "" {
			return
		}
		if resp {
			pk.Info = "DNS ответ: " + name
			if len(ips) > 0 {
				pk.Info += " → " + ips[0].String()
				for _, ip := range ips {
					noteHost(ip.String(), name)
				}
			}
		} else {
			pk.Info = "DNS запрос: " + name
			dnsMu.Lock()
			queries = append(queries, DNSQuery{T: pk.T, Name: name, PID: pk.PID, Proc: pk.Proc})
			if len(queries) > 600 {
				queries = queries[len(queries)-500:]
			}
			dnsMu.Unlock()
			if why := suspiciousDomain(name); why != "" {
				raise("dns", "warn", "Подозрительное имя в DNS: "+name, "dns|"+name, pk, why, "Запрошено процессом: "+pk.Proc)
			}
		}
		return
	}
	if proto != "tcp" {
		return
	}
	if len(p) > 5 && (p[0] == 0x16 || p[0] == 0x17) && p[1] == 3 {
		pk.TLS = true
	} else if pk.Dir == "out" {
		harvest(pk, p)
	}
	// TLS ClientHello -> server name
	if len(p) > 6 && p[0] == 0x16 && p[1] == 3 && p[5] == 1 {
		if sni := parseSNI(p); sni != "" {
			pk.Info = "TLS → " + sni
			if pk.Dir == "out" {
				noteHost(pk.Dst, sni)
			}
		}
		return
	}
	// plain HTTP
	s := string(p[:min(len(p), 1500)])
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE "} {
		if strings.HasPrefix(s, m) {
			line := s
			if i := strings.Index(s, "\r\n"); i > 0 {
				line = s[:i]
			}
			host := ""
			if i := strings.Index(strings.ToLower(s), "\r\nhost:"); i >= 0 {
				rest := s[i+7:]
				if j := strings.Index(rest, "\r\n"); j >= 0 {
					host = strings.TrimSpace(rest[:j])
				}
			}
			path := strings.Fields(line)
			u := ""
			if len(path) >= 2 {
				u = host + maskQuery(path[1])
			}
			pk.Info = "HTTP " + strings.TrimSpace(m) + " " + u
			if pk.Dir == "out" && host != "" {
				noteHost(pk.Dst, host)
			}
			if len(path) >= 2 && pk.Dir == "out" {
				p := strings.ToLower(path[1])
				if q := strings.IndexAny(p, "?#"); q >= 0 {
					p = p[:q]
				}
				for _, e := range []string{".exe", ".msi", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".hta"} {
					if strings.HasSuffix(p, e) {
						raise("httpexe", "warn", "Скачивание "+path[1]+" с "+host+" по http://", "httpexe|"+host+p, pk,
							"Запрос исполняемого файла ("+e+") по незащищённому каналу",
							"Сервер: "+host+" ("+pk.Dst+")")
						break
					}
				}
			}
			low := strings.ToLower(s)
			if strings.Contains(low, "password=") || strings.Contains(low, "passwd=") || strings.Contains(low, "pwd=") || strings.Contains(low, "authorization: basic") {
				pk.Info += "  ⚠ пароль передаётся открытым текстом"
				if pk.Dir == "out" {
					txt := "Пароль или логин отправлен без шифрования на " + host + " (" + pk.Dst + ")"
					pushAlert(Alert{T: pk.T, Kind: "plain", Text: txt, PID: pk.PID, Proc: pk.Proc})
					raise("plain", "bad", txt, "plain|"+host+"|"+pk.Proc, pk,
						"В теле или заголовках HTTP-запроса найдено поле пароля или авторизации",
						"Значения в дампе ниже скрыты звёздочками программой")
				}
			}
			return
		}
	}
	if strings.HasPrefix(s, "HTTP/1.") && pk.Dir == "in" {
		if i := strings.Index(s, "\r\n"); i > 0 {
			pk.Info = s[:i]
		}
		return
	}
	switch remotePort {
	case 21, 23, 110, 143:
		if pk.Dir == "out" && len(p) > 5 && strings.HasPrefix(strings.ToUpper(s), "PASS ") {
			pk.Info = "⚠ пароль передаётся открытым текстом (порт " + strconv.Itoa(int(remotePort)) + ")"
			txt := "Пароль отправлен без шифрования на " + pk.Dst + ":" + strconv.Itoa(int(remotePort))
			pushAlert(Alert{T: pk.T, Kind: "plain", Text: txt, PID: pk.PID, Proc: pk.Proc})
			raise("plain", "bad", txt, "plain|"+pk.Dst+"|"+pk.Proc, pk, "Команда PASS в открытом виде (FTP, POP3, IMAP, Telnet)")
		}
	}
}

func parseDNS(p []byte) (name string, ips []net.IP, resp bool) {
	if len(p) < 13 {
		return
	}
	resp = p[2]&0x80 != 0
	qd, an := int(p[4])<<8|int(p[5]), int(p[6])<<8|int(p[7])
	if qd < 1 {
		return
	}
	i := 12
	var labels []string
	for i < len(p) && p[i] != 0 {
		l := int(p[i])
		if l&0xC0 != 0 || i+1+l > len(p) {
			return "", nil, resp
		}
		labels = append(labels, string(p[i+1:i+1+l]))
		i += 1 + l
	}
	name = strings.Join(labels, ".")
	i += 5 // zero, qtype, qclass
	if !resp {
		return
	}
	for k := 0; k < an && i < len(p); k++ {
		for i < len(p) && p[i] != 0 && p[i]&0xC0 != 0xC0 { // skip name
			i += 1 + int(p[i])
		}
		if i < len(p) && p[i]&0xC0 == 0xC0 {
			i += 2
		} else {
			i++
		}
		if i+10 > len(p) {
			break
		}
		typ, rd := int(p[i])<<8|int(p[i+1]), int(p[i+8])<<8|int(p[i+9])
		i += 10
		if i+rd > len(p) {
			break
		}
		if (typ == 1 && rd == 4) || (typ == 28 && rd == 16) {
			ips = append(ips, net.IP(append([]byte(nil), p[i:i+rd]...)))
		}
		i += rd
	}
	return
}

func parseSNI(p []byte) string {
	// record header 5, handshake header 4, version 2, random 32
	i := 5 + 4 + 2 + 32
	skip := func(lenBytes int) bool {
		if i+lenBytes > len(p) {
			return false
		}
		n := 0
		for k := 0; k < lenBytes; k++ {
			n = n<<8 | int(p[i+k])
		}
		i += lenBytes + n
		return i <= len(p)
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, ciphers, compression
		return ""
	}
	if i+2 > len(p) {
		return ""
	}
	end := i + 2 + (int(p[i])<<8 | int(p[i+1]))
	i += 2
	for i+4 <= len(p) && i+4 <= end {
		typ, l := int(p[i])<<8|int(p[i+1]), int(p[i+2])<<8|int(p[i+3])
		i += 4
		if typ == 0 && i+5 <= len(p) { // server_name
			nl := int(p[i+3])<<8 | int(p[i+4])
			if i+5+nl <= len(p) {
				return string(p[i+5 : i+5+nl])
			}
			return ""
		}
		i += l
	}
	return ""
}

// ---------------------------------------------------------------- readers

func trafficFor(pid int32) (in, out uint64) {
	pkMu.Lock()
	defer pkMu.Unlock()
	t := pidTraf[pid]
	return t[0], t[1]
}

func dnsQueries() []DNSQuery {
	dnsMu.RLock()
	defer dnsMu.RUnlock()
	n := len(queries)
	if n > 300 {
		return append([]DNSQuery(nil), queries[n-300:]...)
	}
	return append([]DNSQuery(nil), queries...)
}

func snifferAlerts() []Alert {
	alertMu.Lock()
	defer alertMu.Unlock()
	return append([]Alert(nil), alerts...)
}

func flowsSnapshot() []Flow {
	pkMu.Lock()
	out := make([]Flow, 0, len(flows))
	for _, f := range flows {
		out = append(out, *f)
	}
	pkMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].In+out[i].Out > out[j].In+out[j].Out })
	if len(out) > 400 {
		out = out[:400]
	}
	for i := range out {
		if out[i].Scope == "public" {
			out[i].Host = hostFor(out[i].Remote)
		}
	}
	return out
}

func snifferStatus() map[string]any {
	pkMu.Lock()
	defer pkMu.Unlock()
	errs := append([]string(nil), snifErrs...)
	return map[string]any{"running": len(snifIf) > 0 && len(errs) == 0 || (len(snifIf) > 0 && pkTotal.Load() > 0),
		"ifaces": snifIf, "errors": errs, "total": pkTotal.Load()}
}

func handlePacketDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	pkMu.Lock()
	var pk *Packet
	for i := len(pkRing) - 1; i >= 0; i-- {
		if pkRing[i].ID == id {
			c := pkRing[i]
			pk = &c
			break
		}
		if pkRing[i].ID < id {
			break
		}
	}
	pkMu.Unlock()
	if pk == nil {
		writeJSON(w, map[string]any{"ok": false})
		return
	}
	if ipScope(pk.Remote) == "public" {
		pk.Host = hostFor(pk.Remote)
	}
	writeJSON(w, map[string]any{"ok": true, "packet": pk, "line": pktLine(pk), "dump": hexDump(pk.Raw)})
}

func handlePackets(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	pkMu.Lock()
	var out []Packet
	for i := len(pkRing) - 1; i >= 0 && len(out) < 600; i-- {
		if pkRing[i].ID <= since {
			break
		}
		out = append(out, pkRing[i])
	}
	last := pkID
	pkMu.Unlock()
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	for i := range out {
		if ipScope(out[i].Remote) == "public" {
			out[i].Host = hostFor(out[i].Remote)
		}
	}
	writeJSON(w, map[string]any{"packets": out, "last": last, "status": snifferStatus()})
}
