package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// VPN awareness. A threat report is much easier to read when it says whether the
// address belongs to the VPN itself, whether the traffic is carried through the VPN
// or goes around it. Everything here is read from Windows: adapters, routing table,
// DNS settings and the connections of VPN client programs.

type VPNAdapter struct {
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	IP     string   `json:"ip"`
	Status string   `json:"status"`
	Index  int      `json:"index"`
	Tunnel bool     `json:"tunnel"`
	DNS    []string `json:"dns"`
	Metric int      `json:"-"`
}

type VPNEndpoint struct {
	Remote string `json:"remote"`
	Host   string `json:"host"`
	Port   uint32 `json:"port"`
	Proto  string `json:"proto"`
	Conns  int    `json:"conns"`
	Bytes  uint64 `json:"bytes"`
}

type VPNClient struct {
	Name      string        `json:"name"`
	Exe       string        `json:"exe"`
	Signer    string        `json:"signer"`
	PID       int32         `json:"pid"`
	PIDs      []int32       `json:"pids"`
	Conns     int           `json:"conns"`
	Endpoints []VPNEndpoint `json:"endpoints"`
}

type VPNState struct {
	Active        bool         `json:"active"`
	Adapters      []VPNAdapter `json:"adapters"`
	Physical      []VPNAdapter `json:"physical"`
	Clients       []VPNClient  `json:"clients"`
	DefaultIface  string       `json:"defaultIface"`
	DefaultViaVPN bool         `json:"defaultViaVpn"`
	Summary       []string     `json:"summary"`
	At            int64        `json:"at"`
}

type VPNAssess struct {
	Verdict string   `json:"verdict"` // client | server | via | direct | none | na
	Title   string   `json:"title"`
	Details []string `json:"details"`
}

type VPNScanRow struct {
	Proc     string   `json:"proc"`
	Exe      string   `json:"exe"`
	PID      int32    `json:"pid"`
	ViaVPN   int      `json:"viaVpn"`
	Direct   int      `json:"direct"`
	Examples []string `json:"examples"` // connections that bypass the VPN
	Verdict  string   `json:"verdict"`  // client | vpn | mixed | direct
}

type routeEnt struct {
	Net     *net.IPNet
	Ones    int
	Metric  int
	IfIndex int
}

var (
	vpnMu     sync.RWMutex
	vpnSt     *VPNState
	vpnRoutes []routeEnt
	vpnIf     = map[int]*VPNAdapter{}
)

var (
	tunnelDesc  = regexp.MustCompile(`(?i)wintun|tap-windows|tap-win|wireguard|openvpn|vpn|nordlynx|zerotier|tailscale|anyconnect|fortinet|sstp|l2tp|pptp|ikev2|hamachi|radmin|tun\b`)
	notTunnel   = regexp.MustCompile(`(?i)teredo|6to4|isatap|ip-https|hyper-v|vethernet|vmware|virtualbox|loopback|bluetooth`)
	vpnTunBlock = func() *net.IPNet { _, n, _ := net.ParseCIDR("198.18.0.0/15"); return n }()
)

// isTunnelAdapter tells VPN adapters from ordinary and from IPv6-transition ones.
func isTunnelAdapter(name, desc, ip string) bool {
	if p := net.ParseIP(ip); p != nil && vpnTunBlock.Contains(p) {
		return true
	}
	return (tunnelDesc.MatchString(desc) || tunnelDesc.MatchString(name)) && !notTunnel.MatchString(desc)
}

func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

const vpnScript = `
$ad=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,Status,ifIndex)
$ip=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceIndex,IPAddress,PrefixLength)
$rt=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric)
$im=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceIndex,InterfaceMetric)
$dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceIndex,@{n='Servers';e={@($_.ServerAddresses)}})
[pscustomobject]@{Adapters=$ad;IPs=$ip;Routes=$rt;Metrics=$im;DNS=$dns} | ConvertTo-Json -Compress -Depth 4`

func vpnLoop() {
	for {
		refreshVPN()
		time.Sleep(20 * time.Second)
	}
}

func refreshVPN() {
	out, _ := runPS(vpnScript, 40*time.Second)
	root := psRoot(out)
	if root == nil {
		return
	}
	ifs := map[int]*VPNAdapter{}
	for _, a := range listOf(root["Adapters"]) {
		idx := num(a["ifIndex"])
		ifs[idx] = &VPNAdapter{Name: str(a["Name"]), Desc: str(a["InterfaceDescription"]), Status: str(a["Status"]), Index: idx}
	}
	for _, a := range listOf(root["IPs"]) {
		if ad := ifs[num(a["InterfaceIndex"])]; ad != nil && ad.IP == "" {
			ad.IP = str(a["IPAddress"])
		}
	}
	for _, a := range listOf(root["Metrics"]) {
		if ad := ifs[num(a["InterfaceIndex"])]; ad != nil {
			ad.Metric = num(a["InterfaceMetric"])
		}
	}
	for _, a := range listOf(root["DNS"]) {
		if ad := ifs[num(a["InterfaceIndex"])]; ad != nil {
			ad.DNS = strList(a["Servers"])
		}
	}
	for _, ad := range ifs {
		ad.Tunnel = isTunnelAdapter(ad.Name, ad.Desc, ad.IP)
	}
	var routes []routeEnt
	for _, r := range listOf(root["Routes"]) {
		_, n, err := net.ParseCIDR(str(r["DestinationPrefix"]))
		if err != nil {
			continue
		}
		ones, _ := n.Mask.Size()
		routes = append(routes, routeEnt{Net: n, Ones: ones, Metric: num(r["RouteMetric"]), IfIndex: num(r["InterfaceIndex"])})
	}

	vpnMu.Lock()
	vpnRoutes, vpnIf = routes, ifs
	vpnMu.Unlock()

	st := &VPNState{At: time.Now().UnixMilli()}
	var ids []int
	for i := range ifs {
		ids = append(ids, i)
	}
	sort.Ints(ids)
	for _, i := range ids {
		ad := *ifs[i]
		if ad.Status != "Up" || ad.IP == "" || strings.HasPrefix(ad.IP, "127.") {
			continue
		}
		if ad.Tunnel {
			st.Adapters = append(st.Adapters, ad)
		} else {
			st.Physical = append(st.Physical, ad)
		}
	}
	if def, tun := routeVia("8.8.4.4"); def != nil {
		st.DefaultIface, st.DefaultViaVPN = def.Name, tun
	}
	st.Active = len(st.Adapters) > 0
	st.Clients = vpnClients()
	st.Summary = vpnSummary(st)

	vpnMu.Lock()
	vpnSt = st
	vpnMu.Unlock()
}

// routeVia answers: through which adapter does Windows send traffic to this address?
func routeVia(ip string) (*VPNAdapter, bool) {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return nil, false
	}
	vpnMu.RLock()
	defer vpnMu.RUnlock()
	best, bestOnes, bestMetric := -1, -1, 1<<30
	for i, r := range vpnRoutes {
		if !r.Net.Contains(p) {
			continue
		}
		m := r.Metric
		if ad := vpnIf[r.IfIndex]; ad != nil {
			m += ad.Metric
		}
		if r.Ones > bestOnes || (r.Ones == bestOnes && m < bestMetric) {
			best, bestOnes, bestMetric = i, r.Ones, m
		}
	}
	if best < 0 {
		return nil, false
	}
	ad := vpnIf[vpnRoutes[best].IfIndex]
	if ad == nil {
		return nil, false
	}
	c := *ad
	return &c, ad.Tunnel
}

func vpnClients() []VPNClient {
	flowBytes := map[string]uint64{}
	for _, f := range flowsSnapshot() {
		flowBytes[fmt.Sprintf("%d|%s", f.PID, f.Remote)] += f.In + f.Out
	}
	conns := connsSnapshot()
	byProg := map[string]*VPNClient{}
	eps := map[string]map[string]*VPNEndpoint{}
	var order []string
	for _, p := range procsSnapshot() {
		if !isTunnelTool(p) {
			continue
		}
		key := strings.ToLower(firstNonEmpty(p.Exe, p.Name))
		c := byProg[key]
		if c == nil {
			c = &VPNClient{Name: p.Name, Exe: p.Exe, Signer: p.Signer, PID: p.PID}
			byProg[key] = c
			eps[key] = map[string]*VPNEndpoint{}
			order = append(order, key)
		}
		c.PIDs = append(c.PIDs, p.PID)
		for _, cn := range conns {
			if cn.PID != p.PID || cn.Dir == "listen" || cn.Scope != "public" {
				continue
			}
			c.Conns++
			e := eps[key][cn.Remote]
			if e == nil {
				e = &VPNEndpoint{Remote: cn.Remote, Host: cn.Host, Port: cn.RPort, Proto: cn.Proto}
				eps[key][cn.Remote] = e
			}
			e.Conns++
			e.Bytes += flowBytes[fmt.Sprintf("%d|%s", p.PID, cn.Remote)]
		}
	}
	var out []VPNClient
	for _, key := range order {
		c := byProg[key]
		for _, e := range eps[key] {
			c.Endpoints = append(c.Endpoints, *e)
		}
		sort.Slice(c.Endpoints, func(i, j int) bool {
			if c.Endpoints[i].Bytes != c.Endpoints[j].Bytes {
				return c.Endpoints[i].Bytes > c.Endpoints[j].Bytes
			}
			return c.Endpoints[i].Conns > c.Endpoints[j].Conns
		})
		if len(c.Endpoints) > 8 {
			c.Endpoints = c.Endpoints[:8]
		}
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Conns > out[j].Conns })
	return out
}

func vpnSummary(st *VPNState) []string {
	var s []string
	if !st.Active {
		s = append(s, "VPN-адаптеров не найдено: весь трафик идёт напрямую, под вашим настоящим адресом.")
		return s
	}
	for _, a := range st.Adapters {
		s = append(s, fmt.Sprintf("VPN-адаптер: %s (%s), адрес %s.", a.Name, a.Desc, a.IP))
	}
	if st.DefaultViaVPN {
		s = append(s, "Маршрут по умолчанию идёт через VPN: весь интернет-трафик компьютера проходит через туннель, сайты видят адрес VPN, а не ваш.")
	} else {
		s = append(s, fmt.Sprintf("Маршрут по умолчанию идёт мимо VPN (через «%s»): через туннель идёт только часть трафика.", st.DefaultIface))
	}
	if len(st.Clients) == 0 {
		s = append(s, "Процесс VPN-клиента сейчас не виден: он может работать как служба с повышенными правами. Запустите LocationFace от имени администратора, чтобы его увидеть.")
	}
	for _, c := range st.Clients {
		procs := ""
		if len(c.PIDs) > 1 {
			procs = fmt.Sprintf(", процессов: %d", len(c.PIDs))
		}
		if c.Conns == 0 {
			s = append(s, fmt.Sprintf("VPN-клиент: %s%s — сейчас без внешних соединений (не подключён или работает в фоне).", c.Name, procs))
		} else {
			s = append(s, fmt.Sprintf("VPN-клиент: %s%s — внешних соединений: %d.", c.Name, procs, c.Conns))
		}
	}
	// DNS: leaving the tunnel is the usual leak
	vpnMu.RLock()
	defer vpnMu.RUnlock()
	for _, a := range st.Physical {
		ad := vpnIf[a.Index]
		if ad == nil || len(ad.DNS) == 0 {
			continue
		}
		var inside, outside []string
		for _, d := range ad.DNS {
			if p := net.ParseIP(d); p != nil && (vpnTunBlock.Contains(p) || isPrivateIP(p)) {
				inside = append(inside, d)
			} else {
				outside = append(outside, d)
			}
		}
		switch {
		case len(outside) > 0 && st.DefaultViaVPN:
			s = append(s, fmt.Sprintf("DNS на адаптере «%s»: %s. Это внешние серверы; при полном VPN запросы к ним всё равно идут через туннель, но проверьте, нет ли утечки DNS.", a.Name, strings.Join(outside, ", ")))
		case len(inside) > 0:
			s = append(s, fmt.Sprintf("DNS на адаптере «%s»: %s — адрес внутри VPN или локальной сети, утечки DNS не видно.", a.Name, strings.Join(inside, ", ")))
		}
	}
	return s
}

func isPrivateIP(p net.IP) bool { return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() }

func vpnState() *VPNState {
	vpnMu.RLock()
	defer vpnMu.RUnlock()
	return vpnSt
}

// assessVPN explains how one finding relates to the VPN.
func assessVPN(in *Incident) VPNAssess {
	st := vpnState()
	if st == nil {
		return VPNAssess{Verdict: "na", Title: "Состояние VPN ещё определяется", Details: []string{"Подождите несколько секунд и откройте карточку снова."}}
	}
	netless := map[string]bool{"defender": true, "autorun": true, "download": true, "stealer": true}
	if in.Remote == "" && netless[in.Kind] {
		return VPNAssess{Verdict: "na", Title: "Не связано с сетью — VPN на эту находку не влияет",
			Details: []string{"Это обнаружение касается файла или записи на диске, а не сетевого соединения.", vpnOneLine(st)}}
	}
	// 1. the program itself is a VPN client
	probe := &ProcMeta{Name: in.Proc, Exe: in.Exe}
	if in.Exe != "" && isTunnelTool(probe) {
		return VPNAssess{Verdict: "client", Title: "Это VPN-клиент: " + in.Proc,
			Details: []string{"Программа определена как VPN или прокси (по названию или по драйверу туннеля рядом с ней).",
				"Её соединения — это и есть работа VPN: она связывается с серверами VPN и передаёт через туннель трафик других программ, поэтому у неё много соединений и большие объёмы данных.", vpnOneLine(st)}}
	}
	// 2. the remote address is one a VPN client talks to
	if in.Remote != "" {
		for _, c := range st.Clients {
			for _, e := range c.Endpoints {
				if e.Remote == in.Remote {
					return VPNAssess{Verdict: "server", Title: "Этот адрес — узел вашего VPN-клиента (" + c.Name + ")",
						Details: []string{fmt.Sprintf("Клиент %s прямо сейчас соединён с %s:%d — это сервер или узел, через который идёт VPN.", c.Name, e.Remote, e.Port), vpnOneLine(st)}}
				}
			}
		}
	}
	if !st.Active {
		return VPNAssess{Verdict: "none", Title: "VPN сейчас не обнаружен — трафик идёт напрямую", Details: []string{vpnOneLine(st)}}
	}
	// 3. is the traffic carried by the tunnel or does it go around it?
	via, tun := "", false
	if in.Via == "tunnel" {
		via, tun = "перехвачено на адаптере VPN", true
	}
	if ad, t := routeVia(in.Remote); ad != nil {
		if !tun {
			tun = t
		}
		if via == "" {
			via = "маршрут к адресу идёт через «" + ad.Name + "»"
		} else {
			via += "; " + "маршрут к адресу идёт через «" + ad.Name + "»"
		}
	}
	if in.Remote == "" {
		return VPNAssess{Verdict: "na", Title: "Адрес не определён — нельзя сказать, идёт ли это через VPN", Details: []string{vpnOneLine(st)}}
	}
	if tun {
		return VPNAssess{Verdict: "via", Title: "Идёт через VPN",
			Details: []string{via + ".", "Внешний адрес, который видит сервер на той стороне, — адрес VPN, а не ваш настоящий.",
				"Сама угроза от этого не исчезает: VPN лишь скрывает ваш адрес, а вредоносная программа по-прежнему работает на вашем компьютере.", vpnOneLine(st)}}
	}
	return VPNAssess{Verdict: "direct", Title: "Мимо VPN — соединение идёт напрямую",
		Details: []string{via + ".", "Это соединение не защищено VPN: сервер видит ваш настоящий адрес.",
			"При включённом VPN так бывает у программ из исключений VPN (раздельное туннелирование) и у самого VPN-клиента; если программа вам незнакома — это отдельный повод насторожиться.", vpnOneLine(st)}}
}

func vpnOneLine(st *VPNState) string {
	if !st.Active {
		return "VPN: не обнаружен."
	}
	names := make([]string, 0, len(st.Adapters))
	for _, a := range st.Adapters {
		names = append(names, a.Name)
	}
	mode := "весь трафик идёт через туннель"
	if !st.DefaultViaVPN {
		mode = "через туннель идёт только часть трафика"
	}
	return fmt.Sprintf("VPN: активен (адаптер %s), %s.", strings.Join(names, ", "), mode)
}

// vpnScan checks every current internet connection: carried by the VPN or going around it.
func vpnScan() []VPNScanRow {
	st := vpnState()
	if st == nil {
		return nil
	}
	clientPID := map[int32]bool{}
	for _, c := range st.Clients {
		clientPID[c.PID] = true
	}
	rows := map[string]*VPNScanRow{}
	for _, c := range connsSnapshot() {
		if c.Dir == "listen" || c.Scope != "public" || c.PID == 0 {
			continue
		}
		key := fmt.Sprintf("%d", c.PID)
		r := rows[key]
		if r == nil {
			r = &VPNScanRow{Proc: c.Proc, Exe: c.Exe, PID: c.PID}
			rows[key] = r
		}
		if clientPID[c.PID] {
			r.Verdict = "client"
			r.Direct++ // its own connections leave the machine by the physical adapter, by design
			continue
		}
		if ad, tun := routeVia(c.Remote); ad != nil && tun {
			r.ViaVPN++
		} else {
			r.Direct++
			if len(r.Examples) < 4 {
				h := c.Remote
				if c.Host != "" {
					h = c.Host + " (" + c.Remote + ")"
				}
				r.Examples = append(r.Examples, fmt.Sprintf("%s → %s:%d", c.Proto, h, c.RPort))
			}
		}
	}
	var out []VPNScanRow
	for _, r := range rows {
		if r.Verdict == "" {
			switch {
			case r.Direct == 0:
				r.Verdict = "vpn"
			case r.ViaVPN == 0:
				r.Verdict = "direct"
			default:
				r.Verdict = "mixed"
			}
		}
		out = append(out, *r)
	}
	rank := map[string]int{"direct": 0, "mixed": 1, "client": 2, "vpn": 3}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Verdict] != rank[out[j].Verdict] {
			return rank[out[i].Verdict] < rank[out[j].Verdict]
		}
		return out[i].Direct+out[i].ViaVPN > out[j].Direct+out[j].ViaVPN
	})
	return out
}
