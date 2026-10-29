package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// ---------------------------------------------------------------- types

type ProcMeta struct {
	PID      int32    `json:"pid"`
	PPID     int32    `json:"ppid"`
	Parent   string   `json:"parent"`
	Name     string   `json:"name"`
	Exe      string   `json:"exe"`
	Cmd      string   `json:"cmd"`
	User     string   `json:"user"`
	Created  int64    `json:"created"`
	Sig      string   `json:"sig"`
	Signer   string   `json:"signer"`
	SHA256   string   `json:"sha256"`
	Score    int      `json:"score"`
	Level    string   `json:"level"` // ok | warn | bad
	Reasons  []string `json:"reasons"`
	Conns    int      `json:"conns"`
	BytesIn  uint64   `json:"bytesIn"`
	BytesOut uint64   `json:"bytesOut"`
}

type Conn struct {
	PID     int32    `json:"pid"`
	Proc    string   `json:"proc"`
	Exe     string   `json:"exe"`
	Proto   string   `json:"proto"`
	Local   string   `json:"local"`
	LPort   uint32   `json:"lport"`
	Remote  string   `json:"remote"`
	RPort   uint32   `json:"rport"`
	Status  string   `json:"status"`
	Dir     string   `json:"dir"`   // out | in | listen
	Scope   string   `json:"scope"` // public | private | loopback | none
	Host    string   `json:"host"`
	Sig     string   `json:"sig"`
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
	Blocked bool     `json:"blocked"`
}

// ---------------------------------------------------------------- state

var (
	stMu     sync.RWMutex
	curConns []Conn
	curProcs []*ProcMeta

	metaMu    sync.Mutex
	metaCache = map[string]*ProcMeta{} // pid-created -> meta

	portMap atomic.Pointer[map[string]int32] // "tcp:443" -> pid
)

func connsSnapshot() []Conn {
	stMu.RLock()
	defer stMu.RUnlock()
	out := append([]Conn(nil), curConns...)
	return out
}

func procsSnapshot() []*ProcMeta {
	stMu.RLock()
	defer stMu.RUnlock()
	return append([]*ProcMeta(nil), curProcs...)
}

func pidForPort(proto string, port uint16) int32 {
	m := portMap.Load()
	if m == nil {
		return 0
	}
	return (*m)[fmt.Sprintf("%s:%d", proto, port)]
}

// ---------------------------------------------------------------- signatures

type sigInfo struct{ Status, Signer string }

var (
	sigMu      sync.Mutex
	sigCache   = map[string]sigInfo{}
	sigPending = map[string]bool{}
	sigQueue   = make(chan string, 8192)
)

func sigKey(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return strings.ToLower(path)
	}
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(path), st.Size(), st.ModTime().Unix())
}

// getSig returns the cached verdict or queues the file for checking.
func getSig(path string) sigInfo {
	if path == "" {
		return sigInfo{"unknown", ""}
	}
	if _, err := os.Stat(path); err != nil {
		return sigInfo{"missing", ""}
	}
	k := sigKey(path)
	sigMu.Lock()
	defer sigMu.Unlock()
	if s, ok := sigCache[k]; ok {
		return s
	}
	if !sigPending[k] {
		sigPending[k] = true
		select {
		case sigQueue <- path:
		default:
			delete(sigPending, k)
		}
	}
	return sigInfo{"pending", ""}
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func sigWorker() {
	for {
		batch := []string{<-sigQueue}
		deadline := time.After(1200 * time.Millisecond)
	collect:
		for len(batch) < 40 {
			select {
			case p := <-sigQueue:
				batch = append(batch, p)
			case <-deadline:
				break collect
			}
		}
		quoted := make([]string, len(batch))
		for i, p := range batch {
			quoted[i] = psQuote(p)
		}
		script := "$p=@(" + strings.Join(quoted, ",") + "); Get-AuthenticodeSignature -LiteralPath $p | ForEach-Object { [pscustomobject]@{Path=$_.Path;Status=$_.Status.ToString();Subject=$(if($_.SignerCertificate){$_.SignerCertificate.Subject}else{''})} } | ConvertTo-Json -Compress"
		res := psJSON(script, 90*time.Second)
		got := map[string]sigInfo{}
		for _, r := range res {
			got[strings.ToLower(str(r["Path"]))] = sigInfo{mapSigStatus(str(r["Status"])), signerCN(str(r["Subject"]))}
		}
		sigMu.Lock()
		for _, p := range batch {
			k := sigKey(p)
			s, ok := got[strings.ToLower(p)]
			if !ok {
				s = sigInfo{"unknown", ""}
			}
			sigCache[k] = s
			delete(sigPending, k)
		}
		sigMu.Unlock()
	}
}

func mapSigStatus(s string) string {
	switch s {
	case "Valid":
		return "signed"
	case "NotSigned":
		return "unsigned"
	case "HashMismatch":
		return "tampered"
	case "NotTrusted", "UnknownError", "Incompatible":
		return "untrusted"
	}
	return "unknown"
}

func signerCN(subject string) string {
	i := strings.Index(subject, "CN=")
	if i < 0 {
		return ""
	}
	s := subject[i+3:]
	if strings.HasPrefix(s, `"`) {
		if j := strings.Index(s[1:], `"`); j >= 0 {
			return s[1 : j+1]
		}
	}
	if j := strings.Index(s, ", "); j >= 0 {
		s = s[:j]
	}
	return s
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > 300<<20 {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- host names

var (
	hostMu    sync.Mutex
	hostNames = map[string]string{} // ip -> name (SNI, HTTP Host, DNS cache, reverse DNS)
	rdnsBusy  = map[string]bool{}
	rdnsSem   = make(chan struct{}, 8)
)

func noteHost(ip, name string) {
	if ip == "" || name == "" {
		return
	}
	hostMu.Lock()
	hostNames[ip] = name
	hostMu.Unlock()
}

func hostFor(ip string) string {
	hostMu.Lock()
	n, ok := hostNames[ip]
	if !ok && !rdnsBusy[ip] {
		rdnsBusy[ip] = true
		go func() {
			rdnsSem <- struct{}{}
			defer func() { <-rdnsSem }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			name := ""
			if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
				name = strings.TrimSuffix(names[0], ".")
			}
			hostMu.Lock()
			if _, exists := hostNames[ip]; !exists {
				hostNames[ip] = name
			}
			hostMu.Unlock()
		}()
	}
	hostMu.Unlock()
	return n
}

func ipScope(ip string) string {
	p := net.ParseIP(ip)
	switch {
	case p == nil || p.IsUnspecified():
		return "none"
	case p.IsLoopback():
		return "loopback"
	case p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() || p.IsMulticast():
		return "private"
	}
	return "public"
}

// ---------------------------------------------------------------- risk rules

var (
	sysNames = map[string]bool{"svchost.exe": true, "lsass.exe": true, "csrss.exe": true, "winlogon.exe": true,
		"services.exe": true, "smss.exe": true, "wininit.exe": true, "spoolsv.exe": true, "taskhostw.exe": true,
		"explorer.exe": true, "dwm.exe": true, "conhost.exe": true, "searchindexer.exe": true, "runtimebroker.exe": true}
	noExeOK = map[string]bool{"System": true, "Registry": true, "Memory Compression": true, "Secure System": true,
		"System Idle Process": true, "Idle": true, "vmmem": true, "Registry ": true}
	lolbins = map[string]bool{"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
		"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true, "bitsadmin.exe": true, "msiexec.exe": true}
	ratPorts = map[uint32]string{4444: "Metasploit", 5555: "ADB/RAT", 1337: "backdoor", 31337: "backdoor", 6667: "IRC-бот",
		6697: "IRC-бот", 9001: "Tor", 9050: "Tor", 8333: "Bitcoin", 3333: "майнинг", 14444: "майнинг", 4545: "RAT", 7777: "RAT", 12345: "NetBus"}
	commonPorts = map[uint32]bool{80: true, 443: true, 53: true, 8080: true, 8443: true, 993: true, 995: true, 465: true, 587: true,
		143: true, 110: true, 25: true, 22: true, 123: true, 5222: true, 5228: true, 853: true, 3478: true, 5223: true, 1900: true, 5353: true}
	susCmd = []string{"-encodedcommand", " -enc ", "frombase64string", "-windowstyle hidden", "-w hidden",
		"downloadstring", "downloadfile", "iex(", "iex (", "-urlcache", "mshta http", "regsvr32 /s /n /u /i:http", "javascript:"}
)

// weakCmd marks command-line patterns that also appear in ordinary scripts.
var weakCmd = map[string]bool{"-encodedcommand": true, " -enc ": true, "-windowstyle hidden": true, "-w hidden": true}

func under(path, dir string) bool {
	return dir != "" && strings.HasPrefix(strings.ToLower(path), strings.ToLower(dir))
}

func scoreProc(m *ProcMeta) {
	var rs []string
	add := func(n int, why string) { m.Score += n; rs = append(rs, why) }
	m.Score = 0
	if isUserTrusted(m.Exe) {
		m.Reasons, m.Level = nil, "ok"
		return
	}
	winDir := os.Getenv("SystemRoot")
	lp := strings.ToLower(m.Exe)
	ln := strings.ToLower(m.Name)

	if m.Exe == "" {
		if m.PID > 4 && !noExeOK[m.Name] && isAdmin() {
			add(1, "Нет пути к исполняемому файлу")
		}
	} else {
		if _, err := os.Stat(m.Exe); err != nil {
			add(4, "Файл процесса удалён с диска (возможна подмена или «безфайловый» запуск)")
		}
		switch {
		case strings.Contains(lp, `\appdata\local\temp\`) || strings.Contains(lp, `\windows\temp\`) || strings.Contains(lp, `\downloads\`):
			add(3, "Запущен из временной папки или «Загрузок»")
		case strings.Contains(lp, `\users\public\`) || strings.Contains(lp, `\$recycle.bin\`):
			add(3, "Запущен из общей или корзины")
		case strings.Contains(lp, `\appdata\`) || (strings.Contains(lp, `\programdata\`) && !strings.Contains(lp, `\programdata\microsoft\`)):
			add(1, "Запущен из папки пользователя (AppData/ProgramData)")
		}
		if sysNames[ln] && !under(m.Exe, winDir) {
			add(6, "Имя системного процесса, но файл лежит не в Windows — маскировка под систему")
		}
		switch m.Sig {
		case "tampered":
			add(6, "Подпись файла нарушена: файл изменён после подписания")
		case "unsigned":
			if under(m.Exe, winDir) {
				add(3, "Нет цифровой подписи, хотя файл в папке Windows")
			} else {
				add(2, "Нет цифровой подписи издателя")
			}
		case "untrusted":
			add(2, "Подпись не вызывает доверия")
		}
	}
	lc := strings.ToLower(m.Cmd)
	var weak, strong string
	nWeak := 0
	for _, s := range susCmd {
		if strings.Contains(lc, s) {
			if weakCmd[s] {
				nWeak++
				weak = s
			} else if strong == "" {
				strong = s
			}
		}
	}
	// an encoded PowerShell command is judged by what it actually says
	if script, ok := decodePSCommand(m.Cmd); ok {
		if why := maliciousScript(script); why != "" {
			add(4, "Закодированная команда PowerShell делает опасное: "+why)
		}
		nWeak, weak = 0, "" // decoded and harmless: hiding the window or encoding alone proves nothing
	}
	switch {
	case strong != "":
		add(4, "Подозрительная командная строка («"+strings.TrimSpace(strong)+"»)")
	case nWeak >= 2:
		add(4, "Скрытый запуск с закодированной командой — типичный приём вредоносных скриптов")
	case nWeak == 1:
		add(2, "Командная строка с приёмом, который используют и вирусы, и обычные скрипты («"+strings.TrimSpace(weak)+"»)")
	}
	m.Reasons = rs
	m.Level = levelOf(m.Score)
}

func levelOf(score int) string {
	switch {
	case score >= 4:
		return "bad"
	case score >= 2:
		return "warn"
	}
	return "ok"
}

// ---------------------------------------------------------------- collection

func metaFor(pid int32) *ProcMeta {
	p, err := process.NewProcess(pid)
	if err != nil {
		return nil
	}
	created, _ := p.CreateTime()
	key := fmt.Sprintf("%d-%d", pid, created)
	metaMu.Lock()
	m, ok := metaCache[key]
	metaMu.Unlock()
	if !ok {
		m = &ProcMeta{PID: pid, Created: created}
		m.Name, _ = p.Name()
		m.Exe, _ = p.Exe()
		m.Cmd, _ = p.Cmdline()
		m.User, _ = p.Username()
		ppid, _ := p.Ppid()
		m.PPID = ppid
		if pp, err := process.NewProcess(ppid); err == nil {
			m.Parent, _ = pp.Name()
		}
		metaMu.Lock()
		metaCache[key] = m
		metaMu.Unlock()
	}
	// signature and hash can arrive later
	s := getSig(m.Exe)
	m.Sig, m.Signer = s.Status, s.Signer
	if m.SHA256 == "" && m.Exe != "" && s.Status != "pending" {
		m.SHA256 = fileSHA256(m.Exe)
	}
	scoreProc(m)
	return m
}

func connLoop() {
	for {
		collect()
		time.Sleep(2 * time.Second)
	}
}

func collect() {
	cs, err := gnet.Connections("inet")
	if err != nil {
		return
	}
	pids, _ := process.Pids()
	metas := map[int32]*ProcMeta{}
	var list []*ProcMeta
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		if m := metaFor(pid); m != nil {
			m2 := *m
			m2.Conns, m2.BytesIn, m2.BytesOut = 0, 0, 0
			metas[pid] = &m2
			list = append(list, &m2)
		}
	}

	// listening ports decide if a connection is inbound
	listening := map[string]bool{}
	for _, c := range cs {
		if c.Type == syscall.SOCK_STREAM && c.Status == "LISTEN" {
			listening[fmt.Sprintf("%d", c.Laddr.Port)] = true
		}
	}
	pm := map[string]int32{}
	blocked := blockedSet()
	var out []Conn
	for _, c := range cs {
		proto := "TCP"
		if c.Type == syscall.SOCK_DGRAM {
			proto = "UDP"
		}
		lp := strings.ToLower(proto)
		if c.Pid > 0 {
			pm[fmt.Sprintf("%s:%d", lp, c.Laddr.Port)] = c.Pid
		}
		m := metas[c.Pid]
		cn := Conn{PID: c.Pid, Proto: proto, Local: c.Laddr.IP, LPort: c.Laddr.Port, Remote: c.Raddr.IP, RPort: c.Raddr.Port, Status: c.Status}
		if proto == "UDP" && c.Status == "" {
			cn.Status = "—"
		}
		if m != nil {
			cn.Proc, cn.Exe, cn.Sig = m.Name, m.Exe, m.Sig
			m.Conns++
		} else if c.Pid == 0 {
			cn.Proc = "System Idle / ядро"
		}
		cn.Scope = ipScope(c.Raddr.IP)
		switch {
		case c.Status == "LISTEN" || c.Raddr.Port == 0:
			cn.Dir = "listen"
		case listening[fmt.Sprintf("%d", c.Laddr.Port)]:
			cn.Dir = "in"
		default:
			cn.Dir = "out"
		}
		if cn.Scope == "public" {
			cn.Host = hostFor(c.Raddr.IP)
			cn.Blocked = blocked[c.Raddr.IP]
		}
		scoreConn(&cn, m)
		out = append(out, cn)
	}
	for _, m := range list {
		in, o := trafficFor(m.PID)
		m.BytesIn, m.BytesOut = in, o
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Proc < out[j].Proc
	})
	sort.Slice(list, func(i, j int) bool {
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		return list[i].Name < list[j].Name
	})
	portMap.Store(&pm)
	recordLiveIncidents(out, metas)
	names := make(map[int32]string, len(list))
	for _, m := range list {
		names[m.PID] = m.Name
	}
	pidNames.Store(&names)
	stMu.Lock()
	curConns, curProcs = out, list
	stMu.Unlock()
}

func scoreConn(c *Conn, m *ProcMeta) {
	var rs []string
	score := 0
	if m != nil {
		score = m.Score
		rs = append(rs, m.Reasons...)
	}
	if c.Scope == "public" && c.Dir != "listen" {
		if why, ok := ratPorts[c.RPort]; ok {
			score += 3
			rs = append(rs, fmt.Sprintf("Порт %d часто используют: %s", c.RPort, why))
		}
		if m != nil && lolbins[strings.ToLower(m.Name)] {
			score += 3
			rs = append(rs, "Системная утилита ("+m.Name+") выходит в интернет — так часто скачивают вредоносный код")
		}
		if !commonPorts[c.RPort] && c.Proto == "TCP" && m != nil && m.Sig != "signed" {
			score++
			rs = append(rs, fmt.Sprintf("Неподписанная программа на нестандартном порту %d", c.RPort))
		}
	}
	if c.Dir == "listen" && (c.Local == "0.0.0.0" || c.Local == "::") && m != nil && m.Exe != "" && m.Sig != "signed" && m.Sig != "pending" {
		score++
		rs = append(rs, "Неподписанная программа принимает подключения из сети")
	}
	c.Score, c.Reasons, c.Level = score, rs, levelOf(score)
}

// ---------------------------------------------------------------- DNS cache

var (
	dnsMu    sync.RWMutex
	dnsCache []map[string]any
)

func dnsCacheLoop() {
	for {
		res := psJSON("Get-DnsClientCache | Select-Object Entry,Name,Type,Data,TimeToLive | ConvertTo-Json -Compress", 30*time.Second)
		for _, r := range res {
			if t := str(r["Type"]); t == "1" || t == "28" {
				noteHost(str(r["Data"]), strings.TrimSuffix(str(r["Entry"]), "."))
			}
		}
		dnsMu.Lock()
		dnsCache = res
		dnsMu.Unlock()
		time.Sleep(20 * time.Second)
	}
}

func dnsSnapshot() map[string]any {
	dnsMu.RLock()
	cache := append([]map[string]any(nil), dnsCache...)
	dnsMu.RUnlock()
	return map[string]any{"cache": cache, "queries": dnsQueries()}
}

// ---------------------------------------------------------------- actions

func killPID(pid int32) error {
	if pid <= 4 {
		return errors.New("системный процесс трогать нельзя")
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

var (
	blkMu  sync.Mutex
	blkSet map[string]bool
)

func blockedFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "LocationFace", "blocked.json")
}

func blockedSet() map[string]bool {
	blkMu.Lock()
	defer blkMu.Unlock()
	if blkSet == nil {
		blkSet = map[string]bool{}
		if data, err := os.ReadFile(blockedFile()); err == nil {
			var l []string
			_ = json.Unmarshal(data, &l)
			for _, ip := range l {
				blkSet[ip] = true
			}
		}
	}
	out := make(map[string]bool, len(blkSet))
	for k := range blkSet {
		out[k] = true
	}
	return out
}

func saveBlocked() {
	var l []string
	for ip := range blkSet {
		l = append(l, ip)
	}
	sort.Strings(l)
	_ = os.MkdirAll(filepath.Dir(blockedFile()), 0o755)
	data, _ := json.Marshal(l)
	_ = os.WriteFile(blockedFile(), data, 0o600)
}

func netsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func blockIP(ip string) error {
	p := net.ParseIP(ip)
	if p == nil || ipScope(ip) != "public" {
		return errors.New("блокировать можно только внешний IP-адрес")
	}
	name := "LocationFace block " + ip
	for _, dir := range []string{"out", "in"} {
		if err := netsh("advfirewall", "firewall", "add", "rule", "name="+name, "dir="+dir, "action=block", "remoteip="+ip); err != nil {
			return err
		}
	}
	blockedSet()
	blkMu.Lock()
	blkSet[ip] = true
	saveBlocked()
	blkMu.Unlock()
	return nil
}

func unblockIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return errors.New("неверный IP")
	}
	err := netsh("advfirewall", "firewall", "delete", "rule", "name=LocationFace block "+ip)
	blockedSet()
	blkMu.Lock()
	delete(blkSet, ip)
	saveBlocked()
	blkMu.Unlock()
	return err
}
