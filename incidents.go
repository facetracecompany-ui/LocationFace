package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Evidence struct {
	T    int64  `json:"t"`
	Line string `json:"line"`
	Dump string `json:"dump,omitempty"`
}

type Incident struct {
	ID       int64      `json:"id"`
	Key      string     `json:"key"`
	Kind     string     `json:"kind"`
	Severity string     `json:"severity"` // bad | warn
	Title    string     `json:"title"`
	What     string     `json:"what"`
	Reasons  []string   `json:"reasons"`
	Advice   string     `json:"advice"`
	First    int64      `json:"first"`
	Last     int64      `json:"last"`
	Count    int        `json:"count"`
	PID      int32      `json:"pid"`
	Proc     string     `json:"proc"`
	Exe      string     `json:"exe"`
	Cmd      string     `json:"cmd"`
	User     string     `json:"user"`
	Parent   string     `json:"parent"`
	Sig      string     `json:"sig"`
	Signer   string     `json:"signer"`
	SHA256   string     `json:"sha256"`
	Started  int64      `json:"started"`
	Remote   string     `json:"remote"`
	Host     string     `json:"host"`
	RPort    uint16     `json:"rport"`
	Proto    string     `json:"proto"`
	Ref      string     `json:"ref"` // kind-specific reference, e.g. the Defender threat name
	Via      string     `json:"via"` // tunnel | physical: the adapter the traffic was seen on
	VPN      *VPNAssess `json:"vpn,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

type kindText struct{ What, Advice string }

var kindInfo = map[string]kindText{
	"plain": {"Программа отправила логин или пароль по незащищённому каналу (HTTP, FTP, POP3). Данные идут открытым текстом: их может прочитать любой, кто видит сеть — Wi-Fi, провайдер, вирус-перехватчик.",
		"Не вводите пароли на сайтах без https://. Если пароль уже ушёл — смените его везде, где он использовался."},
	"scan": {"Кто-то подряд проверяет порты вашего компьютера, ища открытые двери: это разведка перед взломом.",
		"Проверьте, что брандмауэр включён и ненужные порты закрыты. Если адрес из вашей локальной сети — найдите это устройство: оно может быть заражено."},
	"bruteforce": {"С одного адреса идут повторные попытки подключиться к службам удалённого доступа (RDP, SSH, SMB, Telnet, базы данных). Так перебирают пароли.",
		"Отключите ненужные службы удалённого доступа, не выставляйте их в интернет, включите блокировку адреса (кнопка ниже)."},
	"worm": {"Этот компьютер сам рассылает подключения на десятки разных адресов по портам удалённого доступа. Так ведут себя сетевые черви и ботнеты, заражающие соседей.",
		"Срочно отключите компьютер от сети, найдите процесс-источник (указан ниже), завершите его и проверьте систему антивирусом."},
	"ratport": {"Программа подключилась к порту, который обычно используют трояны удалённого доступа, бэкдоры, майнеры или анонимайзеры.",
		"Выясните, что это за программа. Если вы её не узнаёте — завершите процесс, заблокируйте адрес и проверьте файл на VirusTotal."},
	"beacon": {"Программа соединяется с одним и тем же сервером через равные промежутки времени. Такая «пульсация» характерна для вредоносных программ, которые постоянно спрашивают у управляющего сервера новые команды (beacon).",
		"Проверьте программу: подпись, путь, издателя. Для обычного ПО (обновления, синхронизация) это нормально; для неизвестного — повод проверить файл и заблокировать адрес."},
	"exfil": {"Неподписанная программа отправила в интернет очень большой объём данных. Так может выглядеть кража файлов.",
		"Определите, что за программа и на какой адрес идёт трафик. Если это не облачная синхронизация, которую вы запускали, завершите процесс и заблокируйте адрес."},
	"dns": {"Компьютер запросил адрес, который выглядит как сгенерированный автоматически или как канал DNS-туннелирования. Такие имена используют вредоносные программы для связи с управляющими серверами.",
		"Посмотрите, какой процесс сделал запрос. Если он неизвестен — проверьте файл и завершите."},
	"httpexe": {"Исполняемый файл или скрипт скачивается по незащищённому http://. Такой файл по пути можно подменить, и именно так распространяется много вредоносного ПО.",
		"Не запускайте этот файл. Скачивайте программы только с официальных сайтов по https://."},
	"icmp": {"Через ping передаётся необычно большой объём данных. Это признак туннелирования трафика через ICMP.",
		"Определите процесс-источник; если он неизвестен — завершите и проверьте систему."},
	"upload": {"Программа отправила данные на внешний адрес, и это не похоже на обычную работу: либо программа неизвестна, либо адрес — канал, которым часто выводят украденные данные, либо рядом открыты чужие секретные файлы. Обычные отправки (мессенджер на свои серверы, браузер, обновления) сюда не попадают.",
		"Откройте доказательства: там указано, какой процесс, на какой адрес и какие файлы он держал открытыми. Если программу не узнаёте — завершите её, заблокируйте адрес и проверьте файл на VirusTotal. Если рядом были пароли или сессии — смените пароли."},
	"stealer": {"Программа открыла файлы, в которых другая программа хранит пароли, сессии или ключи (пароли браузера, сессия Telegram, токены Discord, криптокошелёк, ключи SSH). Обычным программам эти файлы не нужны — так ведут себя программы-воры.",
		"Если программа вам не знакома — завершите её и удалите. Затем смените пароли (особенно браузерные), завершите сессии Telegram и Discord на всех устройствах и проверьте компьютер антивирусом."},
	"conn": {"Программа установила соединение, которое по нескольким признакам похоже на вредоносное.",
		"Откройте процесс, проверьте файл и подпись. При сомнениях — завершите процесс и заблокируйте адрес."},
	"proc": {"Запущен процесс, набравший высокий балл подозрительности.",
		"Проверьте путь и подпись файла, при необходимости загрузите SHA-256 на VirusTotal. Неизвестное завершите."},
	"defender": {"Защитник Windows обнаружил угрозу.",
		"Безопасность Windows → Защита от вирусов и угроз → Журнал защиты: удалите или поместите угрозу в карантин, затем выполните полное сканирование."},
	"autorun": {"В автозагрузке найдена запись с признаками вредоносной.",
		"Проверьте запись на вкладке «Автозагрузка»; если вы её не создавали — удалите и проверьте файл."},
	"download": {"Скачанный файл выглядит опасным.",
		"Не запускайте файл. Проверьте его на VirusTotal (хеш на вкладке «Загрузки») и удалите, если сомневаетесь."},
}

var (
	incMu    sync.Mutex
	incs     []*Incident
	incByKey = map[string]*Incident{}
	incSeq   int64
	incDirty bool

	procIndex atomic.Pointer[map[int32]*ProcMeta]
	pidSigs   atomic.Pointer[map[int32]string]
)

func incidentsFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "LocationFace", "incidents.json")
}

func sevRank(s string) int {
	if s == "bad" {
		return 2
	}
	return 1
}

func loadIncidents() {
	data, err := os.ReadFile(incidentsFile())
	if err != nil {
		return
	}
	var list []*Incident
	if json.Unmarshal(data, &list) != nil {
		return
	}
	cut := time.Now().AddDate(0, 0, -14).UnixMilli()
	incMu.Lock()
	defer incMu.Unlock()
	for _, x := range list {
		if x.Last < cut {
			continue
		}
		// these are re-detected by every scan; keeping old copies would preserve outdated verdicts
		if x.Kind == "autorun" || x.Kind == "download" || x.Kind == "defender" || x.Kind == "exfil" {
			continue
		}
		incs = append(incs, x)
		incByKey[x.Key] = x
		if x.ID > incSeq {
			incSeq = x.ID
		}
	}
}

func incidentSaver() {
	for {
		time.Sleep(20 * time.Second)
		incMu.Lock()
		if !incDirty {
			incMu.Unlock()
			continue
		}
		data, _ := json.Marshal(incs)
		incDirty = false
		incMu.Unlock()
		_ = os.MkdirAll(filepath.Dir(incidentsFile()), 0o755)
		_ = os.WriteFile(incidentsFile(), data, 0o600)
	}
}

func addIncident(in Incident, ev *Evidence) {
	if in.Exe != "" && isUserTrusted(in.Exe) {
		return
	}
	incMu.Lock()
	defer incMu.Unlock()
	now := time.Now().UnixMilli()
	if x, ok := incByKey[in.Key]; ok {
		x.Count++
		x.Last = now
		if sevRank(in.Severity) > sevRank(x.Severity) {
			x.Severity = in.Severity
		}
		if ev != nil && len(x.Evidence) < 25 {
			x.Evidence = append(x.Evidence, *ev)
		}
		incDirty = true
		return
	}
	if t, ok := kindInfo[in.Kind]; ok {
		in.What, in.Advice = t.What, t.Advice
	}
	incSeq++
	in.ID, in.First, in.Last, in.Count = incSeq, now, now, 1
	if ev != nil {
		in.Evidence = []Evidence{*ev}
	}
	p := in
	incs = append(incs, &p)
	incByKey[p.Key] = &p
	if len(incs) > 500 {
		for _, old := range incs[:len(incs)-500] {
			delete(incByKey, old.Key)
		}
		incs = incs[len(incs)-500:]
	}
	incDirty = true
}

// upsertIncident adds an incident or refreshes an existing one with newer details.
func upsertIncident(in Incident) {
	if in.Exe != "" && isUserTrusted(in.Exe) {
		return
	}
	incMu.Lock()
	defer incMu.Unlock()
	now := time.Now().UnixMilli()
	incDirty = true
	if x, ok := incByKey[in.Key]; ok {
		if in.Kind != "defender" { // a re-check of the same Defender record is not a new occurrence
			x.Count++
			x.Last = now
		}
		x.Severity, x.Title, x.Reasons, x.Evidence = in.Severity, in.Title, in.Reasons, in.Evidence
		x.Cmd, x.SHA256, x.Sig, x.Signer, x.Exe, x.Ref = in.Cmd, in.SHA256, in.Sig, in.Signer, in.Exe, in.Ref
		return
	}
	if t, ok := kindInfo[in.Kind]; ok {
		in.What, in.Advice = t.What, t.Advice
	}
	incSeq++
	in.ID, in.First, in.Last, in.Count = incSeq, now, now, 1
	p := in
	incs = append(incs, &p)
	incByKey[p.Key] = &p
}

func incidentsSnapshot() []Incident {
	incMu.Lock()
	defer incMu.Unlock()
	out := make([]Incident, 0, len(incs))
	for _, x := range incs {
		c := *x
		a := assessVPN(&c) // computed on the way out, never stored
		c.VPN = &a
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return out
}

func clearIncidents() {
	incMu.Lock()
	incs, incByKey, incDirty = nil, map[string]*Incident{}, true
	incMu.Unlock()
}

// fillProc copies what is known about a process into the incident.
func fillProc(in *Incident, pid int32) {
	in.PID = pid
	idx := procIndex.Load()
	if idx == nil {
		return
	}
	if m := (*idx)[pid]; m != nil {
		in.Proc, in.Exe, in.Cmd, in.User, in.Parent = m.Name, m.Exe, m.Cmd, m.User, m.Parent
		in.Sig, in.Signer, in.SHA256, in.Started = m.Sig, m.Signer, m.SHA256, m.Created
	}
}

// ---------------------------------------------------------------- packets as evidence

func pktLine(p *Packet) string {
	s := fmt.Sprintf("%s  %s  %s  %s:%d → %s:%d  %d байт", time.UnixMilli(p.T).Format("15:04:05"), map[string]string{"in": "вход", "out": "выход"}[p.Dir], p.Proto, p.Src, p.SPort, p.Dst, p.DPort, p.Len)
	if p.Flags != "" {
		s += "  [" + p.Flags + "]"
	}
	if p.Info != "" {
		s += "  " + p.Info
	}
	return s
}

func evOf(p *Packet) *Evidence {
	return &Evidence{T: p.T, Line: pktLine(p), Dump: hexDump(p.Raw)}
}

// raise records an incident caused by a packet.
func raise(kind, sev, title, key string, pk *Packet, reasons ...string) {
	in := Incident{Key: key, Kind: kind, Severity: sev, Title: title, Reasons: reasons,
		Remote: pk.Remote, RPort: pk.DPort, Proto: pk.Proto}
	if pk.Dir == "in" {
		in.RPort = pk.SPort
	}
	if ipScope(pk.Remote) == "public" {
		in.Host = hostFor(pk.Remote)
	}
	fillProc(&in, pk.PID)
	if in.Proc == "" {
		in.Proc = pk.Proc
	}
	in.Via = "physical"
	if pk.Tunnel {
		in.Via = "tunnel"
	}
	addIncident(in, evOf(pk))
}

func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "%04x  ", i)
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range b[i:end] {
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// redact masks secrets before a payload is stored anywhere.
func redact(b []byte) []byte {
	out := append([]byte(nil), b...)
	low := bytes.ToLower(out)
	for _, k := range []struct {
		key string
		end string
	}{{"password=", "& \r\n;"}, {"passwd=", "& \r\n;"}, {"pwd=", "& \r\n;"}, {"pass=", "& \r\n;"}, {"token=", "& \r\n;"},
		{"authorization: basic ", "\r\n"}, {"authorization: bearer ", "\r\n"}, {"cookie: ", "\r\n"}, {"set-cookie: ", "\r\n"}} {
		from := 0
		for {
			i := bytes.Index(low[from:], []byte(k.key))
			if i < 0 {
				break
			}
			j := from + i + len(k.key)
			for j < len(out) && !strings.ContainsRune(k.end, rune(out[j])) {
				out[j] = '*'
				j++
			}
			from = j
		}
	}
	return out
}

// ---------------------------------------------------------------- domain heuristics

var susTLD = map[string]bool{"tk": true, "top": true, "xyz": true, "click": true, "gq": true, "ml": true, "cf": true, "ga": true,
	"work": true, "zip": true, "mov": true, "icu": true, "cyou": true, "buzz": true, "rest": true, "monster": true, "sbs": true}

func entropy(s string) float64 {
	cnt := map[rune]float64{}
	for _, r := range s {
		cnt[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range cnt {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// suspiciousDomain returns a reason when a DNS name looks generated or tunnelled.
func suspiciousDomain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	if len(name) > 80 {
		return "Очень длинное имя (" + fmt.Sprint(len(name)) + " символов) — признак DNS-туннелирования"
	}
	sld, tld := labels[len(labels)-2], labels[len(labels)-1]
	if len(sld) < 10 {
		return ""
	}
	vow := 0
	for _, r := range sld {
		if strings.ContainsRune("aeiouy", r) {
			vow++
		}
	}
	ratio := float64(vow) / float64(len(sld))
	h := entropy(sld)
	switch {
	case h >= 3.4 && ratio < 0.25 && len(sld) >= 12:
		return fmt.Sprintf("Имя «%s» похоже на случайно сгенерированное (энтропия %.1f, мало гласных)", sld, h)
	case susTLD[tld] && h >= 3.0:
		return fmt.Sprintf("Случайно выглядящее имя в зоне .%s, которую часто используют для вредоносных сайтов", tld)
	}
	return ""
}

// ---------------------------------------------------------------- live detections from the process table

func recordLiveIncidents(conns []Conn, metas map[int32]*ProcMeta) {
	idx := make(map[int32]*ProcMeta, len(metas))
	sigs := make(map[int32]string, len(metas))
	for pid, m := range metas {
		idx[pid] = m
		sigs[pid] = m.Sig
	}
	procIndex.Store(&idx)
	pidSigs.Store(&sigs)

	for _, m := range metas {
		if m.Level != "bad" {
			continue
		}
		in := Incident{Key: fmt.Sprintf("proc|%s|%d", strings.ToLower(m.Exe+m.Name), m.Created), Kind: "proc", Severity: "bad",
			Title: "Подозрительный процесс: " + m.Name, Reasons: m.Reasons}
		fillProc(&in, m.PID)
		addIncident(in, &Evidence{T: time.Now().UnixMilli(), Line: fmt.Sprintf("PID %d  %s  %s", m.PID, m.Name, m.Exe)})
	}
	for _, c := range conns {
		if c.Dir == "listen" || c.Scope != "public" || c.Score < 3 {
			continue
		}
		sev := "warn"
		if c.Score >= 4 {
			sev = "bad"
		}
		in := Incident{Key: fmt.Sprintf("conn|%s|%s|%d", strings.ToLower(c.Exe+c.Proc), c.Remote, c.RPort), Kind: "conn", Severity: sev,
			Title: fmt.Sprintf("Подозрительное соединение: %s → %s:%d", c.Proc, c.Remote, c.RPort), Reasons: c.Reasons,
			Remote: c.Remote, Host: c.Host, RPort: uint16(c.RPort), Proto: c.Proto}
		fillProc(&in, c.PID)
		if ad, tun := routeVia(c.Remote); ad != nil {
			in.Via = map[bool]string{true: "tunnel", false: "physical"}[tun]
		}
		addIncident(in, &Evidence{T: time.Now().UnixMilli(), Line: fmt.Sprintf("%s  %s:%d → %s:%d  %s", c.Proto, c.Local, c.LPort, c.Remote, c.RPort, c.Status)})
	}
}

// upsertIncident2 refreshes an incident whose single piece of evidence is rebuilt on every check.
func upsertIncident2(in Incident, ev *Evidence) {
	in.Evidence = []Evidence{*ev}
	upsertIncident(in)
}
