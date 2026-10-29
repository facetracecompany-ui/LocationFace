package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Transfer is "this program sent that much to that address", with whatever can
// honestly be said about the content and a verdict that separates normal
// traffic (a messenger talking to its own servers) from suspicious.

type Transfer struct {
	PID      int32     `json:"pid"`
	Proc     string    `json:"proc"`
	Exe      string    `json:"exe"`
	Cmd      string    `json:"cmd"`
	User     string    `json:"user"`
	Parent   string    `json:"parent"`
	Sig      string    `json:"sig"`
	Signer   string    `json:"signer"`
	SHA256   string    `json:"sha256"`
	Actor    string    `json:"actor"` // browser | vendor | signed | unsigned | unknown
	Remote   string    `json:"remote"`
	Host     string    `json:"host"`
	Ports    []uint16  `json:"ports"`
	Proto    string    `json:"proto"`
	Service  string    `json:"service"`
	Category string    `json:"category"`
	In       uint64    `json:"in"`
	Out      uint64    `json:"out"`
	Pkts     int       `json:"pkts"`
	First    int64     `json:"first"`
	Last     int64     `json:"last"`
	Tunnel   bool      `json:"tunnel"`  // seen on a VPN/tunnel adapter
	Trusted  bool      `json:"trusted"` // the user vouched for this program
	Channel  string    `json:"channel"` // how the data travels
	UA       string    `json:"ua"`
	Reqs     []string  `json:"reqs"`
	UpFiles  []UpFile  `json:"upFiles"`
	Fields   []string  `json:"fields"`
	Files    []FileRef `json:"files"`
	Verdict
}

func transfersSnapshot() []Transfer {
	fl := flowsSnapshot()
	idx := procIndex.Load()
	groups := map[string]*Transfer{}
	var order []string
	for _, f := range fl {
		if f.Scope != "public" || f.Out == 0 {
			continue
		}
		hk := f.Host
		if hk == "" {
			hk = f.Remote
		}
		key := fmt.Sprintf("%d|%s", f.PID, hk)
		t := groups[key]
		if t == nil {
			t = &Transfer{PID: f.PID, Proc: f.Proc, Remote: f.Remote, Host: f.Host, Proto: f.Proto, First: f.First}
			groups[key] = t
			order = append(order, key)
		}
		t.Out += f.Out
		t.In += f.In
		t.Pkts += f.Pkts
		if f.First < t.First {
			t.First = f.First
		}
		if f.Last > t.Last {
			t.Last = f.Last
		}
		t.Ports = append(t.Ports, f.RPort)
		if t.UA == "" {
			t.UA = f.UA
		}
		for _, r := range f.Reqs {
			t.Reqs = addUniq(t.Reqs, r, 12)
		}
		for _, x := range f.Fields {
			t.Fields = addUniq(t.Fields, x, 25)
		}
		for _, u := range f.UpFiles {
			if len(t.UpFiles) < 20 {
				t.UpFiles = append(t.UpFiles, u)
			}
		}
		t.Tunnel = t.Tunnel || f.Tunnel
		if f.TLS {
			t.Channel = "tls"
		} else if t.Channel == "" && (len(f.Reqs) > 0 || len(f.UpFiles) > 0 || f.RPort == 80 || f.RPort == 21 || f.RPort == 25) {
			t.Channel = "plain"
		}
	}

	var out []Transfer
	for _, k := range order {
		t := groups[k]
		var meta *ProcMeta
		if idx != nil {
			meta = (*idx)[t.PID]
		}
		if meta != nil {
			t.Proc, t.Exe, t.Cmd, t.User, t.Parent = meta.Name, meta.Exe, meta.Cmd, meta.User, meta.Parent
			t.Sig, t.Signer, t.SHA256 = meta.Sig, meta.Signer, meta.SHA256
		}
		if t.Proc == "" {
			t.Proc = "неизвестный процесс"
		}
		t.Actor = actorKind(meta)
		t.Trusted = meta != nil && isUserTrusted(meta.Exe)
		svc := serviceFor(t.Host, t.Remote)
		if svc != nil {
			t.Service, t.Category = svc.Name, svc.Category
		}
		if t.Channel == "" {
			t.Channel = "unknown"
			if t.Proto == "UDP" {
				t.Channel = "udp"
			}
		}
		files, foreign := candidateFiles(t.PID, t.Out)
		t.Files = files
		t.Verdict = judge(meta, svc, t.In, t.Out, t.Host != "", foreign)
		sort.Slice(t.Ports, func(i, j int) bool { return t.Ports[i] < t.Ports[j] })
		t.Ports = uniqPorts(t.Ports)
		out = append(out, *t)
	}
	rank := map[string]int{"bad": 0, "warn": 1, "ok": 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Level] != rank[out[j].Level] {
			return rank[out[i].Level] < rank[out[j].Level]
		}
		return out[i].Out > out[j].Out
	})
	if len(out) > 300 {
		out = out[:300]
	}
	return out
}

func uniqPorts(p []uint16) []uint16 {
	var out []uint16
	for i, x := range p {
		if i == 0 || x != p[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func destName(t *Transfer) string {
	d := t.Remote
	if t.Host != "" {
		d = t.Host
	}
	if len(t.Ports) > 0 {
		d += fmt.Sprintf(":%d", t.Ports[0])
	}
	return d
}

var reported = map[string]uint64{}

// transferLoop turns suspicious transfers into incidents, once per doubling of volume.
func transferLoop() {
	for {
		time.Sleep(6 * time.Second)
		for _, t := range transfersSnapshot() {
			if t.Level == "ok" {
				continue
			}
			key := "upload|" + strings.ToLower(t.Exe+t.Proc) + "|" + destName(&t)
			if prev, seen := reported[key]; seen && t.Out < prev*2 {
				continue
			}
			reported[key] = t.Out
			upsertIncident(transferIncident(&t, key))
		}
	}
}

func transferIncident(t *Transfer, key string) Incident {
	dest := destName(t)
	in := Incident{Key: key, Kind: "upload", Severity: t.Level,
		Title:   fmt.Sprintf("%s отправил %s → %s", t.Proc, fmtBytes(t.Out), dest),
		Reasons: append([]string{t.Label}, t.Verdict.Reasons...),
		Remote:  t.Remote, Host: t.Host, Proto: t.Proto}
	if len(t.Ports) > 0 {
		in.RPort = t.Ports[0]
	}
	fillProc(&in, t.PID)
	in.Via = "physical"
	if ad, tun := routeVia(t.Remote); t.Tunnel || (ad != nil && tun) {
		in.Via = "tunnel"
	}
	now := time.Now().UnixMilli()
	ch := map[string]string{"tls": "зашифровано (TLS)", "plain": "открытым текстом", "udp": "UDP", "unknown": "не удалось определить"}[t.Channel]
	ev := []Evidence{{T: now, Line: fmt.Sprintf("Отправлено %s, получено %s за %d с (%d пакетов); канал: %s",
		fmtBytes(t.Out), fmtBytes(t.In), max(1, int((t.Last-t.First)/1000)), t.Pkts, ch)}}
	for _, r := range t.Reqs {
		ev = append(ev, Evidence{T: now, Line: "Запрос: " + r})
	}
	for _, u := range t.UpFiles {
		l := "Файл в запросе: " + u.Name
		if u.Type != "" {
			l += " (" + u.Type + ")"
		}
		ev = append(ev, Evidence{T: now, Line: l})
	}
	for _, x := range t.Fields {
		ev = append(ev, Evidence{T: now, Line: x + " (значение скрыто)"})
	}
	for i, f := range t.Files {
		if i >= 10 {
			break
		}
		l := fmt.Sprintf("Открыт процессом: %s (%s)", f.Path, fmtBytes(uint64(f.Size)))
		if f.Match {
			l += " — размер совпадает с объёмом отправки"
		}
		if f.Sens != "" {
			l += " — ⚠ " + f.Sens
		}
		ev = append(ev, Evidence{T: now, Line: l})
	}
	in.Evidence = ev
	return in
}
