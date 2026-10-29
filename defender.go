package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// A full write-up of what Microsoft Defender found: its own records (threat list,
// detection history, Operational event log) joined with what can be learned about the
// file from the system itself. Every statement says where it comes from.

type NameParts struct {
	Type, TypeText         string
	Platform, PlatformText string
	Family, Variant        string
	Suffix, SuffixText     string
}

type DefResource struct {
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Inner string `json:"inner"`
	URL   string `json:"url"`
	Raw   string `json:"raw"`
	Label string `json:"label"` // what kind of object this is, in words
	Start int64  `json:"start"` // for process resources: when it was started
}

type DefDetection struct {
	Time      int64         `json:"time"`
	Changed   int64         `json:"changed"`
	Remedied  int64         `json:"remedied"`
	Resources []DefResource `json:"resources"`
	Process   string        `json:"process"`
	User      string        `json:"user"`
	Source    string        `json:"source"`
	Origin    string        `json:"origin"`
	DetType   string        `json:"detType"`
	Action    string        `json:"action"`
	Status    string        `json:"status"`
	Execution string        `json:"execution"`
	PreExec   string        `json:"preExec"`
	PostClean string        `json:"postClean"`
	Error     string        `json:"error"`
	Signature string        `json:"signature"`
	Engine    string        `json:"engine"`
	FromEvent bool          `json:"fromEvent"`
}

type DefFinding struct {
	Text  string `json:"text"`
	Basis string `json:"basis"` // defender | system | inference
}

type DefTime struct {
	T      int64  `json:"t"`
	Source string `json:"source"`
	Text   string `json:"text"`
}

type RunTrace struct {
	Source string `json:"source"`
	Last   int64  `json:"last"`
	First  int64  `json:"first"`
	Count  int    `json:"count"`
	Note   string `json:"note"`
}

type Sibling struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Created int64  `json:"created"`
}

type FileFacts struct {
	Path     string     `json:"path"`
	Exists   bool       `json:"exists"`
	Size     int64      `json:"size"`
	Created  int64      `json:"created"`
	Modified int64      `json:"modified"`
	Accessed int64      `json:"accessed"`
	Attrs    []string   `json:"attrs"`
	SHA256   string     `json:"sha256"`
	Sig      string     `json:"sig"`
	Signer   string     `json:"signer"`
	Zone     string     `json:"zone"`
	HostURL  string     `json:"hostUrl"`
	Referrer string     `json:"referrer"`
	Runs     []RunTrace `json:"runs"`
	Running  []string   `json:"running"`
	Conns    []string   `json:"conns"`
	Autoruns []string   `json:"autoruns"`
	Related  []string   `json:"related"` // our own earlier findings about this file
	Siblings []Sibling  `json:"siblings"`
}

type DefThreat struct {
	Name       string         `json:"name"`
	ID         string         `json:"id"`
	Severity   string         `json:"severity"`
	Category   string         `json:"category"`
	Active     bool           `json:"active"`
	Executed   string         `json:"executed"` // yes | no | unknown
	First      int64          `json:"first"`
	Last       int64          `json:"last"`
	Parts      NameParts      `json:"parts"`
	Detections []DefDetection `json:"detections"`
	Files      []FileFacts    `json:"files"`
	Timeline   []DefTime      `json:"timeline"`
	Context    []DefTime      `json:"context"`
	Why        []DefFinding   `json:"why"`
	Advice     []string       `json:"advice"`
	InfoURL    string         `json:"infoUrl"`
	Text       string         `json:"text"`
}

// ---------------------------------------------------------------- Defender data

type defRaw struct {
	threats, dets, events []map[string]any
	at                    time.Time
}

var (
	defMu    sync.Mutex
	defCache *defRaw
)

const defScript = `
$thr=@(Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ThreatID=[string]$_.ThreatID;ThreatName=$_.ThreatName;SeverityID=$_.SeverityID;CategoryID=$_.CategoryID;IsActive=$_.IsActive;DidThreatExecute=$_.DidThreatExecute;Resources=@($_.Resources)} })
$det=@(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ThreatID=[string]$_.ThreatID;ProcessName=$_.ProcessName;Resources=@($_.Resources);InitialDetectionTime=$_.InitialDetectionTime.ToUniversalTime().ToString('o');LastThreatStatusChangeTime=$_.LastThreatStatusChangeTime.ToUniversalTime().ToString('o');RemediationTime=$_.RemediationTime.ToUniversalTime().ToString('o');ActionSuccess=$_.ActionSuccess;CleaningActionID=$_.CleaningActionID;CurrentThreatExecutionStatusID=$_.CurrentThreatExecutionStatusID;DetectionSourceTypeID=$_.DetectionSourceTypeID;DomainUser=$_.DomainUser;ThreatStatusID=$_.ThreatStatusID;ThreatStatusErrorCode=$_.ThreatStatusErrorCode;AMProductVersion=$_.AMProductVersion} })
$ev=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1006,1007,1008,1009,1010,1011,1013,1015,1116,1117,1118,1119,1121,1122,1123,1124,1125,1126,5007;StartTime=(Get-Date).AddDays(-90)} -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object { $h=@{}; try{ foreach($d in ([xml]$_.ToXml()).Event.EventData.Data){ $h[[string]$d.Name]=[string]$d.'#text' } }catch{}; [pscustomobject]@{Id=$_.Id;Time=$_.TimeCreated.ToUniversalTime().ToString('o');Data=$h;Text=(($_.Message -split "` + "`n" + `") | Select-Object -First 2) -join ' '} })
[pscustomobject]@{Threats=$thr;Detections=$det;Events=$ev} | ConvertTo-Json -Compress -Depth 6`

func defenderRaw() *defRaw {
	defMu.Lock()
	defer defMu.Unlock()
	if defCache != nil && time.Since(defCache.at) < 45*time.Second {
		return defCache
	}
	r := &defRaw{at: time.Now()}
	out, _ := runPS(defScript, 90*time.Second)
	if root := psRoot(out); root != nil {
		r.threats, r.dets, r.events = listOf(root["Threats"]), listOf(root["Detections"]), listOf(root["Events"])
	}
	defCache = r
	return r
}

func listOf(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		var out []map[string]any
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{x}
	}
	return nil
}

func strList(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s := str(e); s != "" {
				out = append(out, s)
			}
		}
	case string:
		out = []string{x}
	}
	return out
}

func tms(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 {
		return 0
	}
	return t.UnixMilli()
}

func dataOf(e map[string]any) map[string]string {
	out := map[string]string{}
	if m, ok := e["Data"].(map[string]any); ok {
		for k, v := range m {
			out[k] = str(v)
		}
	}
	return out
}

// parseResource understands Defender's "kind:_payload" notation.
func parseResource(raw string) DefResource {
	r := parseResourceRaw(raw)
	r.describe()
	return r
}

func parseResourceRaw(raw string) DefResource {
	r := DefResource{Raw: raw}
	kind, payload, ok := strings.Cut(raw, ":_")
	if !ok {
		r.Kind, r.Path = "other", raw
		return r
	}
	r.Kind = kind
	switch kind {
	case "file", "containerfile", "webfile", "folder":
		parts := strings.Split(payload, "|")
		r.Path = parts[0]
		if kind == "webfile" && len(parts) > 1 {
			r.URL = parts[1]
		}
		if p, inner, ok := strings.Cut(r.Path, "->"); ok {
			r.Path, r.Inner = p, inner
		}
	default:
		r.Path = payload
	}
	return r
}

func (r *DefResource) describe() {
	switch r.Kind {
	case "file":
		r.Label = "файл"
	case "containerfile":
		r.Label = "архив или контейнер"
	case "webfile":
		r.Label = "файл, скачанный из интернета"
	case "folder":
		r.Label = "папка"
	case "startup":
		r.Label = "запись автозагрузки (угроза пыталась закрепиться)"
	case "regkey", "regvalue":
		r.Label = "параметр реестра"
	case "behavior":
		r.Label = "поведение"
	case "process":
		r.Label = "запущенный процесс"
		var pid int
		var ft int64
		if _, err := fmt.Sscanf(r.Path, "pid:%d,ProcessStart:%d", &pid, &ft); err == nil {
			r.Start = ft/10000 - 11644473600000
			r.Path = fmt.Sprintf("PID %d, запущен %s", pid, time.UnixMilli(r.Start).Format("02.01.2006 15:04:05"))
		}
	default:
		r.Label = r.Kind
	}
}

var (
	severityTxt = map[string]string{"0": "Неизвестная", "1": "Низкая", "2": "Средняя", "4": "Высокая", "5": "Критическая"}
	categoryTxt = map[string]string{"1": "Рекламное ПО", "2": "Шпионское ПО", "3": "Вор паролей", "4": "Троян-загрузчик", "5": "Червь", "6": "Бэкдор",
		"7": "Троян удалённого доступа", "8": "Троян", "27": "Потенциально нежелательное ПО", "30": "Эксплойт", "37": "Троян-дроппер", "42": "Вирус", "46": "Поведенческое", "50": "Шифровальщик"}
	statusTxt = map[string]string{"0": "неизвестно", "1": "обнаружена", "2": "вылечена", "3": "помещена в карантин", "4": "удалена", "5": "разрешена пользователем",
		"6": "заблокирована", "102": "не удалось поместить в карантин", "103": "не удалось удалить", "104": "не удалось разрешить", "105": "действие отменено", "107": "не удалось заблокировать"}
	actionTxt = map[string]string{"1": "лечение", "2": "карантин", "3": "удаление", "6": "разрешено", "8": "решение пользователя", "9": "действий не требуется", "10": "блокировка"}
	sourceTxt = map[string]string{"0": "неизвестно", "1": "пользователь", "2": "система", "3": "защита в реальном времени", "4": "проверка загруженных файлов и вложений", "5": "защита сети", "6": "AMSI (проверка скриптов)", "7": "раннее обнаружение при загрузке"}
	execTxt   = map[string]string{"0": "неизвестно", "1": "запуск заблокирован", "2": "запуск разрешён", "3": "выполнялась", "4": "не выполнялась"}
)

var typeDescr = map[string]string{
	"Trojan":           "троян: программа, которая выдаёт себя за полезную или нейтральную, но выполняет скрытые вредные действия",
	"Backdoor":         "бэкдор: даёт злоумышленнику удалённый доступ к компьютеру",
	"TrojanDownloader": "загрузчик: скачивает и запускает другие вредоносные программы",
	"TrojanDropper":    "дроппер: сам распаковывает и устанавливает другие вредоносные файлы",
	"TrojanSpy":        "шпион: собирает и отправляет данные",
	"PWS":              "вор паролей",
	"Ransom":           "шифровальщик-вымогатель",
	"Worm":             "червь: распространяется сам, по сети или через носители",
	"Virus":            "вирус: заражает другие файлы",
	"HackTool":         "инструмент взлома: сам по себе не вирус, но используется для атак и обхода защиты (в том числе в «кряках»)",
	"VirTool":          "инструмент для упаковки и маскировки вредоносных программ",
	"Behavior":         "обнаружение по поведению (что программа делает, а не по тому, как выглядит файл)",
	"PUA":              "потенциально нежелательное ПО: не вирус, но навязчивое или рискованное",
	"Adware":           "рекламное ПО",
	"Exploit":          "эксплойт: использует уязвимость",
	"Program":          "программа сомнительного назначения",
	"Spyware":          "шпионское ПО",
}

var platformDescr = map[string]string{
	"Win32": "обычная 32-битная программа Windows (.exe, .dll)", "Win64": "64-битная программа Windows", "MSIL": "программа на .NET",
	"Script": "скрипт", "JS": "JavaScript", "PowerShell": "скрипт PowerShell", "BAT": "пакетный файл (.bat/.cmd)", "VBS": "скрипт VBScript",
	"HTML": "HTML-страница", "Python": "скрипт Python", "Java": "программа на Java", "AndroidOS": "программа Android", "Linux": "программа Linux",
	"Win32/Win64": "программа Windows",
}

func parseThreatName(name string) NameParts {
	p := NameParts{}
	rest := name
	if i := strings.Index(rest, ":"); i >= 0 {
		p.Type, rest = rest[:i], rest[i+1:]
	}
	if i := strings.Index(rest, "!"); i >= 0 {
		p.Suffix, rest = rest[i+1:], rest[:i]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		p.Platform, rest = rest[:i], rest[i+1:]
	}
	p.Family = rest
	if i := strings.LastIndex(rest, "."); i >= 0 {
		p.Family, p.Variant = rest[:i], rest[i+1:]
	}
	base := p.Type
	if i := strings.Index(base, "/"); i >= 0 {
		base = base[:i]
	}
	p.TypeText = typeDescr[base]
	p.PlatformText = platformDescr[p.Platform]
	switch strings.ToLower(p.Suffix) {
	case "":
	case "ml":
		p.SuffixText = "нейросетевой (машинное обучение) анализ: решение принято по общим признакам файла, а не по точной сигнатуре"
	case "rfn":
		p.SuffixText = "внутренняя метка Microsoft. Официального описания Microsoft не публикует, поэтому по ней нельзя судить, ложное это срабатывание или точное — смотрите «Тип обнаружения» и факты ниже"
	case "dha":
		p.SuffixText = "метка Microsoft, описание которой официально не опубликовано"
	default:
		p.SuffixText = "внутренняя метка Microsoft, описание которой официально не опубликовано"
	}
	return p
}

// ---------------------------------------------------------------- file facts

func ftToMs(ft syscall.Filetime) int64 {
	return (int64(ft.HighDateTime)<<32|int64(ft.LowDateTime))/10000 - 11644473600000
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

func fileTimeBytes(b []byte, off int) int64 {
	if len(b) < off+8 {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[off+i])
	}
	if v == 0 {
		return 0
	}
	ms := int64(v/10000) - 11644473600000
	if ms < 946684800000 {
		return 0
	}
	return ms
}

// runTraces reads the places where Windows remembers that a program was started.
func runTraces(path string) []RunTrace {
	var out []RunTrace
	base := strings.ToLower(filepath.Base(path))
	low := strings.ToLower(path)

	// Prefetch: one file per program, created at first start, touched at the latest
	if ents, err := os.ReadDir(os.Getenv("SystemRoot") + `\Prefetch`); err == nil {
		for _, e := range ents {
			n := strings.ToLower(e.Name())
			if i := strings.LastIndex(n, "-"); i > 0 && n[:i] == base && strings.HasSuffix(n, ".pf") {
				if info, err := e.Info(); err == nil {
					rt := RunTrace{Source: "Prefetch (журнал запусков Windows)", Last: info.ModTime().UnixMilli(), Note: "по файлу " + e.Name()}
					if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
						rt.First = ftToMs(d.CreationTime)
					}
					out = append(out, rt)
				}
			}
		}
	}

	// UserAssist: programs started from the shell, with a run counter
	if ua, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, registry.ENUMERATE_SUB_KEYS); err == nil {
		guids, _ := ua.ReadSubKeyNames(-1)
		ua.Close()
		for _, g := range guids {
			k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`+g+`\Count`, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			names, _ := k.ReadValueNames(-1)
			for _, n := range names {
				dec := strings.ToLower(rot13(n))
				if !strings.HasSuffix(dec, base) {
					continue
				}
				dir := strings.ToLower(filepath.Dir(low))
				pathKnown := strings.Contains(dec, dir) || strings.HasPrefix(dec, "{") // real path, or a Windows known-folder code
				if !pathKnown && genericExe[base] {
					continue // "setup.exe" in some other folder is a different program
				}
				b, _, err := k.GetBinaryValue(n)
				if err != nil || len(b) < 68 {
					continue
				}
				cnt := int(uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24)
				note := "запуск из проводника или меню «Пуск»"
				if !pathKnown {
					note += "; совпало только имя файла, путь другой"
				}
				out = append(out, RunTrace{Source: "UserAssist (запуски из проводника)", Count: cnt, Last: fileTimeBytes(b, 60), Note: note})
			}
			k.Close()
		}
	}

	// BAM: the last time the system saw the program run, per user
	for _, root := range []string{`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, `SYSTEM\CurrentControlSet\Services\bam\UserSettings`} {
		rk, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		sids, _ := rk.ReadSubKeyNames(-1)
		rk.Close()
		for _, sid := range sids {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+sid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			names, _ := k.ReadValueNames(-1)
			tail := strings.ToLower(path)
			if len(tail) > 2 && tail[1] == ':' {
				tail = tail[2:]
			}
			for _, n := range names {
				if strings.HasSuffix(strings.ToLower(n), tail) {
					if b, _, err := k.GetBinaryValue(n); err == nil {
						if t := fileTimeBytes(b, 0); t > 0 {
							out = append(out, RunTrace{Source: "BAM (монитор фоновой активности Windows)", Last: t, Note: "последний запуск"})
						}
					}
				}
			}
			k.Close()
		}
	}
	return out
}

var genericExe = map[string]bool{"setup.exe": true, "install.exe": true, "installer.exe": true, "update.exe": true, "launcher.exe": true,
	"loader.exe": true, "run.exe": true, "main.exe": true, "app.exe": true, "start.exe": true, "patch.exe": true}

func collectFacts(path string) FileFacts {
	f := FileFacts{Path: path}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		f.Exists, f.Size, f.Modified = true, st.Size(), st.ModTime().UnixMilli()
		if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
			f.Created, f.Accessed = ftToMs(d.CreationTime), ftToMs(d.LastAccessTime)
			for _, a := range []struct {
				m uint32
				n string
			}{{syscall.FILE_ATTRIBUTE_HIDDEN, "скрытый"}, {syscall.FILE_ATTRIBUTE_SYSTEM, "системный"}, {syscall.FILE_ATTRIBUTE_READONLY, "только чтение"}} {
				if d.FileAttributes&a.m != 0 {
					f.Attrs = append(f.Attrs, a.n)
				}
			}
		}
		f.SHA256 = fileSHA256(path)
		s := getSig(path)
		f.Sig, f.Signer = s.Status, s.Signer
		f.Zone, f.HostURL, f.Referrer = parseZone(path)
	}
	f.Runs = runTraces(path)
	sort.Slice(f.Runs, func(i, j int) bool { return f.Runs[i].Last > f.Runs[j].Last })

	for _, p := range procsSnapshot() {
		if strings.EqualFold(p.Exe, path) {
			f.Running = append(f.Running, fmt.Sprintf("%s (PID %d, запущен %s)", p.Name, p.PID, time.UnixMilli(p.Created).Format("02.01.2006 15:04:05")))
		}
	}
	for _, c := range connsSnapshot() {
		if strings.EqualFold(c.Exe, path) && c.Dir != "listen" && c.Scope == "public" {
			h := c.Remote
			if c.Host != "" {
				h = c.Host + " (" + c.Remote + ")"
			}
			f.Conns = append(f.Conns, fmt.Sprintf("%s → %s:%d", c.Proto, h, c.RPort))
		}
	}
	for _, a := range autorunsScan() {
		if strings.EqualFold(a.Exe, path) {
			f.Autoruns = append(f.Autoruns, a.Where+": "+a.Name)
		}
	}
	for _, in := range incidentsSnapshot() {
		if strings.EqualFold(in.Exe, path) && in.Kind != "defender" {
			f.Related = append(f.Related, fmt.Sprintf("%s — %s", time.UnixMilli(in.Last).Format("02.01 15:04"), in.Title))
		}
	}

	// files that appeared next to it around the same time: what it unpacked or dropped
	anchor := f.Created
	if anchor == 0 {
		anchor = f.Modified
	}
	if anchor > 0 {
		if ents, err := os.ReadDir(filepath.Dir(path)); err == nil {
			for _, e := range ents {
				if e.IsDir() || strings.EqualFold(filepath.Join(filepath.Dir(path), e.Name()), path) {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				c := info.ModTime().UnixMilli()
				if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
					c = ftToMs(d.CreationTime)
				}
				if c >= anchor-10*60000 && c <= anchor+10*60000 && len(f.Siblings) < 15 {
					f.Siblings = append(f.Siblings, Sibling{Name: e.Name(), Size: info.Size(), Created: c})
				}
			}
		}
	}
	return f
}

// ---------------------------------------------------------------- assembling the report

func defenderReports(name string) []DefThreat {
	raw := defenderRaw()
	byID := map[string]*DefThreat{}
	var order []string
	get := func(id, nm string) *DefThreat {
		key := id
		if key == "" {
			key = nm
		}
		t := byID[key]
		if t == nil {
			t = &DefThreat{ID: id, Name: nm, Executed: "unknown"}
			byID[key] = t
			order = append(order, key)
		}
		if t.Name == "" {
			t.Name = nm
		}
		return t
	}
	idName := map[string]string{}
	for _, th := range raw.threats {
		id, nm := str(th["ThreatID"]), str(th["ThreatName"])
		idName[id] = nm
		t := get(id, nm)
		t.Severity, t.Category = severityTxt[str(th["SeverityID"])], categoryTxt[str(th["CategoryID"])]
		t.Active = th["IsActive"] == true
		if v, ok := th["DidThreatExecute"].(bool); ok {
			t.Executed = map[bool]string{true: "yes", false: "no"}[v]
		}
	}
	for _, e := range raw.events {
		d := dataOf(e)
		if id := d["Threat ID"]; id != "" && d["Threat Name"] != "" {
			idName[id] = d["Threat Name"]
		}
	}
	used := map[int]bool{}
	for _, d := range raw.dets {
		id := str(d["ThreatID"])
		nm := idName[id]
		if nm == "" {
			continue
		}
		t := get(id, nm)
		det := DefDetection{Time: tms(str(d["InitialDetectionTime"])), Changed: tms(str(d["LastThreatStatusChangeTime"])), Remedied: tms(str(d["RemediationTime"])),
			Process: strings.TrimSpace(strings.Replace(str(d["ProcessName"]), "Unknown", "", 1)), User: str(d["DomainUser"]), Signature: str(d["AMProductVersion"]),
			Source: sourceTxt[str(d["DetectionSourceTypeID"])], Status: statusTxt[str(d["ThreatStatusID"])], Execution: execTxt[str(d["CurrentThreatExecutionStatusID"])]}
		det.Action = actionTxt[str(d["CleaningActionID"])]
		if ok, has := d["ActionSuccess"].(bool); has && !ok {
			det.Error = "действие не удалось"
		}
		for _, r := range strList(d["Resources"]) {
			det.Resources = append(det.Resources, parseResource(r))
		}
		// the event log has the richest description of the same detection
		for i, e := range raw.events {
			ed := dataOf(e)
			if str(e["Id"]) != "1116" || ed["Threat ID"] != id || used[i] {
				continue
			}
			if abs64(tms(str(e["Time"]))-det.Time) > 10*60000 && det.Time != 0 {
				continue
			}
			used[i] = true
			applyEvent(&det, t, e, ed)
			break
		}
		t.Detections = append(t.Detections, det)
	}
	// detections that exist only in the event log (history already cleared)
	for i, e := range raw.events {
		ed := dataOf(e)
		if str(e["Id"]) != "1116" || used[i] || ed["Threat ID"] == "" || ed["Threat Name"] == "" {
			continue
		}
		t := get(ed["Threat ID"], ed["Threat Name"])
		det := DefDetection{Time: tms(str(e["Time"]))}
		applyEvent(&det, t, e, ed)
		t.Detections = append(t.Detections, det)
	}

	var out []DefThreat
	for _, k := range order {
		t := byID[k]
		if name != "" && t.Name != name {
			continue
		}
		finishThreat(t, raw)
		out = append(out, *t)
	}
	return out
}

// applyEvent copies the fields of a Defender "malware detected" event (1116) into a detection.
func applyEvent(det *DefDetection, t *DefThreat, e map[string]any, ed map[string]string) {
	det.FromEvent = true
	ep := ed["Process Name"]
	if strings.EqualFold(ep, "unknown") {
		ep = ""
	}
	det.Process = firstNonEmpty(ep, det.Process)
	if strings.EqualFold(det.Process, "unknown") {
		det.Process = ""
	}
	det.User = firstNonEmpty(ed["Detection User"], det.User)
	det.Source = strings.TrimRight(firstNonEmpty(ed["Source Name"], det.Source), ": ")
	det.Origin, det.DetType = ed["Origin Name"], ed["Type Name"]
	det.Action = firstNonEmpty(ed["Action Name"], det.Action)
	det.Execution = firstNonEmpty(ed["Execution Name"], det.Execution)
	det.PreExec, det.PostClean = ed["Pre Execution Status"], ed["Post Clean Status"]
	det.Error = firstNonEmpty(ed["Error Description"], det.Error)
	det.Signature, det.Engine = firstNonEmpty(ed["Security intelligence Version"], det.Signature), ed["Engine Version"]
	t.Severity = firstNonEmpty(ed["Severity Name"], t.Severity)
	t.Category = firstNonEmpty(ed["Category Name"], t.Category)
	if len(det.Resources) == 0 {
		for _, r := range strings.Split(ed["Path"], ";") {
			if r = strings.TrimSpace(r); r != "" {
				det.Resources = append(det.Resources, parseResource(r))
			}
		}
	}
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func finishThreat(t *DefThreat, raw *defRaw) {
	t.Parts = parseThreatName(t.Name)
	t.InfoURL = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=" + url.QueryEscape(t.Name)
	sort.Slice(t.Detections, func(i, j int) bool { return t.Detections[i].Time < t.Detections[j].Time })
	if n := len(t.Detections); n > 0 {
		t.First, t.Last = t.Detections[0].Time, t.Detections[n-1].Time
	}

	seen := map[string]bool{}
	for _, d := range t.Detections {
		for _, r := range d.Resources {
			if (r.Kind == "file" || r.Kind == "containerfile" || r.Kind == "webfile") && r.Path != "" && !seen[strings.ToLower(r.Path)] {
				seen[strings.ToLower(r.Path)] = true
				t.Files = append(t.Files, collectFacts(r.Path))
			}
		}
	}
	// no detection record: fall back to the current threat's resources
	if len(t.Files) == 0 {
		for _, th := range raw.threats {
			if str(th["ThreatName"]) != t.Name {
				continue
			}
			for _, rs := range strList(th["Resources"]) {
				r := parseResource(rs)
				if (r.Kind == "file" || r.Kind == "containerfile" || r.Kind == "webfile") && r.Path != "" && !seen[strings.ToLower(r.Path)] {
					seen[strings.ToLower(r.Path)] = true
					t.Files = append(t.Files, collectFacts(r.Path))
				}
			}
		}
	}

	// Defender's own log within a few minutes of each detection (not the whole span between them)
	seenEv := map[string]bool{}
	for _, d := range t.Detections {
		if d.Time == 0 {
			continue
		}
		for _, e := range raw.events {
			et := tms(str(e["Time"]))
			key := str(e["Id"]) + "|" + str(e["Time"])
			if et < d.Time-3*60000 || et > d.Time+3*60000 || seenEv[key] || str(e["Id"]) == "5007" {
				continue
			}
			seenEv[key] = true
			ed := dataOf(e)
			txt := str(e["Text"])
			if ed["Threat Name"] != "" {
				txt = ed["Threat Name"] + " — " + firstNonEmpty(ed["Action Name"], ed["Status Description"], txt)
			}
			t.Context = append(t.Context, DefTime{T: et, Source: "Журнал Defender, событие " + str(e["Id"]), Text: shorten(txt, 220)})
		}
	}
	if t.First > 0 { // protection settings changed shortly before: exclusions are a classic trick
		for _, e := range raw.events {
			if str(e["Id"]) == "5007" {
				if et := tms(str(e["Time"])); et >= t.First-24*3600000 && et <= t.First+3600000 {
					t.Context = append(t.Context, DefTime{T: et, Source: "Журнал Defender, событие 5007", Text: "изменены настройки защиты: " + shorten(str(e["Text"]), 200)})
				}
			}
		}
	}
	sort.Slice(t.Context, func(i, j int) bool { return t.Context[i].T < t.Context[j].T })
	if len(t.Context) > 120 {
		t.Context = t.Context[:120]
	}
	buildTimeline(t)
	buildWhy(t)
	t.Text = threatText(t)
}

// buildTimeline joins Defender's records and the system's run traces into one story.
func buildTimeline(t *DefThreat) {
	add := func(ms int64, src, text string) {
		if ms > 0 {
			t.Timeline = append(t.Timeline, DefTime{T: ms, Source: src, Text: text})
		}
	}
	for _, d := range t.Detections {
		var names []string
		for _, r := range d.Resources {
			if strings.Contains(r.Kind, "file") || r.Kind == "startup" {
				n := filepath.Base(r.Path)
				if r.Kind == "startup" {
					n = "автозагрузка: " + n
				}
				names = append(names, n)
			}
			if r.Kind == "process" && r.Start > 0 {
				add(r.Start, "Защитник", "Запущен процесс, связанный с угрозой: "+r.Path)
			}
		}
		line := "Обнаружено: " + strings.Join(dedupe(names), ", ")
		if d.Process != "" {
			line += " (в работе процесса " + d.Process + ")"
		}
		if d.Execution != "" {
			line += "; выполнение: " + strings.ToLower(d.Execution)
		}
		if d.Status != "" {
			line += "; итог: " + d.Status
		}
		add(d.Time, "Защитник", line)
		if d.Remedied > 0 && d.Status != "" && abs64(d.Remedied-d.Time) > 60000 {
			add(d.Remedied, "Защитник", "Принято действие: "+d.Status)
		}
	}
	for _, f := range t.Files {
		for _, r := range f.Runs {
			if r.First > 0 {
				add(r.First, "Windows", filepath.Base(f.Path)+": первый запуск по данным "+r.Source)
			}
			add(r.Last, "Windows", filepath.Base(f.Path)+": запуск зафиксирован — "+r.Source)
		}
		add(f.Created, "Файл", filepath.Base(f.Path)+": файл создан на диске")
	}
	sort.SliceStable(t.Timeline, func(i, j int) bool { return t.Timeline[i].T < t.Timeline[j].T })
	seen := map[string]bool{}
	uniq := t.Timeline[:0]
	for _, e := range t.Timeline {
		k := fmt.Sprintf("%d|%s", e.T, e.Text)
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, e)
		}
	}
	t.Timeline = uniq
}

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

var crackWords = []string{"crack", "keygen", "patch", "activator", "kmspico", "amtlib", "xforce", "x-force", "repack", "warez", "nulled", "cheat", "injector", "trainer"}

func buildWhy(t *DefThreat) {
	add := func(basis, text string) { t.Why = append(t.Why, DefFinding{Text: text, Basis: basis}) }
	p := t.Parts
	if p.Type != "" {
		s := "Тип «" + p.Type + "»"
		if p.TypeText != "" {
			s += " — " + p.TypeText
		}
		add("defender", s+".")
	}
	if p.Platform != "" {
		s := "Платформа «" + p.Platform + "»"
		if p.PlatformText != "" {
			s += " — " + p.PlatformText
		}
		add("defender", s+".")
	}
	if p.Family != "" {
		add("defender", "Семейство «"+p.Family+"» — внутреннее название Microsoft. Подробного описания, что именно делает это семейство, Microsoft для таких обнаружений не публикует (кнопка «Описание на сайте Microsoft» открывает официальную страницу, если запись там есть).")
	}
	if p.SuffixText != "" {
		add("defender", "Суффикс «!"+p.Suffix+"» — "+p.SuffixText+".")
	}
	distinct := func(get func(DefDetection) string) []string {
		seen := map[string]bool{}
		var out []string
		for _, d := range t.Detections {
			if v := get(d); v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}
	if v := distinct(func(d DefDetection) string { return d.Source }); len(v) > 0 {
		add("defender", "Как поймали: "+strings.Join(v, "; ")+".")
	}
	if v := distinct(func(d DefDetection) string { return d.DetType }); len(v) > 0 {
		add("defender", "Тип обнаружения по классификации Defender: «"+strings.Join(v, "», «")+"».")
	}
	if v := distinct(func(d DefDetection) string { return d.Origin }); len(v) > 0 {
		add("defender", "Происхождение файла по оценке Defender: "+strings.Join(v, "; ")+".")
	}
	if v := distinct(func(d DefDetection) string { return d.Process }); len(v) > 0 {
		add("defender", "Файлы были замечены в работе процессов: "+strings.Join(v, "; ")+".")
	}
	if v := distinct(func(d DefDetection) string { return firstNonEmpty(d.Execution, d.PreExec) }); len(v) > 0 {
		add("defender", "Состояние выполнения при обнаружениях: "+strings.Join(v, "; ")+".")
	}
	if t.Executed == "yes" {
		add("defender", "Defender отмечает, что угроза успела выполниться.")
	} else if t.Executed == "no" {
		add("defender", "Defender отмечает, что угроза не выполнялась.")
	}

	for _, f := range t.Files {
		name := filepath.Base(f.Path)
		if !f.Exists {
			add("system", name+": файла больше нет на диске — Defender уже поместил его в карантин или удалил (или вы его удалили).")
		}
		if f.Zone == "Интернет" {
			add("system", name+": файл получен из интернета"+map[bool]string{true: " с адреса " + f.HostURL, false: ""}[f.HostURL != ""]+".")
		}
		if f.Exists && (f.Sig == "unsigned" || f.Sig == "untrusted") {
			add("system", name+": нет действительной цифровой подписи. У вредоносных программ подписи обычно нет, но и у многих мелких обычных программ тоже — само по себе это не доказательство.")
		}
		if f.Sig == "tampered" {
			add("system", name+": подпись нарушена — файл изменили после подписания.")
		}
		if len(f.Runs) > 0 {
			add("system", fmt.Sprintf("%s: Windows помнит запуски этого файла (последний — %s).", name, time.UnixMilli(f.Runs[0].Last).Format("02.01.2006 15:04")))
		} else {
			add("system", name+": следов запуска в Prefetch, UserAssist и BAM не найдено — вероятно, файл не запускали (или следы очищены / нет прав администратора).")
		}
		if len(f.Siblings) >= 3 {
			add("inference", fmt.Sprintf("%s: рядом за те же минуты появилось %d других файлов. Так выглядит распаковка архива или работа программы-дроппера; для установщика обычной программы тоже нормально.", name, len(f.Siblings)))
		}
		if len(f.Autoruns) > 0 {
			add("inference", name+": файл прописан в автозагрузке ("+strings.Join(f.Autoruns, "; ")+") — закрепился в системе.")
		}
		if len(f.Conns) > 0 {
			add("inference", name+": у процесса есть соединения с интернетом: "+strings.Join(f.Conns, "; ")+".")
		}
		low := strings.ToLower(f.Path)
		var hits []string
		for _, w := range crackWords {
			if strings.Contains(low, w) {
				hits = append(hits, w)
			}
		}
		if len(hits) > 0 {
			add("inference", fmt.Sprintf("%s: в имени или пути есть слова «%s» — так обычно называют «кряки», активаторы и читы. Именно такие файлы Defender часто метит общими обнаружениями — и среди них нередко реальные трояны.", name, strings.Join(hits, "», «")))
		}
	}
	t.Advice = nil
	adv := func(x string) { t.Advice = append(t.Advice, x) }
	anyExists, startup, procs := false, false, false
	for _, f := range t.Files {
		anyExists = anyExists || f.Exists
	}
	for _, d := range t.Detections {
		for _, r := range d.Resources {
			startup = startup || r.Kind == "startup"
			procs = procs || r.Kind == "process"
		}
	}
	if t.Executed == "yes" || procs {
		adv("Защитник сообщает, что эта угроза успела выполниться. Считайте, что в момент запуска она могла получить доступ к паролям, сессиям браузера и файлам. С другого устройства смените пароли (почта, банки, Steam, Telegram, Discord) и завершите все чужие сессии.")
		adv("Запустите полную проверку: «Безопасность Windows → Защита от вирусов и угроз → Параметры проверки → Проверка автономным Microsoft Defender» — она находит то, что прячется от обычной проверки.")
	}
	if startup {
		adv("Угроза пыталась прописаться в автозагрузку. Проверьте вкладку «Автозагрузка» и планировщик заданий: удалите всё незнакомое.")
	}
	if anyExists {
		adv("Файл ещё на диске: не запускайте его. Нажмите «Проверить Защитником ещё раз» и проверьте хеш на VirusTotal.")
	} else {
		adv("Файлы уже в карантине или удалены Защитником: восстанавливать их не нужно. Хеша для VirusTotal нет, потому что файла больше нет на диске.")
	}
	adv("Если угроза связана со взломанным ПО, кряками или читами — не устанавливайте это снова: именно такие установщики приносят вредоносный код вместе с программой.")
	adv("Журнал и действия над угрозой: «Безопасность Windows → Защита от вирусов и угроз → Журнал защиты» (кнопка ниже открывает его).")
}

func psRoot(out string) map[string]any {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) != nil {
		return nil
	}
	return m
}

// defenderBrief gives the short facts needed for the incident card without touching files.
func defenderBrief() map[string]struct {
	Paths []string
	First int64
	Proc  string
} {
	raw := defenderRaw()
	out := map[string]struct {
		Paths []string
		First int64
		Proc  string
	}{}
	idName := map[string]string{}
	for _, th := range raw.threats {
		idName[str(th["ThreatID"])] = str(th["ThreatName"])
	}
	for _, e := range raw.events {
		if d := dataOf(e); d["Threat ID"] != "" && d["Threat Name"] != "" {
			idName[d["Threat ID"]] = d["Threat Name"]
		}
	}
	for _, d := range raw.dets {
		nm := idName[str(d["ThreatID"])]
		if nm == "" {
			continue
		}
		b := out[nm]
		for _, rs := range strList(d["Resources"]) {
			if r := parseResource(rs); r.Path != "" && strings.Contains(r.Kind, "file") {
				b.Paths = append(b.Paths, r.Path)
			}
		}
		if t := tms(str(d["InitialDetectionTime"])); b.First == 0 || (t > 0 && t < b.First) {
			b.First = t
		}
		b.Proc = firstNonEmpty(b.Proc, str(d["ProcessName"]))
		out[nm] = b
	}
	return out
}

func mpCmdRun() string {
	m, _ := filepath.Glob(os.Getenv("ProgramData") + `\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe`)
	if len(m) > 0 {
		sort.Strings(m)
		return m[len(m)-1]
	}
	p := os.Getenv("ProgramFiles") + `\Windows Defender\MpCmdRun.exe`
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// scanFile asks Defender to check one file again; nothing is removed.
func scanFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return "", fmt.Errorf("файл не найден (возможно, уже в карантине)")
	}
	exe := mpCmdRun()
	if exe == "" {
		return "", fmt.Errorf("не найден MpCmdRun.exe — Защитник Windows не установлен или заменён другим антивирусом")
	}
	cmd := exec.Command(exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	type res struct {
		out  []byte
		code int
	}
	ch := make(chan res, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		ch <- res{out, code}
	}()
	select {
	case r := <-ch:
		tail := shorten(strings.TrimSpace(string(r.out)), 300)
		switch r.code {
		case 0:
			return "Защитник проверил файл заново и угроз не нашёл. Возможно, это было ложное срабатывание — но проверьте и на VirusTotal.", nil
		case 2:
			return "Защитник снова обнаружил угрозу в этом файле. " + tail, nil
		}
		return "", fmt.Errorf("проверка не удалась (код %d): %s", r.code, tail)
	case <-time.After(150 * time.Second):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("проверка заняла слишком много времени")
	}
}

// ---------------------------------------------------------------- plain-text export

func threatText(t *DefThreat) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	tm := func(ms int64) string {
		if ms == 0 {
			return "—"
		}
		return time.UnixMilli(ms).Format("02.01.2006 15:04:05")
	}
	w("ЗАЩИТНИК WINDOWS ОБНАРУЖИЛ УГРОЗУ: %s", t.Name)
	w("Серьёзность: %s · Категория: %s · Активна сейчас: %v · Выполнялась: %s", firstNonEmpty(t.Severity, "—"), firstNonEmpty(t.Category, "—"), t.Active, map[string]string{"yes": "да", "no": "нет", "unknown": "неизвестно"}[t.Executed])
	w("Первое обнаружение: %s · последнее: %s", tm(t.First), tm(t.Last))
	w("Описание Microsoft: %s", t.InfoURL)
	w("")
	w("ОБНАРУЖЕНИЯ")
	for i, d := range t.Detections {
		w("%d. %s", i+1, tm(d.Time))
		for _, r := range d.Resources {
			w("   объект: %s%s%s", r.Path, map[bool]string{true: " → внутри: " + r.Inner, false: ""}[r.Inner != ""], map[bool]string{true: " (скачан с " + r.URL + ")", false: ""}[r.URL != ""])
		}
		w("   процесс: %s · пользователь: %s · источник: %s · происхождение: %s", firstNonEmpty(d.Process, "—"), firstNonEmpty(d.User, "—"), firstNonEmpty(d.Source, "—"), firstNonEmpty(d.Origin, "—"))
		w("   тип обнаружения: %s · действие: %s · состояние: %s · выполнение: %s", firstNonEmpty(d.DetType, "—"), firstNonEmpty(d.Action, "—"), firstNonEmpty(d.Status, "—"), firstNonEmpty(d.Execution, "—"))
		if d.Error != "" {
			w("   ошибка: %s", d.Error)
		}
		w("   базы: %s · движок: %s", firstNonEmpty(d.Signature, "—"), firstNonEmpty(d.Engine, "—"))
	}
	for _, f := range t.Files {
		w("")
		w("ФАЙЛ: %s", f.Path)
		if !f.Exists {
			w("   файла нет на диске (карантин или удалён)")
		} else {
			w("   размер: %d байт · создан: %s · изменён: %s · открыт: %s", f.Size, tm(f.Created), tm(f.Modified), tm(f.Accessed))
			w("   SHA-256: %s", firstNonEmpty(f.SHA256, "—"))
			w("   подпись: %s %s", f.Sig, f.Signer)
			if f.Zone != "" {
				w("   откуда: %s · %s · страница: %s", f.Zone, f.HostURL, f.Referrer)
			}
		}
		for _, r := range f.Runs {
			w("   запуск: %s — %s %s", r.Source, tm(r.Last), r.Note)
		}
		for _, s := range f.Siblings {
			w("   рядом создан: %s (%d байт, %s)", s.Name, s.Size, tm(s.Created))
		}
	}
	w("")
	w("ПОЧЕМУ ЗАЩИТНИК ПОЖАЛОВАЛСЯ")
	label := map[string]string{"defender": "[Defender]", "system": "[система]", "inference": "[вывод программы]"}
	for _, x := range t.Why {
		w(" %s %s", label[x.Basis], x.Text)
	}
	w("")
	w("ЖУРНАЛ DEFENDER ВОКРУГ ОБНАРУЖЕНИЯ")
	for _, c := range t.Context {
		w(" %s  %s — %s", tm(c.T), c.Source, c.Text)
	}
	w("")
	w("ЧТО ДЕЛАТЬ")
	for _, a := range t.Advice {
		w(" • %s", a)
	}
	return b.String()
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
