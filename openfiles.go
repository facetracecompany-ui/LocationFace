package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// What a program has open while it talks to the network. Together with the
// transfer size this shows which files are likely being sent, and catches
// programs that read other programs' secrets.

type FileRef struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mod   int64  `json:"mod"`
	Seen  int64  `json:"seen"`
	Match bool   `json:"match"` // size agrees with the amount sent
	Sens  string `json:"sens"`  // label of a secret this file holds; empty if ordinary
}

var (
	ofMu     sync.Mutex
	pidFiles = map[int32]map[string]*FileRef{}
)

// handleTable returns the handle values that belong to files, per PID.
func handleTable() (map[uint32][]uintptr, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(exe) // our own handle is how we learn the "File" object type index
	if err != nil {
		return nil, err
	}
	defer f.Close()
	proc := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation")
	buf := make([]byte, 4<<20)
	for {
		var ret uint32
		st, _, _ := proc.Call(64, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
		if uint32(st) == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
			buf = make([]byte, len(buf)*2)
			continue
		}
		if st != 0 {
			return nil, windows.NTStatus(st)
		}
		break
	}
	type entry struct {
		Object, PID, Handle uintptr
		Access              uint32
		Trace, TypeIdx      uint16
		Attr, _             uint32
	}
	n := *(*uintptr)(unsafe.Pointer(&buf[0]))
	es := unsafe.Slice((*entry)(unsafe.Pointer(&buf[2*unsafe.Sizeof(uintptr(0))])), n)
	self, fileType := uintptr(windows.GetCurrentProcessId()), uint16(0xffff)
	for i := range es {
		if es[i].PID == self && es[i].Handle == f.Fd() {
			fileType = es[i].TypeIdx
			break
		}
	}
	if fileType == 0xffff {
		return nil, errors.New("не удалось определить тип файловых дескрипторов")
	}
	out := map[uint32][]uintptr{}
	for i := range es {
		if es[i].TypeIdx == fileType {
			out[uint32(es[i].PID)] = append(out[uint32(es[i].PID)], es[i].Handle)
		}
	}
	return out, nil
}

// filesOf duplicates a process's file handles and returns the disk files behind them.
func filesOf(pid uint32, handles []uintptr, deadline time.Time) []string {
	ph, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(ph)
	cur := windows.CurrentProcess()
	var (
		files []string
		seen  = map[string]bool{}
		buf   [windows.MAX_LONG_PATH]uint16
	)
	for _, h := range handles {
		if time.Now().After(deadline) {
			break
		}
		var d windows.Handle
		if windows.DuplicateHandle(ph, windows.Handle(h), cur, &d, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
			continue
		}
		// only real disk files: asking a pipe for its name can hang
		if t, err := windows.GetFileType(d); err == nil && t == windows.FILE_TYPE_DISK {
			if n, err := windows.GetFinalPathNameByHandle(d, &buf[0], uint32(len(buf)), 0); err == nil && n > 0 {
				path := strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`)
				if !seen[path] {
					var fi windows.ByHandleFileInformation
					if windows.GetFileInformationByHandle(d, &fi) == nil && fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
						seen[path] = true
						files = append(files, path)
					}
				}
			}
		}
		windows.CloseHandle(d)
	}
	return files
}

// ---------------------------------------------------------------- classification

type secretRule struct {
	label  string
	match  func(low, base string) bool
	owners []string // executable names that legitimately use this file
	pubs   []string // signer fragments of its legitimate owners
	weak   bool     // only report for unsigned programs
}

var secretRules = []secretRule{
	{label: "Пароли и cookie браузера", owners: []string{"chrome.exe", "msedge.exe", "browser.exe", "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe", "chromium.exe"},
		pubs: []string{"google", "mozilla", "yandex", "opera", "brave", "vivaldi"},
		match: func(low, base string) bool {
			if !(strings.Contains(low, `\user data\`) || strings.Contains(low, `\profiles\`) || strings.Contains(low, `\opera stable\`)) {
				return false
			}
			switch base {
			case "login data", "login data for account", "cookies", "web data", "key4.db", "logins.json", "cookies.sqlite", "local state":
				return true
			}
			return false
		}},
	{label: "Сессия Telegram (tdata)", owners: []string{"telegram.exe"}, pubs: []string{"telegram"},
		match: func(low, base string) bool { return strings.Contains(low, `\telegram desktop\tdata`) }},
	{label: "Токены Discord", owners: []string{"discord.exe", "discordcanary.exe", "discordptb.exe"}, pubs: []string{"discord"},
		match: func(low, base string) bool {
			return strings.Contains(low, `\local storage\leveldb`) && (strings.Contains(low, `\discord`) || strings.Contains(low, `\lightcord`))
		}},
	{label: "Криптокошелёк", owners: []string{"exodus.exe", "electrum.exe", "bitcoin-qt.exe", "atomic wallet.exe", "chrome.exe", "msedge.exe", "firefox.exe", "browser.exe"},
		pubs: []string{"exodus", "electrum", "bitcoin", "google", "mozilla", "yandex"},
		match: func(low, base string) bool {
			return base == "wallet.dat" || strings.Contains(low, `\exodus\exodus.wallet`) || strings.Contains(low, `\electrum\wallets\`) ||
				strings.Contains(low, `\atomic\local storage\leveldb`) || strings.Contains(low, "nkbihfbeogaeaoehlefnkodbefgpgknn")
		}},
	{label: "Ключи SSH и облачные учётные данные",
		owners: []string{"ssh.exe", "ssh-agent.exe", "git.exe", "git-remote-https.exe", "putty.exe", "pageant.exe", "plink.exe", "winscp.exe", "termius.exe", "kubectl.exe", "aws.exe", "az.exe", "gcloud.exe", "terraform.exe", "scp.exe", "sftp.exe"},
		match: func(low, base string) bool {
			return (strings.Contains(low, `\.ssh\`) && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub")) ||
				strings.HasSuffix(low, `\.aws\credentials`) || strings.HasSuffix(low, `\.kube\config`) ||
				strings.HasSuffix(low, `\.azure\accesstokens.json`) || strings.HasSuffix(low, `\gcloud\credentials.db`) ||
				(strings.Contains(low, `\.ssh\`) && strings.HasSuffix(base, ".ppk"))
		}},
	{label: "База менеджера паролей (KeePass)", owners: []string{"keepass.exe", "keepassxc.exe"}, pubs: []string{"keepass"},
		match: func(low, base string) bool {
			return strings.HasSuffix(base, ".kdbx") || strings.HasSuffix(base, ".kdb")
		}},
	{label: "Файл с паролями", weak: true,
		owners: []string{"notepad.exe", "wordpad.exe", "winword.exe", "excel.exe", "notepad++.exe", "code.exe", "explorer.exe", "onenote.exe", "soffice.bin", "libreoffice.exe"},
		match: func(low, base string) bool {
			if !(strings.Contains(base, "password") || strings.Contains(base, "парол") || strings.Contains(base, "passwd")) {
				return false
			}
			switch strings.ToLower(filepath.Ext(base)) {
			case ".txt", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".json", ".rtf", ".odt":
				return true
			}
			return false
		}},
}

func sensitiveRule(path string) *secretRule {
	low := strings.ToLower(path)
	base := filepath.Base(low)
	for i := range secretRules {
		if secretRules[i].match(low, base) {
			return &secretRules[i]
		}
	}
	return nil
}

// foreignTo reports whether the process has no business with this secret.
func foreignTo(r *secretRule, m *ProcMeta) bool {
	if r == nil || m == nil || isUserTrusted(m.Exe) {
		return false
	}
	kind := actorKind(m)
	if kind == "unknown" {
		return false // not yet verified: do not guess
	}
	base := exeBase(m)
	for _, o := range r.owners {
		if base == o {
			return false
		}
	}
	if signerHas(m, r.pubs) {
		return false
	}
	if r.weak {
		return kind == "unsigned"
	}
	// well-known vendors (antivirus, system) read these files legitimately
	return kind != "vendor" && kind != "browser"
}

var boringDirs = []string{`\windows\`, `\program files\`, `\program files (x86)\`, `\programdata\microsoft\`, `\appdata\local\microsoft\`,
	`\cache\`, `\code cache\`, `\gpucache\`, `\cache_data\`, `\shadercache\`, `\blob_storage\`, `\dawncache\`, `\grshadercache\`,
	`\cachestorage\`, `\inetcache\`, `\crashpad\`, `\node_modules\`, `\site-packages\`, `\__pycache__\`, `\go\pkg\mod\`, `\.git\objects\`,
	`\$recycle.bin\`, `\system volume information\`}
var boringExt = map[string]bool{".dll": true, ".exe": true, ".sys": true, ".mui": true, ".nls": true, ".ttf": true, ".otf": true, ".ttc": true,
	".etl": true, ".pf": true, ".mum": true, ".cat": true, ".manifest": true, ".lnk": true, ".tmp": true, ".pyc": true, ".pak": true, ".dat": false}

func boringFile(path string) bool {
	low := strings.ToLower(path)
	if boringExt[strings.ToLower(filepath.Ext(low))] || strings.HasPrefix(filepath.Base(low), "~") {
		return true
	}
	for _, d := range boringDirs {
		if strings.Contains(low, d) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- sampler

func fileSampler() {
	for {
		time.Sleep(4 * time.Second)
		sampleFiles()
	}
}

// recentSenders: processes that sent data to the internet in the last minute.
func recentSenders() map[int32]bool {
	out := map[int32]bool{}
	now := time.Now().UnixMilli()
	pkMu.Lock()
	for _, f := range flows {
		if f.Scope == "public" && f.Out > 0 && now-f.Last < 60000 && f.PID > 4 {
			out[f.PID] = true
		}
	}
	pkMu.Unlock()
	return out
}

func sampleFiles() {
	targets := recentSenders()
	pubConn := map[int32]bool{}
	for _, c := range connsSnapshot() {
		if c.Scope == "public" && c.Dir != "listen" && c.PID > 4 {
			targets[c.PID] = true
			pubConn[c.PID] = true
		}
	}
	if len(targets) == 0 {
		return
	}
	table, err := handleTable()
	if err != nil {
		return
	}
	self := int32(os.Getpid())
	deadline := time.Now().Add(3500 * time.Millisecond)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for pid := range targets {
		hs := table[uint32(pid)]
		if pid == self || len(hs) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pid int32, hs []uintptr) {
			defer wg.Done()
			defer func() { <-sem }()
			ingestFiles(pid, filesOf(uint32(pid), hs, deadline), pubConn[pid])
		}(pid, hs)
	}
	wg.Wait()

	// forget stale entries
	cut := time.Now().Add(-10 * time.Minute).UnixMilli()
	ofMu.Lock()
	for pid, m := range pidFiles {
		for p, f := range m {
			if f.Seen < cut {
				delete(m, p)
			}
		}
		if len(m) == 0 {
			delete(pidFiles, pid)
		}
	}
	ofMu.Unlock()
}

func ingestFiles(pid int32, paths []string, publicConn bool) {
	var meta *ProcMeta
	if idx := procIndex.Load(); idx != nil {
		meta = (*idx)[pid]
	}
	now := time.Now().UnixMilli()
	var found []*FileRef
	ofMu.Lock()
	m := pidFiles[pid]
	if m == nil {
		m = map[string]*FileRef{}
		pidFiles[pid] = m
	}
	for _, p := range paths {
		rule := sensitiveRule(p)
		if rule == nil && boringFile(p) {
			continue
		}
		if meta != nil && strings.EqualFold(p, meta.Exe) {
			continue
		}
		f := m[p]
		if f == nil {
			if len(m) >= 250 {
				continue
			}
			f = &FileRef{Path: p}
			if st, err := os.Stat(p); err == nil {
				f.Size, f.Mod = st.Size(), st.ModTime().UnixMilli()
			}
			m[p] = f
		}
		f.Seen = now
		if rule != nil && foreignTo(rule, meta) {
			f.Sens = rule.label
			found = append(found, f)
		}
	}
	ofMu.Unlock()
	for _, f := range found {
		reportSensitive(meta, f, publicConn)
	}
}

func reportSensitive(m *ProcMeta, f *FileRef, publicConn bool) {
	sev := "warn"
	if publicConn && actorKind(m) == "unsigned" {
		sev = "bad"
	}
	in := Incident{Key: "stealer|" + strings.ToLower(m.Exe+m.Name) + "|" + f.Sens, Kind: "stealer", Severity: sev,
		Title: fmt.Sprintf("%s открыл чужой секретный файл: %s", m.Name, f.Sens)}
	in.Reasons = []string{
		fmt.Sprintf("Программа не является владельцем файла «%s», но держит его открытым", filepath.Base(f.Path)),
		"Вид программы: " + map[string]string{"unsigned": "без цифровой подписи", "signed": "подписана, но издатель не из списка известных"}[actorKind(m)],
	}
	if publicConn {
		in.Reasons = append(in.Reasons, "В это же время у программы есть соединения с интернетом — данные могут уходить наружу")
	}
	fillProc(&in, m.PID)
	addIncident(in, &Evidence{T: time.Now().UnixMilli(), Line: fmt.Sprintf("Открыт файл: %s  (%s, %s)", f.Path, f.Sens, fmtBytes(uint64(f.Size)))})
}

// candidateFiles lists the files a process has had open, most likely sources first.
func candidateFiles(pid int32, out uint64) (all []FileRef, foreign []FileRef) {
	ofMu.Lock()
	for _, f := range pidFiles[pid] {
		c := *f
		if c.Size > 0 && out > 0 && float64(out) >= float64(c.Size)*0.9 && float64(out) <= float64(c.Size)*1.3+256<<10 {
			c.Match = true
		}
		all = append(all, c)
		if c.Sens != "" {
			foreign = append(foreign, c)
		}
	}
	ofMu.Unlock()
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Match != b.Match {
			return a.Match
		}
		if (a.Sens != "") != (b.Sens != "") {
			return a.Sens != ""
		}
		return a.Seen > b.Seen
	})
	if len(all) > 20 {
		all = all[:20]
	}
	return
}
