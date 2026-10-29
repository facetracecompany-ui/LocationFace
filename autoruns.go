package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

type Autorun struct {
	Where   string   `json:"where"`
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Exe     string   `json:"exe"`
	Exists  bool     `json:"exists"`
	Sig     string   `json:"sig"`
	Signer  string   `json:"signer"`
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
	Decoded string   `json:"decoded,omitempty"` // script behind a PowerShell -EncodedCommand
}

// exeFromCommand extracts the program path from a command line.
func exeFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if exp, err := registry.ExpandString(cmd); err == nil {
		cmd = exp
	}
	if st, err := os.Stat(cmd); err == nil && !st.IsDir() { // a plain path, possibly with spaces
		return cmd
	}
	cmd = strings.TrimPrefix(cmd, `\??\`)
	if strings.HasPrefix(strings.ToLower(cmd), `\systemroot\`) {
		cmd = os.Getenv("SystemRoot") + cmd[len(`\systemroot`):]
	}
	if strings.HasPrefix(cmd, `"`) {
		if j := strings.Index(cmd[1:], `"`); j >= 0 {
			return cmd[1 : j+1]
		}
		return strings.Trim(cmd, `"`)
	}
	low := strings.ToLower(cmd)
	for _, ext := range []string{".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", ".ps1", ".dll"} {
		if i := strings.Index(low, ext); i >= 0 {
			return cmd[:i+len(ext)]
		}
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return f[0]
	}
	return cmd
}

// resolveBare finds a program given without a directory ("explorer.exe").
func resolveBare(p string) string {
	if p == "" || strings.ContainsAny(p, `\/`) {
		return p
	}
	win := os.Getenv("SystemRoot")
	for _, d := range []string{win, filepath.Join(win, "System32"), filepath.Join(win, "SysWOW64")} {
		c := filepath.Join(d, p)
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if lp, err := exec.LookPath(p); err == nil {
		return lp
	}
	return p
}

var disguiseName = regexp.MustCompile(`(?i)system|maintenance|windows|microsoft|update|security|defender|service|driver|runtime|host`)

func makeAutorun(where, name, cmd string) Autorun {
	a := Autorun{Where: where, Name: name, Command: cmd, Exe: resolveBare(exeFromCommand(cmd))}
	if a.Exe != "" {
		if _, err := os.Stat(a.Exe); err == nil {
			a.Exists = true
		}
	}
	if s, ok := decodePSCommand(cmd); ok {
		a.Decoded = s
		if len(a.Decoded) > 4000 {
			a.Decoded = a.Decoded[:4000] + "\n…"
		}
	}
	m := &ProcMeta{Name: filepath.Base(a.Exe), Cmd: cmd}
	if a.Exists {
		m.Exe = a.Exe
		s := getSig(a.Exe)
		m.Sig, a.Sig, a.Signer = s.Status, s.Status, s.Signer
	} else {
		a.Sig = "missing"
	}
	scoreProc(m) // for a missing file only the command-line rules apply
	a.Score, a.Reasons = m.Score, m.Reasons
	if !a.Exists && a.Exe != "" && !strings.EqualFold(filepath.Ext(a.Exe), ".dll") {
		a.Score += 2
		a.Reasons = append(a.Reasons, "Файла нет на диске — устаревшая или «битая» запись (вирусы тоже удаляют себя, оставляя запись)")
	}
	// a harmless-sounding name pointing into a user folder, without a trusted signature
	lp := strings.ToLower(a.Exe)
	userDir := strings.Contains(lp, `\appdata\`) || strings.Contains(lp, `\programdata\`) || strings.Contains(lp, `\temp\`) || strings.Contains(lp, `\users\public\`)
	if userDir && a.Sig != "signed" && a.Sig != "pending" && disguiseName.MatchString(name) && !strings.Contains(strings.ToLower(where), "папка") {
		a.Score += 3
		a.Reasons = append(a.Reasons, "Название похоже на системное, но программа лежит в папке пользователя без подписи — типичная маскировка")
	}
	a.Level = levelOf(a.Score)
	return a
}

func regRunValues(root registry.Key, rootName, path, label string) []Autorun {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	var out []Autorun
	for _, n := range names {
		v, _, err := k.GetStringValue(n)
		if err != nil || strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, makeAutorun(rootName+`\`+label, n, v))
	}
	return out
}

var (
	arMu    sync.Mutex
	arCache []Autorun
	arAt    time.Time
)

func autorunsScan() []Autorun {
	arMu.Lock()
	defer arMu.Unlock()
	if time.Since(arAt) < 10*time.Second && arCache != nil {
		return arCache
	}
	var out []Autorun
	runPaths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, p := range runPaths {
		out = append(out, regRunValues(registry.CURRENT_USER, "HKCU", p, p[len(`Software\Microsoft\Windows\CurrentVersion\`):])...)
		out = append(out, regRunValues(registry.LOCAL_MACHINE, "HKLM", p, p[len(`Software\Microsoft\Windows\CurrentVersion\`):])...)
	}

	// Winlogon: classic hijack points
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE); err == nil {
		for _, c := range []struct{ name, want string }{{"Shell", "explorer.exe"}, {"Userinit", `c:\windows\system32\userinit.exe,`}} {
			v, _, err := k.GetStringValue(c.name)
			if err != nil {
				continue
			}
			a := makeAutorun("Winlogon", c.name, v)
			if !strings.EqualFold(strings.TrimSpace(v), c.want) {
				a.Score += 5
				a.Reasons = append(a.Reasons, "Значение изменено (ожидается «"+c.want+"») — так вирусы встраиваются в вход в систему")
				a.Level = levelOf(a.Score)
			}
			out = append(out, a)
		}
		k.Close()
	}

	// Image File Execution Options debugger = program hijack
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, registry.ENUMERATE_SUB_KEYS); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, s := range subs {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`+s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if v, _, err := sk.GetStringValue("Debugger"); err == nil && v != "" {
				a := makeAutorun("IFEO Debugger", s, v)
				a.Score += 5
				a.Reasons = append(a.Reasons, "Перехват запуска программы через Debugger — приём для закрепления вируса")
				a.Level = levelOf(a.Score)
				out = append(out, a)
			}
			sk.Close()
		}
	}

	// Startup folders
	for _, d := range []struct{ label, path string }{
		{"Папка «Автозагрузка» (пользователь)", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
		{"Папка «Автозагрузка» (все)", filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
	} {
		ents, _ := os.ReadDir(d.path)
		var lnks []string
		for _, e := range ents {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			if strings.EqualFold(filepath.Ext(full), ".lnk") {
				lnks = append(lnks, full)
				continue
			}
			out = append(out, makeAutorun(d.label, e.Name(), full))
		}
		// resolve shortcuts to the program they really start
		targets := map[string]string{}
		if len(lnks) > 0 {
			q := make([]string, len(lnks))
			for i, l := range lnks {
				q[i] = psQuote(l)
			}
			res := psJSON("$w=New-Object -ComObject WScript.Shell; @("+strings.Join(q, ",")+") | ForEach-Object { $s=$w.CreateShortcut($_); [pscustomobject]@{Path=$_;Target=$s.TargetPath;Args=$s.Arguments} } | ConvertTo-Json -Compress", 30*time.Second)
			for _, r := range res {
				if t := str(r["Target"]); t != "" {
					targets[strings.ToLower(str(r["Path"]))] = `"` + t + `" ` + str(r["Args"])
				}
			}
		}
		for _, l := range lnks {
			cmd := l
			if t, ok := targets[strings.ToLower(l)]; ok {
				cmd = strings.TrimSpace(t)
			}
			out = append(out, makeAutorun(d.label, filepath.Base(l), cmd))
		}
	}

	// Services outside Windows
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		winDir := strings.ToLower(os.Getenv("SystemRoot"))
		for _, s := range subs {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			typ, _, e1 := sk.GetIntegerValue("Type")
			start, _, e2 := sk.GetIntegerValue("Start")
			img, _, e3 := sk.GetStringValue("ImagePath")
			sk.Close()
			if e1 != nil || e2 != nil || e3 != nil || (typ&0x30) == 0 || start > 2 {
				continue
			}
			exe := strings.ToLower(exeFromCommand(img))
			if strings.HasPrefix(exe, winDir) {
				continue
			}
			out = append(out, makeAutorun("Служба (автозапуск)", s, img))
		}
	}

	// Scheduled tasks outside \Microsoft
	tasks := psJSON(`Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object { $a=$_.Actions | Select-Object -First 1; [pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;Exe=$a.Execute;Args=$a.Arguments} } | ConvertTo-Json -Compress`, 40*time.Second)
	for _, t := range tasks {
		cmd := strings.TrimSpace(str(t["Exe"]) + " " + str(t["Args"]))
		if str(t["Exe"]) == "" {
			continue
		}
		out = append(out, makeAutorun("Планировщик задач", str(t["Path"])+str(t["Name"]), cmd))
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	arCache, arAt = out, time.Now()
	return out
}
