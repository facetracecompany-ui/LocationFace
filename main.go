package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

//go:embed web
var webFS embed.FS

var (
	token    string
	lastSeen atomic.Int64 // last time the window polled the API
	started  = time.Now()
)

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchElevated starts a copy with administrator rights (UAC prompt).
func relaunchElevated() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString("--elevated")
	return windows.ShellExecute(0, verb, file, args, nil, windows.SW_NORMAL) == nil
}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if x == a {
			return true
		}
	}
	return false
}

func main() {
	if !isAdmin() && !hasArg("--elevated") && !hasArg("--noelevate") {
		if relaunchElevated() {
			return
		}
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token = hex.EncodeToString(b)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", ln.Addr().(*net.TCPAddr).Port, token)

	loadTrusted()
	loadIncidents()
	go incidentSaver()
	go vpnLoop()
	go fileSampler()
	go transferLoop()
	go connLoop()
	go sigWorker()
	go dnsCacheLoop()
	startSniffer()

	sub, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	api := func(path string, h http.HandlerFunc) { mux.HandleFunc(path, guard(h)) }
	api("/api/overview", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, overview()) })
	api("/api/conns", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, connsSnapshot()) })
	api("/api/procs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, procsSnapshot()) })
	api("/api/packets", handlePackets)
	api("/api/flows", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, flowsSnapshot()) })
	api("/api/dns", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, dnsSnapshot()) })
	api("/api/downloads", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, downloadsScan()) })
	api("/api/autoruns", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, autorunsScan()) })
	api("/api/security", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, securityScan(r.URL.Query().Get("refresh") == "1"))
	})
	api("/api/incidents", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, incidentsSnapshot()) })
	api("/api/packet", handlePacketDetail)
	api("/api/blocks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, blocksSnapshot()) })
	api("/api/vpn", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("refresh") == "1" {
			refreshVPN()
		}
		resp := map[string]any{"state": vpnState()}
		if r.URL.Query().Get("scan") == "1" {
			resp["scan"] = vpnScan()
		}
		writeJSON(w, resp)
	})
	api("/api/defender", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, defenderReports(r.URL.Query().Get("name"))) })
	api("/api/trusted", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, trustedList()) })
	api("/api/transfers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, transfersSnapshot()) })
	api("/api/action", handleAction)
	go func() { log.Fatal(http.Serve(ln, mux)) }()

	if f := os.Getenv("LF_URL_FILE"); f != "" { // tests: no window
		_ = os.WriteFile(f, []byte(url), 0o600)
		select {}
	}

	openWindow(url)
	// quit when the window is closed
	for {
		time.Sleep(3 * time.Second)
		seen := lastSeen.Load()
		if seen != 0 && time.Since(time.UnixMilli(seen)) > 20*time.Second {
			return
		}
		if seen == 0 && time.Since(started) > 60*time.Second {
			return
		}
	}
}

func openWindow(url string) {
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			if exec.Command(p, "--app="+url, "--window-size=1380,880").Start() == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		lastSeen.Store(time.Now().UnixMilli())
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// runPS runs a PowerShell snippet without a console window and returns stdout.
func runPS(script string, timeout time.Duration) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
		return strings.TrimPrefix(string(out), "\ufeff"), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("timeout")
	}
}

// psJSON runs a script whose output is ConvertTo-Json and decodes it as a list.
func psJSON(script string, timeout time.Duration) []map[string]any {
	out, _ := runPS(script, timeout)
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var list []map[string]any
	if json.Unmarshal([]byte(out), &list) == nil {
		return list
	}
	var one map[string]any
	if json.Unmarshal([]byte(out), &one) == nil {
		return []map[string]any{one}
	}
	return nil
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	var err error
	var info string
	switch q.Get("do") {
	case "kill":
		pid, _ := strconv.Atoi(q.Get("pid"))
		err = killPID(int32(pid))
	case "block":
		err = blockIP(q.Get("ip"), BlockInfo{Host: q.Get("host"), Proc: q.Get("proc"), Exe: q.Get("exe"), Why: q.Get("why"), Manual: q.Get("manual") == "1"})
		if err == nil {
			info = "Адрес заблокирован. Снять блокировку можно на вкладке «Блокировки»."
		}
	case "unblock":
		err = unblockIP(q.Get("ip"))
		if err == nil {
			info = "Адрес разблокирован: правила удалены из брандмауэра."
		}
	case "unblock_all":
		var done, failed int
		done, failed, err = unblockAll()
		info = fmt.Sprintf("Разблокировано адресов: %d", done)
		if failed > 0 {
			info += fmt.Sprintf(", не удалось: %d", failed)
		} else {
			err = nil
		}
	case "clear_incidents":
		clearIncidents()
	case "open_defender":
		err = exec.Command("explorer.exe", "windowsdefender://threat/").Start()
	case "scan_file":
		info, err = scanFile(q.Get("path"))
	case "trust":
		err = trustProgram(q.Get("path"))
	case "untrust":
		untrustProgram(q.Get("path"))
	case "reveal":
		p := q.Get("path")
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			_ = exec.Command("explorer", "/select,"+p).Start()
		} else {
			err = fmt.Errorf("файл не найден")
		}
	default:
		err = fmt.Errorf("неизвестное действие")
	}
	msg := "ok"
	if info != "" {
		msg = info
	}
	if err != nil {
		msg = err.Error()
		if strings.Contains(strings.ToLower(msg), "access is denied") {
			msg = "Отказано в доступе — запустите от имени администратора"
		}
	}
	writeJSON(w, map[string]any{"ok": err == nil, "message": msg})
}
