package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func meta(name, exe, sig, signer string) *ProcMeta {
	return &ProcMeta{PID: 1, Name: name, Exe: exe, Sig: sig, Signer: signer}
}

func TestServiceMatching(t *testing.T) {
	cases := []struct{ host, ip, want string }{
		{"api.telegram.org", "", "Telegram"},
		{"", "149.154.167.51", "Telegram"},
		{"cdn.discordapp.com", "", "Discord"},
		{"www.google.com", "", "Google"},
		{"notgoogle.com", "", ""}, // suffix must end at a dot boundary
		{"google.com.evil.example", "", ""},
		{"evil.example", "203.0.113.5", ""},
		{"abc.ngrok-free.app", "", "Туннель / динамический DNS"},
	}
	for _, c := range cases {
		got := ""
		if s := serviceFor(c.host, c.ip); s != nil {
			got = s.Name
		}
		if got != c.want {
			t.Errorf("serviceFor(%q,%q)=%q want %q", c.host, c.ip, got, c.want)
		}
	}
}

func TestOfficialTelegramUploadIsNotAThreat(t *testing.T) {
	tg := meta("Telegram.exe", `C:\Program Files\Telegram Desktop\Telegram.exe`, "signed", "Telegram FZ-LLC")
	v := judge(tg, serviceFor("", "149.154.167.51"), 0, 300<<20, false, nil)
	if v.Level != "ok" || v.Score != 0 {
		t.Fatalf("official client uploading 300MB to its servers must be ok: %+v", v)
	}
	if !strings.Contains(v.Label, "Ожидаемо") {
		t.Fatalf("label should explain it is expected: %q", v.Label)
	}
}

func TestUnknownProgramUsingTelegramBotIsFlagged(t *testing.T) {
	py := meta("python.exe", `C:\Users\u\AppData\Local\Temp\x\python.exe`, "unsigned", "")
	v := judge(py, serviceFor("api.telegram.org", ""), 0, 2<<20, true, nil)
	if v.Level == "ok" {
		t.Fatalf("unsigned program sending to a Telegram bot API must be flagged: %+v", v)
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "Telegram") {
		t.Fatalf("reason should name the channel: %v", v.Reasons)
	}
}

func TestVerdictScenarios(t *testing.T) {
	chrome := meta("chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "signed", "Google LLC")
	other := meta("tool.exe", `C:\Tools\tool.exe`, "signed", "Some Small Vendor Ltd")
	unsigned := meta("mystery.exe", `C:\Users\u\AppData\Roaming\mystery.exe`, "unsigned", "")
	pending := meta("new.exe", `C:\x\new.exe`, "pending", "")
	cases := []struct {
		name  string
		m     *ProcMeta
		host  string
		in    uint64
		out   uint64
		named bool
		want  string
	}{
		{"browser uploads 500MB anywhere", chrome, "files.random-host.example", 0, 500 << 20, true, "ok"},
		{"signed small vendor, 5MB unknown host", other, "api.vendor.example", 0, 5 << 20, true, "ok"},
		{"unsigned, tiny send", unsigned, "x.example", 0, 10 << 10, true, "ok"},
		{"unsigned, 5MB to unknown named host", unsigned, "x.example", 0, 5 << 20, true, "warn"},
		{"unsigned, 30MB to bare IP", unsigned, "", 0, 30 << 20, false, "bad"},
		{"signature still being checked, big upload", pending, "x.example", 0, 300 << 20, true, "ok"},
		{"unsigned to anonymous file host", unsigned, "gofile.io", 0, 1 << 20, true, "warn"},
		{"browser to anonymous file host", chrome, "gofile.io", 0, 50 << 20, true, "ok"},
	}
	for _, c := range cases {
		v := judge(c.m, serviceFor(c.host, ""), c.in, c.out, c.named, nil)
		if v.Level != c.want {
			t.Errorf("%s: got %s (score %d: %v), want %s", c.name, v.Level, v.Score, v.Reasons, c.want)
		}
	}
}

func TestSecretOwnership(t *testing.T) {
	login := `C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data`
	tdata := `C:\Users\u\AppData\Roaming\Telegram Desktop\tdata\D877F783D5D3EF8C\map1`
	r := sensitiveRule(login)
	if r == nil || r.label != "Пароли и cookie браузера" {
		t.Fatalf("browser password db not recognised: %+v", r)
	}
	if sensitiveRule(tdata) == nil {
		t.Fatal("telegram session not recognised")
	}
	if sensitiveRule(`C:\Users\u\Documents\report.docx`) != nil {
		t.Fatal("ordinary document must not be treated as a secret")
	}
	chrome := meta("chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "signed", "Google LLC")
	defender := meta("MsMpEng.exe", `C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`, "signed", "Microsoft Corporation")
	tg := meta("Telegram.exe", `C:\Telegram\Telegram.exe`, "signed", "Telegram FZ-LLC")
	thief := meta("svc.exe", `C:\Users\u\AppData\Roaming\svc.exe`, "unsigned", "")
	smallVendor := meta("backup.exe", `C:\Backup\backup.exe`, "signed", "Some Backup Ltd")
	if foreignTo(r, chrome) || foreignTo(r, defender) {
		t.Error("owner and antivirus must not be flagged")
	}
	if !foreignTo(r, thief) || !foreignTo(r, smallVendor) {
		t.Error("unrelated programs reading browser passwords must be flagged")
	}
	if foreignTo(sensitiveRule(tdata), tg) || !foreignTo(sensitiveRule(tdata), thief) {
		t.Error("telegram session ownership wrong")
	}
	if foreignTo(r, meta("x.exe", "", "pending", "")) {
		t.Error("unverified program must not be flagged yet")
	}
}

func TestStealerWithOutgoingTrafficIsBad(t *testing.T) {
	foreign := []FileRef{{Path: `C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data`, Sens: "Пароли и cookie браузера"}}
	thief := meta("svc.exe", `C:\Users\u\AppData\Roaming\svc.exe`, "unsigned", "")
	v := judge(thief, nil, 0, 50<<10, true, foreign)
	if v.Level != "bad" {
		t.Fatalf("reading browser passwords must be bad: %+v", v)
	}
	chrome := meta("chrome.exe", `C:\x\chrome.exe`, "signed", "Google LLC")
	if v := judge(chrome, nil, 0, 50<<10, true, nil); v.Level != "ok" {
		t.Fatalf("browser alone must be ok: %+v", v)
	}
}

func TestIngestFilesRaisesStealer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AppData", "Local", "Google", "Chrome", "User Data", "Default")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "Login Data")
	_ = os.WriteFile(login, []byte("sqlite"), 0o600)
	thief := meta("svc.exe", `C:\Users\u\AppData\Roaming\svc.exe`, "unsigned", "")
	thief.PID = 4321
	idx := map[int32]*ProcMeta{4321: thief}
	procIndex.Store(&idx)
	defer procIndex.Store(nil)
	ingestFiles(4321, []string{login}, true)
	in := hasIncident("stealer", "svc.exe")
	if in == nil || in.Severity != "bad" || len(in.Evidence) == 0 || !strings.Contains(in.Evidence[0].Line, "Login Data") {
		t.Fatalf("stealer incident missing or wrong: %+v", in)
	}
}

func TestRealHandleTableSeesOurOwnFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "held-open-by-test.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	table, err := handleTable()
	if err != nil {
		t.Skipf("handle table unavailable: %v", err)
	}
	files := filesOf(uint32(os.Getpid()), table[uint32(os.Getpid())], time.Now().Add(5*time.Second))
	for _, x := range files {
		if strings.EqualFold(x, p) {
			return
		}
	}
	t.Fatalf("our own open file %s not found among %d files", p, len(files))
}

func TestHarvestMultipartAndFTP(t *testing.T) {
	body := "POST /upload?token=SECRETVALUE&id=7 HTTP/1.1\r\nHost: up.example.com\r\nUser-Agent: python-requests/2.31\r\n" +
		"Content-Type: multipart/form-data; boundary=xx\r\n\r\n--xx\r\nContent-Disposition: form-data; name=\"file\"; filename=\"C:\\Users\\u\\Documents\\passwords.xlsx\"\r\n" +
		"Content-Type: application/vnd.ms-excel\r\n\r\nBINARY\r\n--xx--"
	pk := &Packet{Dir: "out"}
	harvest(pk, []byte(body))
	if pk.Req != "POST up.example.com/upload" {
		t.Errorf("request line: %q", pk.Req)
	}
	if len(pk.UpFiles) != 1 || pk.UpFiles[0].Name != "passwords.xlsx" || pk.UpFiles[0].Type != "application/vnd.ms-excel" {
		t.Errorf("uploaded file not extracted: %+v", pk.UpFiles)
	}
	if !strings.HasPrefix(pk.UA, "python-requests") {
		t.Errorf("user agent: %q", pk.UA)
	}
	all := strings.Join(pk.Fields, "|") + pk.Req
	if strings.Contains(all, "SECRETVALUE") {
		t.Errorf("a parameter value leaked: %s", all)
	}
	if !strings.Contains(all, "параметр адреса: token") || !strings.Contains(all, "поле формы: file") {
		t.Errorf("names missing: %s", all)
	}

	ftp := &Packet{Dir: "out"}
	harvest(ftp, []byte("STOR secrets.zip\r\n"))
	if len(ftp.UpFiles) != 1 || ftp.UpFiles[0].Name != "secrets.zip" {
		t.Errorf("ftp upload not extracted: %+v", ftp.UpFiles)
	}
	if got := maskQuery("/a?token=abc&x=1"); got != "/a?token=…&x=…" {
		t.Errorf("maskQuery: %q", got)
	}
}

// TestTransferPipeline pushes synthetic flows through the same path the UI uses.
func TestTransferPipeline(t *testing.T) {
	tg := meta("Telegram.exe", `C:\Telegram\Telegram.exe`, "signed", "Telegram FZ-LLC")
	tg.PID = 7001
	bad := meta("updater32.exe", `C:\Users\u\AppData\Roaming\updater32.exe`, "unsigned", "")
	bad.PID = 7002
	idx := map[int32]*ProcMeta{7001: tg, 7002: bad}
	procIndex.Store(&idx)
	defer procIndex.Store(nil)
	for _, ip := range []string{"149.154.167.51", "203.0.113.99"} {
		hostMu.Lock()
		hostNames[ip] = ""
		hostMu.Unlock()
	}
	pkMu.Lock()
	flows["t1"] = &Flow{PID: 7001, Proc: "Telegram.exe", Proto: "TCP", Remote: "149.154.167.51", RPort: 443, Scope: "public", Out: 300 << 20, In: 1 << 20, Pkts: 9000, First: 1, Last: 99999, TLS: true}
	flows["t2"] = &Flow{PID: 7002, Proc: "updater32.exe", Proto: "TCP", Remote: "203.0.113.99", RPort: 8080, Scope: "public", Out: 40 << 20, Pkts: 500, First: 1, Last: 99999,
		UpFiles: []UpFile{{Name: "cookies.zip", Type: "application/zip"}}, Reqs: []string{"POST 203.0.113.99/up"}}
	pkMu.Unlock()
	defer func() {
		pkMu.Lock()
		delete(flows, "t1")
		delete(flows, "t2")
		pkMu.Unlock()
	}()

	var tgT, badT *Transfer
	for _, x := range transfersSnapshot() {
		x := x
		switch x.PID {
		case 7001:
			tgT = &x
		case 7002:
			badT = &x
		}
	}
	if tgT == nil || badT == nil {
		t.Fatalf("transfers missing: %v %v", tgT, badT)
	}
	if tgT.Level != "ok" || tgT.Service != "Telegram" || tgT.Channel != "tls" {
		t.Errorf("telegram transfer: %+v", tgT.Verdict)
	}
	if badT.Level == "ok" || len(badT.UpFiles) != 1 || badT.Channel != "plain" {
		t.Errorf("unknown uploader should be flagged with its file: level=%s files=%v channel=%s", badT.Level, badT.UpFiles, badT.Channel)
	}
	inc := transferIncident(badT, "upload|test")
	joined := ""
	for _, e := range inc.Evidence {
		joined += e.Line + "\n"
	}
	if !strings.Contains(joined, "cookies.zip") || !strings.Contains(joined, "POST 203.0.113.99/up") {
		t.Errorf("incident evidence lacks what was sent:\n%s", joined)
	}
}
