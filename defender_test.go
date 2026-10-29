package main

import (
	"strings"
	"testing"
	"time"
)

func TestThreatNameParsing(t *testing.T) {
	p := parseThreatName("Trojan:Win32/Kepavll!rfn")
	if p.Type != "Trojan" || p.Platform != "Win32" || p.Family != "Kepavll" || p.Variant != "" || p.Suffix != "rfn" {
		t.Fatalf("bad parts: %+v", p)
	}
	if !strings.Contains(p.SuffixText, "не публикует") {
		t.Errorf("must say the suffix is not officially documented: %q", p.SuffixText)
	}
	for _, bad := range []string{"чаще бывают ложными", "ложное срабатывание"} {
		if strings.Contains(p.SuffixText, bad) && !strings.Contains(p.SuffixText, "нельзя судить") {
			t.Errorf("suffix text must not claim it is usually a false positive: %q", p.SuffixText)
		}
	}
	w := parseThreatName("Trojan:Win32/Wacatac.H!ml")
	if w.Family != "Wacatac" || w.Variant != "H" || !strings.Contains(w.SuffixText, "машинное обучение") {
		t.Errorf("bad parts: %+v", w)
	}
	if h := parseThreatName("HackTool:Win32/Crack!rfn"); !strings.Contains(h.TypeText, "инструмент взлома") {
		t.Errorf("hacktool description: %q", h.TypeText)
	}
	if b := parseThreatName("Behavior:Win32/Foo.A"); b.Suffix != "" || b.Family != "Foo" {
		t.Errorf("no-suffix name: %+v", b)
	}
}

func TestResourceParsing(t *testing.T) {
	f := parseResource(`file:_C:\Users\u\Downloads\a.exe`)
	if f.Kind != "file" || f.Path != `C:\Users\u\Downloads\a.exe` || f.Label != "файл" {
		t.Errorf("file: %+v", f)
	}
	w := parseResource(`webfile:_C:\Users\u\Downloads\a.exe|https://evil.example/a.exe|pid:44`)
	if w.URL != "https://evil.example/a.exe" || w.Path != `C:\Users\u\Downloads\a.exe` {
		t.Errorf("webfile: %+v", w)
	}
	c := parseResource(`containerfile:_C:\a.zip->setup.exe`)
	if c.Path != `C:\a.zip` || c.Inner != "setup.exe" {
		t.Errorf("container: %+v", c)
	}
	st := parseResource(`startup:_C:\Menu\x.lnk`)
	if !strings.Contains(st.Label, "автозагрузки") {
		t.Errorf("startup label: %q", st.Label)
	}
	pr := parseResource("process:_pid:34076,ProcessStart:134375665800976146")
	if pr.Start != 1793092980097 || !strings.Contains(pr.Path, "PID 34076") {
		t.Errorf("process start must be decoded from FILETIME: %+v", pr)
	}
}

func syntheticDefender() {
	ev := func(id int, ts, name, tid string, data map[string]any) map[string]any {
		data["Threat ID"], data["Threat Name"] = tid, name
		return map[string]any{"Id": float64(id), "Time": ts, "Data": data, "Text": "event"}
	}
	defMu.Lock()
	defCache = &defRaw{at: time.Now(),
		threats: []map[string]any{
			{"ThreatID": "100", "ThreatName": "Trojan:Win32/Test.A", "SeverityID": float64(5), "CategoryID": float64(8), "IsActive": true, "DidThreatExecute": true},
		},
		dets: []map[string]any{
			{"ThreatID": "100", "ProcessName": `C:\Windows\explorer.exe`,
				"Resources":            []any{`file:_C:\nowhere\loader.exe`, `startup:_C:\nowhere\loader.lnk`, "process:_pid:77,ProcessStart:134375665800976146"},
				"InitialDetectionTime": "2026-10-27T09:22:10Z", "LastThreatStatusChangeTime": "2026-10-27T09:22:30Z", "RemediationTime": "2026-10-27T09:23:00Z",
				"ThreatStatusID": float64(3), "CurrentThreatExecutionStatusID": float64(3), "DetectionSourceTypeID": float64(3)},
		},
		events: []map[string]any{
			ev(1116, "2026-10-27T09:22:11Z", "Trojan:Win32/Test.A", "100", map[string]any{"Source Name": "Защита в реальном времени:", "Type Name": "Конкретный",
				"Origin Name": "Локальный компьютер", "Process Name": "Unknown", "Detection User": `PC\u`, "Severity Name": "Критический", "Category Name": "Троян"}),
			ev(1116, "2026-10-20T10:00:00Z", "HackTool:Win32/Old.B", "200", map[string]any{"Severity Name": "Высокий", "Category Name": "Инструмент", "Path": `file:_C:\nowhere\old.exe`}),
		},
	}
	defMu.Unlock()
}

func TestDefenderReportFromLog(t *testing.T) {
	syntheticDefender()
	reps := defenderReports("Trojan:Win32/Test.A")
	if len(reps) != 1 {
		t.Fatalf("want 1 threat, got %d", len(reps))
	}
	r := reps[0]
	if r.Severity != "Критический" || r.Category != "Троян" || !r.Active || r.Executed != "yes" {
		t.Errorf("summary wrong: %+v", r)
	}
	if len(r.Detections) != 1 {
		t.Fatalf("detections: %d", len(r.Detections))
	}
	d := r.Detections[0]
	if d.Source != "Защита в реальном времени" || d.DetType != "Конкретный" || d.Process != `C:\Windows\explorer.exe` || !d.FromEvent {
		t.Errorf("event fields not merged into the detection: %+v", d)
	}
	if len(d.Resources) != 3 || d.Resources[2].Start != 1793092980097 {
		t.Errorf("resources: %+v", d.Resources)
	}
	// the story: detection, then the process the threat had started
	var tl []string
	for _, e := range r.Timeline {
		tl = append(tl, e.Text)
	}
	joined := strings.Join(tl, "\n")
	if !strings.Contains(joined, "loader.exe") || !strings.Contains(joined, "PID 77") {
		t.Errorf("timeline lacks the file or the started process:\n%s", joined)
	}
	for i := 1; i < len(r.Timeline); i++ {
		if r.Timeline[i].T < r.Timeline[i-1].T {
			t.Fatal("timeline must be chronological")
		}
	}
	// executed + startup entry + missing file: advice must follow from the facts
	adv := strings.Join(r.Advice, "\n")
	for _, want := range []string{"успела выполниться", "автозагрузку", "уже в карантине"} {
		if !strings.Contains(adv, want) {
			t.Errorf("advice lacks %q:\n%s", want, adv)
		}
	}
	// nothing the program cannot know
	for _, w := range r.Why {
		if strings.Contains(w.Text, "чаще ложные") {
			t.Errorf("unsupported claim: %s", w.Text)
		}
	}
	if !strings.Contains(r.Text, "Trojan:Win32/Test.A") || !strings.Contains(r.Text, "ЖУРНАЛ DEFENDER") {
		t.Errorf("text export incomplete")
	}
	if !strings.Contains(r.InfoURL, "Trojan%3AWin32%2FTest.A") {
		t.Errorf("info url: %s", r.InfoURL)
	}
}

func TestEveryDefenderThreatBecomesAnIncident(t *testing.T) {
	syntheticDefender()
	recordDefenderIncidents()
	active := hasIncident("defender", "Test.A")
	if active == nil || active.Severity != "bad" || active.Ref != "Trojan:Win32/Test.A" {
		t.Fatalf("active executed threat should be bad with a reference: %+v", active)
	}
	old := hasIncident("defender", "Old.B")
	if old == nil || old.Severity != "warn" {
		t.Fatalf("a threat known only from the event log must still be listed: %+v", old)
	}
	// re-running a check must not pile up repeats
	recordDefenderIncidents()
	if again := hasIncident("defender", "Test.A"); again.Count != 1 {
		t.Errorf("re-check counted as a new occurrence: %d", again.Count)
	}
}
