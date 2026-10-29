package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeFirewall replaces Windows Firewall: it counts rules per address like the real one does.
type fakeFirewall struct {
	rules       map[string][]fwRule
	adds        int
	failRemove  bool
	failAdd     bool
	readable    bool
	removeLeave bool // Remove "succeeds" but the rules stay (e.g. blocked by policy)
}

func newFake(t *testing.T) *fakeFirewall {
	t.Setenv("APPDATA", t.TempDir()) // blocked.json goes here
	f := &fakeFirewall{rules: map[string][]fwRule{}, readable: true}
	blkMu.Lock()
	blkInfo, blkLoaded = nil, false
	blkMu.Unlock()
	oldA, oldL, oldAdd, oldRm := requireAdmin, fwList, fwAdd, fwRemove
	requireAdmin = func() bool { return true }
	fwList = func() (map[string][]fwRule, bool) {
		cp := map[string][]fwRule{}
		for k, v := range f.rules {
			cp[k] = append([]fwRule(nil), v...)
		}
		return cp, f.readable
	}
	fwAdd = func(ip string) error {
		if f.failAdd {
			return errors.New("boom")
		}
		f.adds++
		f.rules[ip] = append(f.rules[ip], fwRule{Enabled: true}, fwRule{Enabled: true}) // out + in
		return nil
	}
	fwRemove = func(ip string) error {
		if f.failRemove {
			return errors.New("denied")
		}
		if !f.removeLeave {
			delete(f.rules, ip)
		}
		return nil
	}
	t.Cleanup(func() { requireAdmin, fwList, fwAdd, fwRemove = oldA, oldL, oldAdd, oldRm })
	return f
}

func TestBlockRecordsWhoAndWhy(t *testing.T) {
	f := newFake(t)
	if err := blockIP("203.0.113.50", BlockInfo{Proc: "evil.exe", Exe: `C:\x\evil.exe`, Host: "bad.example", Why: "маячок"}); err != nil {
		t.Fatal(err)
	}
	if len(f.rules["203.0.113.50"]) != 2 {
		t.Fatalf("both directions must be blocked, got %d rules", len(f.rules["203.0.113.50"]))
	}
	rows := blocksSnapshot()
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	r := rows[0]
	if r.IP != "203.0.113.50" || r.Proc != "evil.exe" || r.Why != "маячок" || r.State != "active" || !r.Known || r.At == 0 {
		t.Errorf("row: %+v", r)
	}
	if !blockedSet()["203.0.113.50"] {
		t.Error("blocked set must contain the address (the connection list tags it)")
	}
}

func TestBlockTwiceDoesNotDuplicateRules(t *testing.T) {
	f := newFake(t)
	for i := 0; i < 3; i++ {
		if err := blockIP("203.0.113.50", BlockInfo{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.rules["203.0.113.50"]); n != 2 {
		t.Fatalf("repeated blocking must leave exactly 2 rules, got %d", n)
	}
}

func TestBlockRefusesWhatItShouldNot(t *testing.T) {
	newFake(t)
	for _, ip := range []string{"192.168.0.1", "127.0.0.1", "10.0.0.5", "not an ip", "", "224.0.0.1"} {
		if err := blockIP(ip, BlockInfo{}); err == nil {
			t.Errorf("%q must not be blockable", ip)
		}
	}
	requireAdmin = func() bool { return false }
	if err := blockIP("203.0.113.50", BlockInfo{}); err == nil || !strings.Contains(err.Error(), "администратора") {
		t.Errorf("without admin rights the reason must be explained: %v", err)
	}
	if err := unblockIP("203.0.113.50"); err == nil || !strings.Contains(err.Error(), "администратора") {
		t.Errorf("same for unblock: %v", err)
	}
}

func TestFailedAddLeavesNothingBehind(t *testing.T) {
	f := newFake(t)
	f.failAdd = true
	if err := blockIP("203.0.113.50", BlockInfo{}); err == nil {
		t.Fatal("must report the failure")
	}
	if len(f.rules) != 0 || len(blocksSnapshot()) != 0 {
		t.Errorf("a failed block must not be remembered: %+v", blocksSnapshot())
	}
}

func TestUnblockRemovesRulesAndRecord(t *testing.T) {
	f := newFake(t)
	_ = blockIP("203.0.113.50", BlockInfo{})
	if err := unblockIP("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 0 || len(blocksSnapshot()) != 0 || blockedSet()["203.0.113.50"] {
		t.Errorf("address must be fully unblocked: rules=%v rows=%v", f.rules, blocksSnapshot())
	}
}

func TestUnblockIsHonestWhenRulesStay(t *testing.T) {
	f := newFake(t)
	_ = blockIP("203.0.113.50", BlockInfo{})
	f.removeLeave = true
	err := unblockIP("203.0.113.50")
	if err == nil || !strings.Contains(err.Error(), "всё ещё заблокирован") {
		t.Fatalf("must not claim success while rules remain: %v", err)
	}
	if !blockedSet()["203.0.113.50"] {
		t.Error("the record must stay while the block is still in force")
	}
	f.removeLeave, f.failRemove = false, true
	if err := unblockIP("203.0.113.50"); err == nil {
		t.Error("a failing removal must be reported")
	}
	if !blockedSet()["203.0.113.50"] {
		t.Error("the record must stay when removal failed")
	}
}

func TestSnapshotShowsWhatTheFirewallReallyHolds(t *testing.T) {
	f := newFake(t)
	_ = blockIP("203.0.113.50", BlockInfo{Why: "a"})
	_ = blockIP("203.0.113.51", BlockInfo{Why: "b"})
	_ = blockIP("203.0.113.52", BlockInfo{Why: "c"})
	delete(f.rules, "203.0.113.51")                                      // someone removed the rule by hand
	f.rules["203.0.113.52"][0].Enabled = false                           // someone switched one off
	f.rules["203.0.113.99"] = []fwRule{{Enabled: true}, {Enabled: true}} // a rule we have no record of

	got := map[string]BlockRow{}
	for _, r := range blocksSnapshot() {
		got[r.IP] = r
	}
	if got["203.0.113.50"].State != "active" {
		t.Errorf("50: %+v", got["203.0.113.50"])
	}
	if got["203.0.113.51"].State != "missing" || !got["203.0.113.51"].Known {
		t.Errorf("a rule deleted by hand must show as missing: %+v", got["203.0.113.51"])
	}
	if got["203.0.113.52"].State != "disabled" {
		t.Errorf("a switched-off rule must show as disabled: %+v", got["203.0.113.52"])
	}
	if r, ok := got["203.0.113.99"]; !ok || r.Known || r.State != "active" {
		t.Errorf("a foreign rule with our name must be listed so it can be removed: %+v", r)
	}

	f.readable = false
	for _, r := range blocksSnapshot() {
		if r.State != "unknown" {
			t.Errorf("if the firewall cannot be read the state must be unknown, got %s", r.State)
		}
	}
}

func TestUnblockCleansUpAMissingRule(t *testing.T) {
	f := newFake(t)
	_ = blockIP("203.0.113.51", BlockInfo{})
	delete(f.rules, "203.0.113.51")
	if err := unblockIP("203.0.113.51"); err != nil {
		t.Fatalf("unblocking an address whose rule is already gone must just clear the record: %v", err)
	}
	if len(blocksSnapshot()) != 0 {
		t.Error("record not cleared")
	}
}

func TestUnblockAllReportsPartialFailure(t *testing.T) {
	f := newFake(t)
	for _, ip := range []string{"203.0.113.60", "203.0.113.61", "203.0.113.62"} {
		_ = blockIP(ip, BlockInfo{})
	}
	done, failed, err := unblockAll()
	if done != 3 || failed != 0 || err != nil || len(f.rules) != 0 {
		t.Fatalf("done=%d failed=%d err=%v rules=%v", done, failed, err, f.rules)
	}
}

func TestOldBlockFileIsMigrated(t *testing.T) {
	newFake(t)
	path := blockedFile()
	_ = os.MkdirAll(strings.TrimSuffix(path, `\blocked.json`), 0o755)
	if err := os.WriteFile(path, []byte(`["203.0.113.70","203.0.113.71"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	blkMu.Lock()
	blkInfo, blkLoaded = nil, false
	blkMu.Unlock()
	set := blockedSet()
	if !set["203.0.113.70"] || !set["203.0.113.71"] {
		t.Fatalf("addresses stored by the first version must survive: %v", set)
	}
}

func TestBlockInfoSurvivesARestart(t *testing.T) {
	newFake(t)
	_ = blockIP("203.0.113.80", BlockInfo{Proc: "p.exe", Why: "reason"})
	blkMu.Lock()
	blkInfo, blkLoaded = nil, false // as after a restart
	blkMu.Unlock()
	rows := blocksSnapshot()
	if len(rows) != 1 || rows[0].Proc != "p.exe" || rows[0].Why != "reason" {
		t.Fatalf("who and why must be kept on disk: %+v", rows)
	}
}
