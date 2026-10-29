package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Addresses blocked through Windows Firewall. The firewall is the source of truth: a block
// exists only if its rules exist, and an unblock counts only when the rules are really gone.
// The program's own file (blocked.json) adds who blocked an address, when and why.

type BlockInfo struct {
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Proc   string `json:"proc"`
	Exe    string `json:"exe"`
	Why    string `json:"why"`
	At     int64  `json:"at"`
	Manual bool   `json:"manual"`
}

type BlockRow struct {
	BlockInfo
	State string `json:"state"` // active | disabled | missing | unknown
	Rules int    `json:"rules"`
	Known bool   `json:"known"` // false: the rule exists in the firewall but this program has no record of it
}

type fwRule struct {
	Enabled bool
}

var (
	blkMu     sync.Mutex
	blkInfo   map[string]*BlockInfo
	blkLoaded bool

	// the firewall, behind functions so tests can replace it
	requireAdmin = func() bool { return isAdmin() }
	fwList       = fwListReal
	fwAdd        = fwAddReal
	fwRemove     = fwRemoveReal
)

func blockedFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "LocationFace", "blocked.json")
}

func loadBlocksLocked() {
	if blkLoaded {
		return
	}
	blkLoaded = true
	blkInfo = map[string]*BlockInfo{}
	data, err := os.ReadFile(blockedFile())
	if err != nil {
		return
	}
	var list []BlockInfo
	if json.Unmarshal(data, &list) == nil {
		for i := range list {
			if list[i].IP != "" {
				b := list[i]
				blkInfo[b.IP] = &b
			}
		}
		return
	}
	var legacy []string // the first version stored bare addresses
	if json.Unmarshal(data, &legacy) == nil {
		for _, ip := range legacy {
			blkInfo[ip] = &BlockInfo{IP: ip, Why: "заблокирован ранее (подробности не сохранились)"}
		}
	}
}

func saveBlocksLocked() {
	list := make([]BlockInfo, 0, len(blkInfo))
	for _, b := range blkInfo {
		list = append(list, *b)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].At > list[j].At })
	_ = os.MkdirAll(filepath.Dir(blockedFile()), 0o755)
	data, _ := json.Marshal(list)
	_ = os.WriteFile(blockedFile(), data, 0o600)
}

// blockedSet is the set of addresses this program has blocked.
func blockedSet() map[string]bool {
	blkMu.Lock()
	defer blkMu.Unlock()
	loadBlocksLocked()
	out := make(map[string]bool, len(blkInfo))
	for ip := range blkInfo {
		out[ip] = true
	}
	return out
}

func ruleName(ip string) string { return "LocationFace block " + ip }

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

func netsh(args ...string) error {
	out, err := hidden(exec.Command("netsh", args...)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// fwListReal returns our rules per address; ok is false when the firewall could not be read.
func fwListReal() (map[string][]fwRule, bool) {
	out, err := runPS(`$r=@(Get-NetFirewallRule -DisplayName 'LocationFace block *' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{Name=$_.DisplayName;Enabled=[string]$_.Enabled} })
if($r.Count -gt 0){ $r | ConvertTo-Json -Compress } else { '[]' }`, 30*time.Second)
	if err != nil {
		return nil, false
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, false
	}
	var rows []map[string]any
	if json.Unmarshal([]byte(out), &rows) != nil {
		var one map[string]any
		if json.Unmarshal([]byte(out), &one) != nil {
			return nil, false
		}
		rows = []map[string]any{one}
	}
	res := map[string][]fwRule{}
	for _, r := range rows {
		ip := strings.TrimPrefix(str(r["Name"]), "LocationFace block ")
		res[ip] = append(res[ip], fwRule{Enabled: strings.EqualFold(str(r["Enabled"]), "True")})
	}
	return res, true
}

func fwAddReal(ip string) error {
	for _, dir := range []string{"out", "in"} {
		if err := netsh("advfirewall", "firewall", "add", "rule", "name="+ruleName(ip), "dir="+dir, "action=block", "remoteip="+ip); err != nil {
			return err
		}
	}
	return nil
}

func fwRemoveReal(ip string) error {
	_, err := runPS(`Remove-NetFirewallRule -DisplayName '`+ruleName(ip)+`' -ErrorAction SilentlyContinue`, 30*time.Second)
	return err
}

func cleanIP(ip string) (string, error) {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return "", errors.New("это не IP-адрес")
	}
	return p.String(), nil
}

// blockIP blocks an address in both directions. Repeating it never piles up duplicate rules.
func blockIP(ip string, meta BlockInfo) error {
	ip, err := cleanIP(ip)
	if err != nil {
		return err
	}
	if ipScope(ip) != "public" {
		return errors.New("блокировать можно только внешний IP-адрес (не локальный и не служебный)")
	}
	if !requireAdmin() {
		return errors.New("для блокировки нужны права администратора — запустите программу от имени администратора")
	}
	_ = fwRemove(ip) // start clean
	if err := fwAdd(ip); err != nil {
		_ = fwRemove(ip) // never leave half of a block behind
		return fmt.Errorf("брандмауэр не принял правило: %v", err)
	}
	if rules, ok := fwList(); ok && len(rules[ip]) == 0 {
		return errors.New("правило не появилось в брандмауэре — блокировка не действует")
	}
	meta.IP, meta.At = ip, time.Now().UnixMilli()
	blkMu.Lock()
	loadBlocksLocked()
	blkInfo[ip] = &meta
	saveBlocksLocked()
	blkMu.Unlock()
	return nil
}

// unblockIP removes the rules and the record, and only reports success if the rules are really gone.
func unblockIP(ip string) error {
	ip, err := cleanIP(ip)
	if err != nil {
		return err
	}
	if !requireAdmin() {
		return errors.New("для разблокировки нужны права администратора — запустите программу от имени администратора")
	}
	if err := fwRemove(ip); err != nil {
		return fmt.Errorf("не удалось удалить правило: %v", err)
	}
	if rules, ok := fwList(); ok && len(rules[ip]) > 0 {
		return errors.New("правило осталось в брандмауэре — адрес всё ещё заблокирован; удалите его вручную в «Брандмауэр Защитника Windows в режиме повышенной безопасности»")
	}
	blkMu.Lock()
	loadBlocksLocked()
	delete(blkInfo, ip)
	saveBlocksLocked()
	blkMu.Unlock()
	return nil
}

func unblockAll() (done, failed int, firstErr error) {
	for _, r := range blocksSnapshot() {
		if err := unblockIP(r.IP); err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		} else {
			done++
		}
	}
	return
}

// blocksSnapshot joins our records with what the firewall really holds.
func blocksSnapshot() []BlockRow {
	rules, ok := fwList()
	blkMu.Lock()
	loadBlocksLocked()
	byIP := map[string]*BlockRow{}
	for ip, b := range blkInfo {
		byIP[ip] = &BlockRow{BlockInfo: *b, Known: true}
	}
	blkMu.Unlock()
	for ip, rs := range rules { // rules we never recorded (record lost, or created by an older version)
		if byIP[ip] == nil {
			byIP[ip] = &BlockRow{BlockInfo: BlockInfo{IP: ip, Why: "правило есть в брандмауэре, но программа не помнит, кто и когда его создал"}}
		}
		_ = rs
	}
	out := make([]BlockRow, 0, len(byIP))
	for ip, r := range byIP {
		rs := rules[ip]
		r.Rules = len(rs)
		off := 0
		for _, x := range rs {
			if !x.Enabled {
				off++
			}
		}
		switch {
		case !ok:
			r.State = "unknown"
		case len(rs) == 0:
			r.State = "missing"
		case off > 0:
			r.State = "disabled"
		default:
			r.State = "active"
		}
		if r.Host == "" && ipScope(ip) == "public" {
			r.Host = hostFor(ip)
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At > out[j].At
		}
		return out[i].IP < out[j].IP
	})
	return out
}
