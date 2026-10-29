package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Programs the user vouched for. Trust is tied to the file's size and modification
// time, so a program that gets replaced stops being trusted automatically.

type trustEntry struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mod   int64  `json:"mod"`
	Added int64  `json:"added"`
}

var (
	utMu   sync.Mutex
	utList = map[string]trustEntry{}
)

func trustedFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "LocationFace", "trusted.json")
}

func loadTrusted() {
	data, err := os.ReadFile(trustedFile())
	if err != nil {
		return
	}
	var l []trustEntry
	if json.Unmarshal(data, &l) != nil {
		return
	}
	utMu.Lock()
	for _, e := range l {
		utList[strings.ToLower(e.Path)] = e
	}
	utMu.Unlock()
}

func saveTrustedLocked() {
	var l []trustEntry
	for _, e := range utList {
		l = append(l, e)
	}
	sort.Slice(l, func(i, j int) bool { return l[i].Path < l[j].Path })
	data, _ := json.Marshal(l)
	_ = os.MkdirAll(filepath.Dir(trustedFile()), 0o755)
	_ = os.WriteFile(trustedFile(), data, 0o600)
}

func isUserTrusted(path string) bool {
	if path == "" {
		return false
	}
	utMu.Lock()
	e, ok := utList[strings.ToLower(path)]
	utMu.Unlock()
	if !ok {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.Size() == e.Size && st.ModTime().UnixMilli() == e.Mod
}

func trustProgram(path string) error {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return errors.New("файл не найден")
	}
	utMu.Lock()
	utList[strings.ToLower(path)] = trustEntry{Path: path, Size: st.Size(), Mod: st.ModTime().UnixMilli(), Added: time.Now().UnixMilli()}
	saveTrustedLocked()
	utMu.Unlock()
	removeIncidentsByExe(path)
	return nil
}

func untrustProgram(path string) {
	utMu.Lock()
	delete(utList, strings.ToLower(path))
	saveTrustedLocked()
	utMu.Unlock()
}

func trustedList() []trustEntry {
	utMu.Lock()
	defer utMu.Unlock()
	out := make([]trustEntry, 0, len(utList))
	for _, e := range utList {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Added > out[j].Added })
	return out
}

func removeIncidentsByExe(path string) {
	incMu.Lock()
	defer incMu.Unlock()
	keep := incs[:0]
	for _, x := range incs {
		if strings.EqualFold(x.Exe, path) {
			delete(incByKey, x.Key)
			continue
		}
		keep = append(keep, x)
	}
	incs = keep
	incDirty = true
}
