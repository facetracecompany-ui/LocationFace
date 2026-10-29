package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Download struct {
	Name     string   `json:"name"`
	Path     string   `json:"path"`
	Size     int64    `json:"size"`
	Modified int64    `json:"modified"`
	Ext      string   `json:"ext"`
	Zone     string   `json:"zone"`    // "Интернет", "Локальная сеть", ""
	HostURL  string   `json:"hostUrl"` // direct download URL
	Referrer string   `json:"referrer"`
	Sig      string   `json:"sig"`
	Signer   string   `json:"signer"`
	SHA256   string   `json:"sha256"`
	Score    int      `json:"score"`
	Level    string   `json:"level"`
	Reasons  []string `json:"reasons"`
}

var (
	riskyExt = map[string]bool{".exe": true, ".msi": true, ".scr": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true,
		".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".lnk": true, ".dll": true, ".jar": true,
		".iso": true, ".img": true, ".docm": true, ".xlsm": true, ".pptm": true, ".com": true, ".pif": true, ".cpl": true}
	scriptExt = map[string]bool{".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
		".wsf": true, ".hta": true, ".scr": true, ".pif": true, ".com": true, ".cpl": true}
	signExt = map[string]bool{".exe": true, ".dll": true, ".msi": true, ".scr": true, ".sys": true, ".ocx": true, ".cpl": true}
	docExt  = map[string]bool{".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".txt": true, ".jpg": true,
		".png": true, ".jpeg": true, ".mp3": true, ".mp4": true, ".zip": true}

	dlMu    sync.Mutex
	dlHash  = map[string]string{}
	zoneTxt = map[string]string{"0": "Мой компьютер", "1": "Локальная сеть", "2": "Доверенные сайты", "3": "Интернет", "4": "Ограниченные сайты"}
)

func parseZone(path string) (zone, host, ref string) {
	data, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ZoneId="):
			id := strings.TrimPrefix(line, "ZoneId=")
			if t, ok := zoneTxt[id]; ok {
				zone = t
			} else {
				zone = "Зона " + id
			}
		case strings.HasPrefix(line, "HostUrl="):
			host = strings.TrimPrefix(line, "HostUrl=")
		case strings.HasPrefix(line, "ReferrerUrl="):
			ref = strings.TrimPrefix(line, "ReferrerUrl=")
		}
	}
	return
}

func downloadsScan() []Download {
	home, _ := os.UserHomeDir()
	roots := []string{
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "OneDrive", "Desktop"),
		filepath.Join(home, "OneDrive", "Рабочий стол"),
		os.TempDir(),
	}
	cutoff := time.Now().AddDate(0, 0, -45)
	var out []Download
	hashed := 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			depth := strings.Count(strings.TrimPrefix(p, root), string(os.PathSeparator))
			if d.IsDir() {
				if depth >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			if len(out) >= 400 {
				return filepath.SkipAll
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(cutoff) {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			zone, host, ref := parseZone(p)
			inTemp := strings.EqualFold(root, os.TempDir())
			// downloads/desktop: everything from the internet or any risky type; temp: only risky types
			if !riskyExt[ext] && (zone == "" || inTemp) && !(ext == ".zip" && zone != "") {
				return nil
			}
			dl := Download{Name: d.Name(), Path: p, Size: info.Size(), Modified: info.ModTime().UnixMilli(), Ext: ext,
				Zone: zone, HostURL: host, Referrer: ref}
			if signExt[ext] {
				s := getSig(p)
				dl.Sig, dl.Signer = s.Status, s.Signer
			}
			if (riskyExt[ext] || zone == "Интернет") && info.Size() < 200<<20 {
				k := p + "|" + info.ModTime().String()
				dlMu.Lock()
				h, ok := dlHash[k]
				dlMu.Unlock()
				if !ok && hashed < 25 {
					hashed++
					h = fileSHA256(p)
					dlMu.Lock()
					dlHash[k] = h
					dlMu.Unlock()
				}
				dl.SHA256 = h
			}
			scoreDownload(&dl)
			out = append(out, dl)
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Modified > out[j].Modified
	})
	return out
}

func scoreDownload(d *Download) {
	add := func(n int, why string) { d.Score += n; d.Reasons = append(d.Reasons, why) }
	internet := d.Zone == "Интернет"
	// "invoice.pdf.exe" — an executable pretending to be a document
	base := strings.ToLower(strings.TrimSuffix(d.Name, d.Ext))
	if riskyExt[d.Ext] && docExt[strings.ToLower(filepath.Ext(base))] {
		add(5, "Двойное расширение: файл выдаёт себя за документ, но запускается как программа")
	}
	switch {
	case d.Ext == ".js" && internet:
		add(1, "JavaScript-файл из интернета (если это не ваш проект — не запускайте двойным щелчком)")
	case scriptExt[d.Ext] && internet:
		add(3, "Скрипт, скачанный из интернета")
	case (d.Ext == ".exe" || d.Ext == ".msi") && internet && d.Sig == "unsigned":
		add(3, "Скачанная программа без цифровой подписи")
	case (d.Ext == ".exe" || d.Ext == ".msi") && d.Sig == "tampered":
		add(6, "Подпись нарушена — файл изменён")
	case (d.Ext == ".exe" || d.Ext == ".msi") && d.Sig == "unsigned":
		add(2, "Программа без цифровой подписи")
	case (d.Ext == ".iso" || d.Ext == ".img" || d.Ext == ".lnk") && internet:
		add(2, "Образ диска или ярлык из интернета — часто используется для обхода защиты")
	case (d.Ext == ".docm" || d.Ext == ".xlsm" || d.Ext == ".pptm") && internet:
		add(2, "Документ с макросами из интернета")
	}
	if d.HostURL != "" && strings.HasPrefix(strings.ToLower(d.HostURL), "http://") && riskyExt[d.Ext] {
		add(1, "Скачан по незащищённому http://")
	}
	d.Level = levelOf(d.Score)
}
