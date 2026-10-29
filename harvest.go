package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// What can be learned about outgoing data from plain-text protocols:
// request line, upload file names, form field names. Values are never kept.

var (
	reFile = regexp.MustCompile(`(?i)filename\*?=(?:utf-8'')?"?([^";\r\n]+)"?`)
	reCT   = regexp.MustCompile(`(?i)content-type:\s*([^\r\n;]+)`)
	reDisp = regexp.MustCompile(`(?i)content-disposition:\s*form-data;\s*name="([^"]+)"`)
	reUA   = regexp.MustCompile(`(?i)\r\nuser-agent:\s*([^\r\n]+)`)
	reHost = regexp.MustCompile(`(?i)\r\nhost:\s*([^\r\n]+)`)
	reRcpt = regexp.MustCompile(`(?i)rcpt to:\s*<?([^>\r\n ]+)`)
	reStor = regexp.MustCompile(`(?i)^(stor|appe)\s+([^\r\n]+)`)
)

var httpMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}

func addUniq(list []string, s string, max int) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, s)
}

// maskQuery keeps parameter names and hides their values: /a?token=abc -> /a?token=…
func maskQuery(p string) string {
	i := strings.IndexByte(p, '?')
	if i < 0 {
		return p
	}
	var keys []string
	for _, kv := range strings.Split(p[i+1:], "&") {
		if k, _, _ := strings.Cut(kv, "="); k != "" {
			keys = append(keys, k+"=…")
		}
	}
	return p[:i] + "?" + strings.Join(keys, "&")
}

func harvest(pk *Packet, p []byte) {
	if len(p) < 4 {
		return
	}
	s := string(p[:min(len(p), 2000)])

	for _, m := range httpMethods {
		if !strings.HasPrefix(s, m+" ") {
			continue
		}
		line, _, _ := strings.Cut(s, "\r\n")
		f := strings.Fields(line)
		if len(f) < 2 {
			break
		}
		host := ""
		if h := reHost.FindStringSubmatch(s); h != nil {
			host = strings.TrimSpace(h[1])
		}
		path, query, hasQ := strings.Cut(f[1], "?")
		pk.Req = m + " " + host + path
		if hasQ {
			for _, kv := range strings.Split(query, "&") {
				if k, _, _ := strings.Cut(kv, "="); k != "" && len(k) < 40 {
					pk.Fields = addUniq(pk.Fields, "параметр адреса: "+k, 25)
				}
			}
		}
		if u := reUA.FindStringSubmatch(s); u != nil {
			pk.UA = strings.TrimSpace(u[1])
			if len(pk.UA) > 120 {
				pk.UA = pk.UA[:120]
			}
		}
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 && strings.Contains(strings.ToLower(s[:i]), "application/x-www-form-urlencoded") {
			for _, kv := range strings.Split(s[i+4:], "&") {
				if k, _, _ := strings.Cut(kv, "="); k != "" && len(k) < 40 && isPrintable(k) {
					pk.Fields = addUniq(pk.Fields, "поле формы: "+k, 25)
				}
			}
		}
		break
	}

	// multipart upload: file names and field names
	for _, loc := range reFile.FindAllStringSubmatchIndex(s, 5) {
		name := strings.TrimSpace(s[loc[2]:loc[3]])
		typ := ""
		if end := min(len(s), loc[1]+300); loc[1] < end {
			if t := reCT.FindStringSubmatch(s[loc[1]:end]); t != nil {
				typ = strings.TrimSpace(t[1])
			}
		}
		if name != "" {
			pk.UpFiles = append(pk.UpFiles, UpFile{Name: filepath.Base(strings.ReplaceAll(name, `\`, "/")), Type: typ})
		}
	}
	for _, d := range reDisp.FindAllStringSubmatch(s, 8) {
		pk.Fields = addUniq(pk.Fields, "поле формы: "+d[1], 25)
	}

	// FTP upload and mail recipients
	if m := reStor.FindStringSubmatch(s); m != nil {
		pk.UpFiles = append(pk.UpFiles, UpFile{Name: strings.TrimSpace(m[2]), Type: "FTP " + strings.ToUpper(m[1])})
	}
	for _, r := range reRcpt.FindAllStringSubmatch(s, 5) {
		pk.Fields = addUniq(pk.Fields, "получатель письма: "+r[1], 25)
	}
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
