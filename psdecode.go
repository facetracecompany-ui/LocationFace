package main

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf16"
)

// PowerShell -EncodedCommand hides a script in base64 (UTF-16LE). Installers use it
// as often as malware does, so the verdict has to come from the script itself.

var reEncoded = regexp.MustCompile(`(?i)\s-(?:e|ec|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})"?`)

func decodePSCommand(cmd string) (string, bool) {
	m := reEncoded.FindStringSubmatch(cmd)
	if m == nil {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil || len(raw) < 4 || len(raw)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	s := string(utf16.Decode(u))
	// a real script is text: reject garbage that merely happened to decode
	printable := 0
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 0xFFFD) {
			printable++
		}
	}
	if len([]rune(s)) == 0 || float64(printable)/float64(len([]rune(s))) < 0.9 {
		return "", false
	}
	return s, true
}

var malScript = []struct{ pat, why string }{
	{"downloadstring", "скачивание и запуск кода из интернета (DownloadString)"},
	{"downloadfile", "скачивание файла (DownloadFile)"},
	{"invoke-webrequest", "загрузка из интернета (Invoke-WebRequest)"},
	{"iwr ", "загрузка из интернета (iwr)"},
	{"net.webclient", "сетевой клиент (Net.WebClient)"},
	{"start-bitstransfer", "скрытая загрузка (BITS)"},
	{"invoke-expression", "запуск строки как кода (Invoke-Expression)"},
	{"iex ", "запуск строки как кода (iex)"},
	{"iex(", "запуск строки как кода (iex)"},
	{"frombase64string", "ещё один слой кодирования (FromBase64String)"},
	{"add-mppreference", "изменение исключений Защитника Windows"},
	{"set-mppreference", "изменение настроек Защитника Windows"},
	{"disablerealtimemonitoring", "отключение защиты Защитника Windows"},
	{"amsiinitfailed", "обход антивирусной проверки (AMSI)"},
	{"reflection.assembly", "загрузка кода в память (Reflection.Assembly)"},
	{"virtualalloc", "выделение памяти под вредоносный код (VirtualAlloc)"},
	{"mimikatz", "кража паролей (Mimikatz)"},
	{"-bypass amsi", "обход антивирусной проверки"},
}

// maliciousScript returns what is wrong with a decoded script, or "" if it looks ordinary.
func maliciousScript(script string) string {
	low := strings.ToLower(script)
	for _, p := range malScript {
		if strings.Contains(low, p.pat) {
			return p.why
		}
	}
	return ""
}
