package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Trust model. A transfer is only worth an alarm when the program is not who
// it should be for that destination, or when it touches secrets it does not own.
// Sending a file to Telegram with the Telegram client is expected traffic.

type Service struct {
	Name       string
	Category   string
	Domains    []string // suffixes
	CIDRs      []string
	Publishers []string // substrings of the signer name that make a client "official"
	Exfil      bool     // channel often used to move stolen data out
	Note       string
	nets       []*net.IPNet
}

var services = []*Service{
	{Name: "Telegram", Category: "мессенджер", Domains: []string{"telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org", "tdesktop.com"},
		CIDRs:      []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.56.0/22", "95.161.64.0/20", "185.76.151.0/24"},
		Publishers: []string{"telegram"}, Exfil: true, Note: "боты Telegram"},
	{Name: "Discord", Category: "мессенджер", Domains: []string{"discord.com", "discordapp.com", "discord.gg", "discord.media", "discordapp.net", "discordstatus.com"},
		Publishers: []string{"discord"}, Exfil: true, Note: "вебхуки Discord"},
	{Name: "WhatsApp", Category: "мессенджер", Domains: []string{"whatsapp.com", "whatsapp.net", "wa.me"}, Publishers: []string{"whatsapp", "meta platforms"}},
	{Name: "Viber", Category: "мессенджер", Domains: []string{"viber.com", "vibercdn.com"}, Publishers: []string{"viber"}},
	{Name: "Google", Category: "поиск и сервисы", Domains: []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "ytimg.com",
		"googlevideo.com", "1e100.net", "gvt1.com", "gvt2.com", "google-analytics.com", "doubleclick.net", "googlesyndication.com", "app-measurement.com", "withgoogle.com", "googletagmanager.com"},
		Publishers: []string{"google"}},
	{Name: "Microsoft", Category: "система и сервисы", Domains: []string{"microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "office365.com",
		"outlook.com", "bing.com", "msn.com", "azure.com", "azureedge.net", "msedge.net", "microsoftonline.com", "sharepoint.com", "onedrive.com", "skype.com",
		"xboxlive.com", "msftconnecttest.com", "windows.net", "msauth.net", "msftncsi.com", "visualstudio.com", "vscode-cdn.net", "trafficmanager.net", "digicert.com"},
		Publishers: []string{"microsoft"}},
	{Name: "Apple", Category: "сервисы", Domains: []string{"apple.com", "icloud.com", "mzstatic.com", "apple-dns.net"}, Publishers: []string{"apple"}},
	{Name: "Cloudflare", Category: "CDN", Domains: []string{"cloudflare.com", "cloudflare-dns.com", "one.one.one.one", "cloudflarestorage.com"}, Publishers: []string{"cloudflare"}},
	{Name: "Amazon / CDN", Category: "CDN и облако", Domains: []string{"amazonaws.com", "cloudfront.net", "awsstatic.com", "akamaiedge.net", "akamai.net",
		"akamaized.net", "akamaihd.net", "fastly.net", "edgecastcdn.net", "azurefd.net", "cdn77.org", "stackpathcdn.com", "b-cdn.net"}, Publishers: []string{"amazon"}},
	{Name: "Яндекс", Category: "поиск и сервисы", Domains: []string{"yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net", "yandexcloud.net", "yandex.by", "yandex.kz"},
		Publishers: []string{"yandex"}},
	{Name: "VK / Mail.ru", Category: "соцсети", Domains: []string{"vk.com", "userapi.com", "vkuser.net", "mail.ru", "vk-cdn.net", "vkontakte.ru", "okcdn.ru", "ok.ru"},
		Publishers: []string{"vk ", "vkontakte", "mail.ru"}},
	{Name: "Steam / Valve", Category: "игры", Domains: []string{"steampowered.com", "steamcontent.com", "steamstatic.com", "valve.net", "steamserver.net",
		"steamcommunity.com", "valvesoftware.com", "steam-chat.com"}, Publishers: []string{"valve"}},
	{Name: "Epic Games", Category: "игры", Domains: []string{"epicgames.com", "unrealengine.com", "epicgames.dev"}, Publishers: []string{"epic games"}},
	{Name: "GitHub", Category: "разработка", Domains: []string{"github.com", "githubusercontent.com", "githubassets.com", "github.io", "githubcopilot.com"}, Publishers: []string{"github"}},
	{Name: "NVIDIA", Category: "драйверы", Domains: []string{"nvidia.com", "nvidiagrid.net", "geforce.com"}, Publishers: []string{"nvidia"}},
	{Name: "JetBrains", Category: "разработка", Domains: []string{"jetbrains.com", "jb.gg", "jetbrains.ai"}, Publishers: []string{"jetbrains"}},
	{Name: "OpenAI / Anthropic", Category: "ИИ", Domains: []string{"openai.com", "chatgpt.com", "oaistatic.com", "anthropic.com", "claude.ai", "claude.com"}, Publishers: []string{"openai", "anthropic"}},
	{Name: "Mozilla", Category: "браузер", Domains: []string{"mozilla.org", "mozilla.net", "firefox.com", "mozgcp.net"}, Publishers: []string{"mozilla"}},
	{Name: "Adobe", Category: "сервисы", Domains: []string{"adobe.com", "adobe.io", "adobelogin.com", "typekit.net", "adobedtm.com", "adobe.net"}, Publishers: []string{"adobe"}},
	{Name: "Dropbox", Category: "облако", Domains: []string{"dropbox.com", "dropboxstatic.com", "dropboxapi.com"}, Publishers: []string{"dropbox"}},
	{Name: "Mega", Category: "облако", Domains: []string{"mega.nz", "mega.io"}, Publishers: []string{"mega limited"}, Exfil: true, Note: "анонимные файлообменники"},

	// channels without an "official client": only browsers should talk to them
	{Name: "Анонимный файлообменник", Category: "файлообменник", Exfil: true, Note: "анонимные файлообменники",
		Domains: []string{"anonfiles.com", "gofile.io", "file.io", "transfer.sh", "0x0.st", "catbox.moe", "temp.sh", "filebin.net", "pixeldrain.com", "bashupload.com", "uguu.se", "send.vis.ee", "krakenfiles.com"}},
	{Name: "Pastebin и подобные", Category: "текстовый обмен", Exfil: true, Note: "сервисы вставки текста",
		Domains: []string{"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "controlc.com", "rentry.co", "dpaste.org"}},
	{Name: "Туннель / динамический DNS", Category: "туннель", Exfil: true, Note: "туннели и динамический DNS",
		Domains: []string{"ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "serveo.net", "trycloudflare.com", "playit.gg", "duckdns.org", "no-ip.com",
			"ddns.net", "hopto.org", "zapto.org", "serveousercontent.com", "localtunnel.me", "loca.lt", "pagekite.me", "webhook.site", "requestbin.com", "pipedream.net", "interact.sh", "oast.fun", "oast.pro", "oast.live"}},
}

var browserExes = map[string]bool{"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "browser.exe": true, "opera.exe": true,
	"brave.exe": true, "vivaldi.exe": true, "chromium.exe": true, "yandex.exe": true}

var trustedPublishers = []string{"microsoft", "google", "mozilla", "yandex", "valve", "nvidia", "intel", "advanced micro devices", "amd", "realtek",
	"apple", "adobe", "jetbrains", "discord", "telegram", "openai", "anthropic", "github", "dropbox", "oracle", "logitech", "epic games",
	"riot games", "mullvad", "cloudflare", "docker", "python software foundation", "node.js", "opera", "brave", "vivaldi", "zoom", "slack",
	"kaspersky", "eset", "avast", "bitdefender", "malwarebytes", "norton", "mcafee", "dr.web", "msi", "micro-star", "asus", "dell", "lenovo", "hewlett", "steelseries"}

func init() {
	for _, s := range services {
		for _, c := range s.CIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				s.nets = append(s.nets, n)
			}
		}
	}
}

func serviceFor(host, ip string) *Service {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host != "" {
		for _, s := range services {
			for _, d := range s.Domains {
				if host == d || strings.HasSuffix(host, "."+d) {
					return s
				}
			}
		}
	}
	if p := net.ParseIP(ip); p != nil {
		for _, s := range services {
			for _, n := range s.nets {
				if n.Contains(p) {
					return s
				}
			}
		}
	}
	return nil
}

func exeBase(m *ProcMeta) string {
	if m == nil {
		return ""
	}
	if m.Exe != "" {
		return strings.ToLower(filepath.Base(m.Exe))
	}
	return strings.ToLower(m.Name)
}

func signerHas(m *ProcMeta, parts []string) bool {
	if m == nil || m.Sig != "signed" {
		return false
	}
	s := strings.ToLower(m.Signer)
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// officialActor: is this program the real client for that service?
func officialActor(s *Service, m *ProcMeta) bool {
	return s != nil && signerHas(m, s.Publishers)
}

var tunnelNames = []string{"clash", "v2ray", "xray", "sing-box", "singbox", "hiddify", "amnezia", "wireguard", "openvpn", "nekoray", "nekobox",
	"outline", "shadowsocks", "psiphon", "mullvad", "protonvpn", "nordvpn", "surfshark", "expressvpn", "warp-svc", "tailscale", "zerotier",
	"lantern", "windscribe", "hysteria", "mihomo", "tun2socks", "vpn"}
var tunnelFiles = []string{"wintun.dll", "wireguard.dll", "tun2socks.exe", "openvpn.exe", "tap-windows.exe"}
var tunnelDirs sync.Map // directory -> bool

// isTunnelTool recognises VPN and proxy clients: they carry other programs' traffic,
// so big transfers to one address are normal for them. Works by name and by the
// tunnel driver (wintun.dll and similar) shipped next to the program.
func isTunnelTool(m *ProcMeta) bool {
	if m == nil || m.Score >= 4 {
		return false
	}
	b := exeBase(m)
	if b == "tor.exe" || strings.HasPrefix(b, "happ") {
		return true
	}
	for _, n := range tunnelNames {
		if strings.Contains(b, n) {
			return true
		}
	}
	if m.Exe == "" {
		return false
	}
	dir := filepath.Dir(m.Exe)
	if v, ok := tunnelDirs.Load(dir); ok {
		return v.(bool)
	}
	found := false
	for _, f := range tunnelFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			found = true
			break
		}
	}
	tunnelDirs.Store(dir, found)
	return found
}

func underProgramFiles(p string) bool {
	l := strings.ToLower(p)
	return strings.HasPrefix(l, `c:\program files\`) || strings.HasPrefix(l, `c:\program files (x86)\`) || strings.Contains(l, `\windowsapps\`)
}

// actorKind classifies who is sending: browser | vendor | tunnel | signed | unsigned | unknown.
func actorKind(m *ProcMeta) string {
	switch {
	case m == nil || m.Sig == "pending" || m.Sig == "":
		return "unknown"
	case m.Sig == "signed" && browserExes[exeBase(m)]:
		return "browser"
	case signerHas(m, trustedPublishers):
		return "vendor"
	case isTunnelTool(m):
		return "tunnel"
	case m.Sig == "signed":
		return "signed"
	case m.Sig == "unknown" && m.Exe == "":
		return "unknown"
	}
	return "unsigned"
}

// actorExpected: traffic from this actor to this address is nothing special.
func actorExpected(m *ProcMeta, host, ip string) bool {
	if m != nil && isUserTrusted(m.Exe) {
		return true
	}
	switch actorKind(m) {
	case "browser", "vendor", "tunnel":
		return true
	}
	return officialActor(serviceFor(host, ip), m)
}

type Verdict struct {
	Level   string   `json:"level"` // ok | warn | bad
	Label   string   `json:"label"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}

// judge decides whether a transfer deserves attention.
func judge(m *ProcMeta, svc *Service, in, out uint64, named bool, foreign []FileRef) Verdict {
	v := Verdict{Level: "ok"}
	if m != nil && isUserTrusted(m.Exe) {
		v.Label = "Вы отметили эту программу как доверенную"
		return v
	}
	kind := actorKind(m)
	name := "процесс"
	if m != nil {
		name = m.Name
	}
	official := officialActor(svc, m)
	expected := official
	switch {
	case official:
		v.Label = fmt.Sprintf("Ожидаемо: %s → %s", name, svc.Name)
	case kind == "browser":
		expected = true
		v.Label = "Браузер: отправляет то, что вы делаете сами (формы, загрузки на сайты)"
	case kind == "vendor":
		expected = true
		v.Label = "Известный производитель: " + m.Signer
	case kind == "tunnel":
		expected = true
		v.Label = "VPN или прокси-клиент: пропускает через себя трафик других программ, поэтому большие отправки на один адрес для него нормальны"
	case kind == "signed":
		v.Label = "Подписанная программа: " + m.Signer
	case kind == "unsigned":
		v.Label = "Программа без цифровой подписи"
	default:
		v.Label = "Программа неизвестна (уже завершилась или ещё проверяется)"
	}
	add := func(n int, why string) { v.Score += n; v.Reasons = append(v.Reasons, why) }

	if svc != nil && svc.Exfil && !official && kind != "browser" {
		add(3, fmt.Sprintf("«%s» — канал, который часто используют для вывода украденных данных (%s), а отправляет не официальный клиент", svc.Name, svc.Note))
	}
	if kind == "unsigned" {
		// theft is one-sided: a program that also receives about as much (stream, call, game, sync) is just talking
		oneSided := out >= 3*in
		if svc == nil && out >= 1<<20 && oneSided {
			add(2, "Программа без подписи отправила "+fmtBytes(out)+" на неизвестный адрес, получив в ответ только "+fmtBytes(in))
		}
		if svc == nil && out >= 20<<20 && oneSided {
			add(1, "Большой объём отправки (больше 20 МБ)")
		}
		if !named && out >= 100<<10 && oneSided {
			add(1, "Адрес без имени сайта — обычные программы ходят по доменам")
		}
		if m != nil && m.Score >= 4 {
			add(2, "Сама программа выглядит подозрительно: "+strings.Join(m.Reasons, "; "))
		}
	}
	if kind == "signed" && svc == nil && out >= 200<<20 {
		add(1, "Очень большой объём отправки ("+fmtBytes(out)+")")
	}
	if len(foreign) > 0 {
		seen := map[string]bool{}
		for _, f := range foreign {
			if !seen[f.Sens] {
				seen[f.Sens] = true
				add(4, fmt.Sprintf("Процесс открыл чужой секретный файл: %s (%s) — так работают программы-воры", f.Sens, filepath.Base(f.Path)))
			}
		}
	}
	if expected && len(foreign) == 0 {
		v.Score, v.Reasons = 0, nil // official or well-known traffic is not an alarm
	}
	if kind == "unsigned" && m != nil && v.Score > 0 && len(foreign) == 0 && underProgramFiles(m.Exe) && m.Score < 3 {
		v.Score--
		v.Reasons = append(v.Reasons, "Программа установлена в Program Files — это немного снижает подозрение")
	}
	switch {
	case v.Score >= 4:
		v.Level = "bad"
	case v.Score >= 2:
		v.Level = "warn"
	}
	return v
}
