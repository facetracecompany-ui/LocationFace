package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

type Finding struct {
	Group  string   `json:"group"`
	Title  string   `json:"title"`
	Status string   `json:"status"` // ok | warn | bad | info
	Detail string   `json:"detail"`
	Fix    string   `json:"fix,omitempty"`
	Items  []string `json:"items,omitempty"`
}

type SecReport struct {
	Score     int       `json:"score"`
	Grade     string    `json:"grade"`
	At        int64     `json:"at"`
	Findings  []Finding `json:"findings"`
	Scanning  bool      `json:"scanning"`
	DurationM int64     `json:"durationMs"`
}

var (
	secMu   sync.Mutex // serialises scans
	secLast *SecReport
	secBusy bool
	secData sync.RWMutex
)

func securityScan(refresh bool) *SecReport {
	secData.RLock()
	last := secLast
	secData.RUnlock()
	if last != nil && !refresh && time.Since(time.UnixMilli(last.At)) < 90*time.Second {
		return last
	}
	secMu.Lock()
	defer secMu.Unlock()
	secData.RLock()
	last = secLast
	secData.RUnlock()
	if last != nil && time.Since(time.UnixMilli(last.At)) < 5*time.Second {
		return last
	}
	secData.Lock()
	secBusy = true
	secData.Unlock()
	t0 := time.Now()

	var (
		mu  sync.Mutex
		all []Finding
		wg  sync.WaitGroup
	)
	run := func(f func() []Finding) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := f()
			mu.Lock()
			all = append(all, r...)
			mu.Unlock()
		}()
	}
	run(checkDefender)
	run(checkFirewall)
	run(checkAccounts)
	run(checkRegistrySettings)
	run(checkHosts)
	run(checkSecureBoot)
	run(checkLive)
	run(checkAutoruns)
	run(checkDownloads)
	wg.Wait()

	order := map[string]int{"bad": 0, "warn": 1, "info": 2, "ok": 3}
	for i := 1; i < len(all); i++ { // stable insertion sort by severity
		for j := i; j > 0 && order[all[j].Status] < order[all[j-1].Status]; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	score := 100
	for _, f := range all {
		switch f.Status {
		case "bad":
			score -= 15
		case "warn":
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	grade := "Отлично"
	switch {
	case score < 50:
		grade = "Опасно — есть серьёзные проблемы"
	case score < 75:
		grade = "Есть что исправить"
	case score < 90:
		grade = "Хорошо"
	}
	rep := &SecReport{Score: score, Grade: grade, At: time.Now().UnixMilli(), Findings: all, DurationM: time.Since(t0).Milliseconds()}
	secData.Lock()
	secLast, secBusy = rep, false
	secData.Unlock()
	return rep
}

// ---------------------------------------------------------------- checks

func checkDefender() []Finding {
	var out []Finding
	const g = "Антивирус"
	av := psJSON(`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState | ConvertTo-Json -Compress`, 30*time.Second)
	var names []string
	enabled := false
	for _, a := range av {
		st, _ := a["productState"].(float64)
		on := int(st)&0x1000 != 0
		if on {
			enabled = true
		}
		s := str(a["displayName"])
		if on {
			s += " — включён"
		} else {
			s += " — выключен"
		}
		names = append(names, s)
	}
	if len(av) == 0 {
		out = append(out, Finding{g, "Антивирус не обнаружен", "bad", "Windows не видит ни одной антивирусной программы.", "Включите Защитник Windows: Параметры → Конфиденциальность и защита → Безопасность Windows.", nil})
	} else if !enabled {
		out = append(out, Finding{g, "Антивирус выключен", "bad", "Установлен антивирус, но защита в реальном времени отключена.", "Включите защиту в реальном времени в Безопасности Windows.", names})
	} else {
		out = append(out, Finding{g, "Антивирус работает", "ok", "Защита включена.", "", names})
	}

	mp := psJSON(`Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected,AntivirusEnabled | ConvertTo-Json -Compress`, 30*time.Second)
	if len(mp) > 0 {
		m := mp[0]
		if v, ok := m["RealTimeProtectionEnabled"].(bool); ok && !v && enabled {
			out = append(out, Finding{g, "Защита Windows в реальном времени выключена", "warn", "Если у вас нет стороннего антивируса, компьютер не защищён.", "Включите в Безопасности Windows → Защита от вирусов и угроз.", nil})
		}
		if age, ok := m["AntivirusSignatureAge"].(float64); ok && age > 7 {
			out = append(out, Finding{g, "Базы Защитника устарели", "warn", fmt.Sprintf("Последнее обновление баз было %d дн. назад.", int(age)), "Обновите: Безопасность Windows → Защита от вирусов → Обновления защиты.", nil})
		}
		if v, ok := m["IsTamperProtected"].(bool); ok && !v {
			out = append(out, Finding{g, "Защита от изменений отключена", "info", "Tamper Protection не позволяет вирусам отключать Защитника.", "Включите в Безопасности Windows → Параметры защиты от вирусов.", nil})
		}
	}

	th := psJSON(`Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive } | Select-Object ThreatName,SeverityID | ConvertTo-Json -Compress`, 30*time.Second)
	if len(th) > 0 {
		var items []string
		for _, t := range th {
			items = append(items, str(t["ThreatName"]))
		}
		out = append(out, Finding{g, "Защитник нашёл активные угрозы", "bad", fmt.Sprintf("Найдено угроз: %d.", len(th)), "Откройте Безопасность Windows → Защита от вирусов → Журнал защиты и удалите угрозы.", items})
	} else if len(mp) > 0 {
		out = append(out, Finding{g, "Активных угроз нет", "ok", "Защитник Windows не сообщает об активных угрозах.", "", nil})
	}

	recordDefenderIncidents()
	ex := psJSON(`$p=Get-MpPreference -ErrorAction SilentlyContinue; if($p){ [pscustomobject]@{Path=@($p.ExclusionPath);Proc=@($p.ExclusionProcess);Ext=@($p.ExclusionExtension)} | ConvertTo-Json -Compress -Depth 3 }`, 30*time.Second)
	if len(ex) > 0 {
		var items []string
		for _, k := range []string{"Path", "Proc", "Ext"} {
			if l, ok := ex[0][k].([]any); ok {
				for _, v := range l {
					if s := str(v); s != "" && !strings.HasPrefix(s, "N/A") {
						items = append(items, s)
					}
				}
			}
		}
		if len(items) > 0 {
			out = append(out, Finding{g, "У Защитника есть исключения", "warn", "Эти пути, процессы и расширения Защитник не проверяет. Вирусы часто добавляют себя сюда. Убедитесь, что всё в списке добавили вы.", "Безопасность Windows → Защита от вирусов → Управление настройками → Исключения.", items})
		} else {
			out = append(out, Finding{g, "Исключений в Защитнике нет", "ok", "Защитник проверяет всё.", "", nil})
		}
	}
	return out
}

func checkFirewall() []Finding {
	const g = "Сеть"
	fw := psJSON(`Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress`, 30*time.Second)
	if len(fw) == 0 {
		return nil
	}
	var off []string
	for _, p := range fw {
		if e, ok := p["Enabled"].(bool); ok && !e {
			off = append(off, str(p["Name"]))
		} else if n, ok := p["Enabled"].(float64); ok && n == 0 {
			off = append(off, str(p["Name"]))
		}
	}
	if len(off) > 0 {
		return []Finding{{g, "Брандмауэр выключен", "bad", "Отключены профили: " + strings.Join(off, ", ") + ". Приложения могут принимать подключения без фильтрации.", "Панель управления → Брандмауэр Защитника Windows → Включение и отключение.", nil}}
	}
	return []Finding{{g, "Брандмауэр включён", "ok", "Все профили защищены.", "", nil}}
}

func checkAccounts() []Finding {
	const g = "Учётные записи"
	var out []Finding
	us := psJSON(`Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress`, 30*time.Second)
	for _, u := range us {
		if e, _ := u["Enabled"].(bool); e && strings.EqualFold(str(u["Name"]), "Guest") {
			out = append(out, Finding{g, "Включена гостевая учётная запись", "warn", "Учётная запись Guest позволяет войти без пароля.", "Отключите: lusrmgr.msc → Пользователи → Гость.", nil})
		}
	}
	ad := psJSON(`Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name | ConvertTo-Json -Compress`, 30*time.Second)
	if len(ad) > 0 {
		var items []string
		for _, a := range ad {
			items = append(items, str(a["Name"]))
		}
		st := "ok"
		d := "Администраторов немного."
		if len(ad) > 3 {
			st, d = "warn", "Администраторов много — лишние права облегчают работу вирусам."
		}
		out = append(out, Finding{g, "Администраторы компьютера", st, d, "", items})
	}
	return out
}

func regDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

func checkRegistrySettings() []Finding {
	var out []Finding
	if v, ok := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); ok && v == 0 {
		out = append(out, Finding{"Система", "Контроль учётных записей (UAC) отключён", "bad", "Программы получают права администратора без запроса.", "Панель управления → Учётные записи → Изменение параметров UAC.", nil})
	} else if ok {
		out = append(out, Finding{"Система", "UAC включён", "ok", "Запросы повышения прав работают.", "", nil})
	}
	if v, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); ok && v == 0 {
		out = append(out, Finding{"Сеть", "Удалённый рабочий стол (RDP) включён", "warn", "К компьютеру можно подключиться по сети. Если он доступен из интернета — его активно перебирают боты.", "Если RDP не нужен: Параметры → Система → Удалённый рабочий стол → Выкл.", nil})
	}
	if v, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok && v == 1 {
		out = append(out, Finding{"Сеть", "Включён устаревший протокол SMBv1", "bad", "Через SMBv1 распространялись WannaCry и другие черви.", "Отключите компонент «Поддержка общего доступа к файлам SMB 1.0» в «Включение или отключение компонентов Windows».", nil})
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE); err == nil {
		en, _, _ := k.GetIntegerValue("ProxyEnable")
		srv, _, _ := k.GetStringValue("ProxyServer")
		pac, _, _ := k.GetStringValue("AutoConfigURL")
		k.Close()
		if en == 1 && srv != "" {
			out = append(out, Finding{"Сеть", "В Windows включён прокси-сервер", "warn", "Весь трафик браузеров идёт через " + srv + ". Вредоносные программы подменяют прокси, чтобы перехватывать данные.", "Параметры → Сеть и Интернет → Прокси. Если вы его не настраивали — отключите.", nil})
		}
		if pac != "" {
			out = append(out, Finding{"Сеть", "Задан скрипт автонастройки прокси", "warn", "Адрес скрипта: " + pac + ". Если вы его не настраивали, это может быть признаком перехвата трафика.", "Параметры → Сеть и Интернет → Прокси → Использовать сценарий настройки.", nil})
		}
		if en != 1 && pac == "" {
			out = append(out, Finding{"Сеть", "Прокси не используется", "ok", "Трафик идёт напрямую.", "", nil})
		}
	}
	return out
}

func checkHosts() []Finding {
	const g = "Сеть"
	data, err := os.ReadFile(os.Getenv("SystemRoot") + `\System32\drivers\etc\hosts`)
	if err != nil {
		return nil
	}
	var items []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		if len(f) >= 2 && (f[1] == "localhost" || f[1] == "localhost.localdomain") && (f[0] == "127.0.0.1" || f[0] == "::1") {
			continue
		}
		items = append(items, line)
	}
	if len(items) > 0 {
		detail := fmt.Sprintf("Записей: %d. Через hosts вирусы перенаправляют сайты банков и антивирусов на подставные адреса.", len(items))
		for _, it := range items {
			l := strings.ToLower(it)
			if strings.Contains(l, "adobe") || strings.Contains(l, "licen") || strings.Contains(l, "activat") || strings.Contains(l, "genuine") {
				detail += " Часть записей блокирует серверы проверки лицензий — так делают «активаторы» взломанных программ; именно через них часто попадают трояны."
				break
			}
		}
		return []Finding{{g, "Файл hosts содержит записи", "warn", detail, "Откройте C:\\Windows\\System32\\drivers\\etc\\hosts в Блокноте от имени администратора и удалите чужие строки.", items}}
	}
	return []Finding{{g, "Файл hosts чистый", "ok", "Подмены адресов сайтов нет.", "", nil}}
}

func checkSecureBoot() []Finding {
	out, err := runPS(`try { Confirm-SecureBootUEFI } catch { 'unsupported' }`, 20*time.Second)
	out = strings.TrimSpace(out)
	if err != nil {
		return nil
	}
	switch strings.ToLower(out) {
	case "true":
		return []Finding{{"Система", "Безопасная загрузка (Secure Boot) включена", "ok", "Защита от загрузочных вирусов активна.", "", nil}}
	case "false":
		return []Finding{{"Система", "Безопасная загрузка (Secure Boot) выключена", "warn", "Нет защиты от руткитов, подменяющих загрузчик.", "Включите Secure Boot в настройках BIOS/UEFI.", nil}}
	}
	return nil
}

func checkLive() []Finding {
	var out []Finding
	procs := procsSnapshot()
	conns := connsSnapshot()
	var badProcs, warnProcs []string
	for _, p := range procs {
		line := p.Name + " (PID " + fmt.Sprint(p.PID) + ") — " + strings.Join(p.Reasons, "; ")
		if p.Level == "bad" {
			badProcs = append(badProcs, line)
		} else if p.Level == "warn" {
			warnProcs = append(warnProcs, line)
		}
	}
	switch {
	case len(badProcs) > 0:
		out = append(out, Finding{"Процессы", "Подозрительные запущенные процессы", "bad", fmt.Sprintf("Высокий риск: %d.", len(badProcs)), "Откройте вкладку «Процессы», проверьте файл и при необходимости завершите.", badProcs})
	case len(warnProcs) > 0:
		out = append(out, Finding{"Процессы", "Процессы, требующие внимания", "warn", fmt.Sprintf("Средний риск: %d (чаще всего — программы без цифровой подписи).", len(warnProcs)), "Откройте вкладку «Процессы» и проверьте незнакомые.", warnProcs})
	case len(procs) > 0:
		out = append(out, Finding{"Процессы", "Подозрительных процессов нет", "ok", "Проверено процессов: " + fmt.Sprint(len(procs)) + ".", "", nil})
	}

	var badConns, listen []string
	for _, c := range conns {
		if c.Level == "bad" && c.Dir != "listen" {
			h := c.Remote
			if c.Host != "" {
				h = c.Host + " (" + c.Remote + ")"
			}
			badConns = append(badConns, fmt.Sprintf("%s → %s:%d — %s", c.Proc, h, c.RPort, strings.Join(c.Reasons, "; ")))
		}
		if c.Dir == "listen" && (c.Local == "0.0.0.0" || c.Local == "::") && c.Proto == "TCP" && c.Sig != "signed" && c.Sig != "pending" && c.Exe != "" {
			listen = append(listen, fmt.Sprintf("%s слушает порт %d", c.Proc, c.LPort))
		}
	}
	if len(badConns) > 0 {
		out = append(out, Finding{"Сеть", "Подозрительные сетевые соединения", "bad", fmt.Sprintf("Найдено: %d.", len(badConns)), "Откройте вкладку «Соединения», проверьте адрес и процесс; при необходимости заблокируйте IP.", dedupe(badConns)})
	} else if len(conns) > 0 {
		out = append(out, Finding{"Сеть", "Подозрительных соединений нет", "ok", "Проверено соединений: " + fmt.Sprint(len(conns)) + ".", "", nil})
	}
	if len(listen) > 0 {
		out = append(out, Finding{"Сеть", "Неподписанные программы принимают подключения", "warn", "Эти программы открыли порты для всей сети.", "Убедитесь, что вы знаете эти программы.", dedupe(listen)})
	}

	al := snifferAlerts()
	var plain, scan []string
	for _, a := range al {
		if a.Kind == "plain" {
			plain = append(plain, a.Text)
		} else {
			scan = append(scan, a.Text)
		}
	}
	if len(plain) > 0 {
		out = append(out, Finding{"Трафик", "Данные передаются без шифрования", "bad", "Пароли ушли по протоколу HTTP/FTP/POP3 открытым текстом — их может прочитать любой в сети.", "Не вводите пароли на сайтах без https://.", plain})
	}
	if len(scan) > 0 {
		out = append(out, Finding{"Трафик", "Обнаружено сканирование портов", "warn", "Кто-то проверяет ваш компьютер на открытые порты. Для домашней сети из интернета это нормальный фон, но если сканируют изнутри сети — это тревожно.", "Убедитесь, что брандмауэр включён и ненужные порты закрыты.", scan})
	}
	return out
}

func checkAutoruns() []Finding {
	var bad, warn []string
	for _, a := range autorunsScan() {
		line := a.Where + ": " + a.Name + " → " + a.Exe
		if a.Level == "bad" {
			bad = append(bad, line+" — "+strings.Join(a.Reasons, "; "))
			addIncident(Incident{Key: "autorun|" + a.Where + "|" + a.Name, Kind: "autorun", Severity: "bad",
				Title: "Подозрительная автозагрузка: " + a.Name, Reasons: a.Reasons, Proc: a.Name, Exe: a.Exe, Cmd: a.Command,
				Sig: a.Sig, Signer: a.Signer},
				&Evidence{T: time.Now().UnixMilli(), Line: a.Where + ": " + a.Command})
		} else if a.Level == "warn" {
			warn = append(warn, line)
		}
	}
	switch {
	case len(bad) > 0:
		return []Finding{{"Автозагрузка", "Подозрительные программы в автозагрузке", "bad", fmt.Sprintf("Найдено: %d.", len(bad)), "Откройте вкладку «Автозагрузка» и удалите незнакомое.", bad}}
	case len(warn) > 0:
		return []Finding{{"Автозагрузка", "В автозагрузке есть программы без подписи", "warn", fmt.Sprintf("Найдено: %d.", len(warn)), "Проверьте вкладку «Автозагрузка».", warn}}
	}
	return []Finding{{"Автозагрузка", "Автозагрузка выглядит чисто", "ok", "Подозрительных записей нет.", "", nil}}
}

func checkDownloads() []Finding {
	var bad, warn []string
	for _, d := range downloadsScan() {
		line := d.Name + " — " + strings.Join(d.Reasons, "; ")
		if d.Level == "bad" {
			bad = append(bad, line)
			in := Incident{Key: "download|" + d.Path, Kind: "download", Severity: "bad", Title: "Опасный скачанный файл: " + d.Name,
				Reasons: d.Reasons, Proc: d.Name, Exe: d.Path, Sig: d.Sig, Signer: d.Signer, SHA256: d.SHA256}
			if d.HostURL != "" {
				in.Host = hostOfURL(d.HostURL)
			}
			ev := "Файл: " + d.Path
			if d.HostURL != "" {
				ev += "  | скачан с: " + d.HostURL
			}
			if d.Referrer != "" {
				ev += "  | со страницы: " + d.Referrer
			}
			addIncident(in, &Evidence{T: time.Now().UnixMilli(), Line: ev})
		} else if d.Level == "warn" {
			warn = append(warn, line)
		}
	}
	switch {
	case len(bad) > 0:
		return []Finding{{"Загрузки", "Опасные скачанные файлы", "bad", fmt.Sprintf("Найдено: %d.", len(bad)), "Не запускайте эти файлы; проверьте их на VirusTotal (вкладка «Загрузки»).", bad}}
	case len(warn) > 0:
		return []Finding{{"Загрузки", "Скачанные файлы без подписи", "warn", fmt.Sprintf("Найдено: %d.", len(warn)), "Запускайте только то, что скачали с официальных сайтов.", warn}}
	}
	return []Finding{{"Загрузки", "Скачанные файлы выглядят безопасно", "ok", "Подозрительных файлов за 45 дней нет.", "", nil}}
}

func hostOfURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- overview

func overview() map[string]any {
	host, _ := os.Hostname()
	conns := connsSnapshot()
	procs := procsSnapshot()
	pub, badC, listen := 0, 0, 0
	for _, c := range conns {
		if c.Scope == "public" {
			pub++
		}
		if c.Level == "bad" {
			badC++
		}
		if c.Dir == "listen" {
			listen++
		}
	}
	badP, warnP := 0, 0
	for _, p := range procs {
		switch p.Level {
		case "bad":
			badP++
		case "warn":
			warnP++
		}
	}
	var inB, outB uint64
	for _, f := range flowsSnapshot() {
		inB += f.In
		outB += f.Out
	}
	incBad, incWarn := 0, 0
	for _, x := range incidentsSnapshot() {
		if x.Severity == "bad" {
			incBad++
		} else {
			incWarn++
		}
	}
	secData.RLock()
	rep, busy := secLast, secBusy
	secData.RUnlock()
	if rep == nil && !busy {
		go securityScan(false)
		busy = true
	}
	return map[string]any{
		"host": host, "admin": isAdmin(), "conns": len(conns), "public": pub, "badConns": badC, "listen": listen,
		"procs": len(procs), "badProcs": badP, "warnProcs": warnP, "bytesIn": inB, "bytesOut": outB,
		"sniffer": snifferStatus(), "alerts": snifferAlerts(), "security": rep, "scanning": busy,
		"incBad": incBad, "incWarn": incWarn,
	}
}

// recordDefenderIncidents makes one incident per threat Defender has ever reported, not only active ones:
// a quarantined trojan still tells what ran on this computer.
func recordDefenderIncidents() {
	raw := defenderRaw()
	brief := defenderBrief()
	for _, th := range raw.threats {
		nm := str(th["ThreatName"])
		if nm == "" {
			continue
		}
		active, executed := th["IsActive"] == true, th["DidThreatExecute"] == true
		sev := "warn"
		if active || executed {
			sev = "bad"
		}
		in := Incident{Key: "defender|" + nm, Kind: "defender", Severity: sev, Ref: nm, Title: "Защитник Windows обнаружил угрозу: " + nm}
		if t := severityTxt[str(th["SeverityID"])]; t != "" {
			in.Reasons = append(in.Reasons, "Серьёзность по оценке Защитника: "+t)
		}
		if c := categoryTxt[str(th["CategoryID"])]; c != "" {
			in.Reasons = append(in.Reasons, "Категория: "+c)
		}
		if active {
			in.Reasons = append(in.Reasons, "Угроза всё ещё помечена как активная")
		} else {
			in.Reasons = append(in.Reasons, "Защитник уже обработал угрозу (карантин или удаление)")
		}
		if executed {
			in.Reasons = append(in.Reasons, "Защитник отмечает, что угроза успела выполниться")
		}
		ev := &Evidence{T: time.Now().UnixMilli(), Line: "Get-MpThreat: " + nm}
		if b, ok := brief[nm]; ok {
			for _, p := range b.Paths {
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					in.Exe = p
					break
				}
			}
			if len(b.Paths) > 0 {
				ev.Line = fmt.Sprintf("Объект: %s · первое обнаружение %s · процесс: %s", strings.Join(dedupe(b.Paths), "; "), time.UnixMilli(b.First).Format("02.01.2006 15:04"), firstNonEmpty(b.Proc, "—"))
			}
		}
		upsertIncident2(in, ev)
	}

	// threats that are gone from the current list but remain in Defender's event log
	known := map[string]bool{}
	for _, th := range raw.threats {
		known[str(th["ThreatName"])] = true
	}
	for _, e := range raw.events {
		d := dataOf(e)
		nm := d["Threat Name"]
		if nm == "" || known[nm] || str(e["Id"]) != "1116" {
			continue
		}
		known[nm] = true
		in := Incident{Key: "defender|" + nm, Kind: "defender", Severity: "warn", Ref: nm, Title: "Защитник Windows обнаружил угрозу: " + nm,
			Reasons: []string{"Защитник уже обработал эту угрозу (карантин или удаление), но она была на этом компьютере"}}
		if d["Severity Name"] != "" {
			in.Reasons = append(in.Reasons, "Серьёзность по оценке Защитника: "+d["Severity Name"])
		}
		if d["Category Name"] != "" {
			in.Reasons = append(in.Reasons, "Категория: "+d["Category Name"])
		}
		ev := &Evidence{T: time.Now().UnixMilli(), Line: "Журнал Защитника, событие 1116: " + nm}
		if b, ok := brief[nm]; ok && len(b.Paths) > 0 {
			ev.Line = fmt.Sprintf("Объект: %s · первое обнаружение %s", strings.Join(dedupe(b.Paths), "; "), time.UnixMilli(b.First).Format("02.01.2006 15:04"))
		} else if d["Path"] != "" {
			ev.Line = "Объект: " + shorten(d["Path"], 300)
		}
		upsertIncident2(in, ev)
	}
}
