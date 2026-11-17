package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// render builds the report: the environment first, then a human summary, then the tables and the raw results.
func render(rep *Report) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	ladder := dpi.LadderSeed(probeSeed)

	w("mgprobe v%s: отчёт о доступности сервисов", rep.Version)
	w("Дата и время: %s    Windows: %s    Длительность: %d с    Зерно случайных разрезов: %d", rep.Time, rep.Windows, rep.ElapsedSec, rep.Seed)
	w("")
	w("Провайдер: ____")
	w("Город: ____")
	w("Домашний или мобильный: ____")
	w("")
	w("=== Среда ===")
	for _, l := range rep.Environment.lines() {
		w("%s", l)
	}

	w("")
	w("=== Сводка ===")
	for _, l := range summarize(rep) {
		w("%s", l)
	}

	w("")
	w("=== DNS ===")
	w("%s", dohLine(rep.DoH))
	for _, d := range rep.DNS {
		w("%-30s система: %-34s DoH: %-34s %s; адреса для проверок: %s", d.Name, firstN(d.System, d.SystemErr), firstN(d.DoH, ""), dnsVerdict[d.Verdict], d.Used)
	}

	w("")
	w("=== TLS по TCP 443: хост x способ, по «лицам» ===")
	w("Лицо chrome: ClientHello как у текущего Chrome (с постквантовым ключом, не влезает в один сегмент). chrome-small: как у Chrome старой версии, около 500 байт.")
	w("tls12: то же, но не выше TLS 1.2. Если хост открылся без обхода, остальные способы проверены на chrome только (нет ли поломки), прочие лица помечены -.")
	for _, f := range faces {
		w("")
		w("Лицо %s", f.Name)
		hdr := fmt.Sprintf("%-28s", "")
		for i := range ladder {
			hdr += fmt.Sprintf("%-6d", i+1)
		}
		w("%s", hdr)
		for _, s := range services {
			for _, h := range s.Hosts {
				row := fmt.Sprintf("%-28s", h)
				for _, st := range ladder {
					row += fmt.Sprintf("%-6s", outcomeCode[tlsOutcome(rep.TLS, h, f.Name, st.Name)])
				}
				w("%s", row)
			}
		}
	}
	var legend []string
	for i, s := range ladder {
		name := s.Name
		if s.Experimental {
			name += "*"
		}
		legend = append(legend, fmt.Sprintf("%d=%s", i+1, name))
	}
	w("")
	w("Способы: %s", strings.Join(legend, ", "))
	w("* = использует TTL=1 (эксперимент: на пути без роутеров, как loopback, ничего не делает, на настоящем пути куски переотправляются по таймауту).")
	w("Исходы: ok=открылось, c-tmo=нет ответа на соединение, c-ref=соединение отвергнуто, rst=сброс (RST), fin=закрыто (FIN), sil=тишина,")
	w("        alert=ошибка TLS от сервера, cert=чужой сертификат, oth=другое, skip=пропущено, noadr=нет адреса, -=не проверялось")

	w("")
	w("=== Зарубежные датацентры: обрыв после 16-20 КБ ===")
	w("Скачивание до 256 КБ без обхода, одним соединением; на TLS 1.3 (лицо chrome-small) и на TLS 1.2 (лицо tls12).")
	for _, l := range bigLines(rep.Big) {
		w("%s", l)
	}

	w("")
	w("=== Скорость загрузки ===")
	for _, s := range rep.Speed {
		w("%s", speedLine(s))
	}

	w("")
	w("=== QUIC (UDP 443, HTTP/3) ===")
	row := fmt.Sprintf("%-18s", "вариант")
	for _, h := range quicHosts {
		row += fmt.Sprintf("%-18s", h)
	}
	w("%s", row)
	for _, v := range quicVariants() {
		row = fmt.Sprintf("%-18s", v.name())
		for _, h := range quicHosts {
			o := "-"
			for _, r := range rep.QUIC {
				if r.Host == h && r.Variant == v.name() {
					o = outcomeCode[r.Outcome]
				}
			}
			row += fmt.Sprintf("%-18s", o)
		}
		w("%s", row)
	}

	w("")
	w("=== Серверы Telegram (TCP 443, MTProto) ===")
	row = fmt.Sprintf("%-6s", "")
	for _, v := range mtVariants {
		row += fmt.Sprintf("%-20s", v)
	}
	w("%s", row)
	for _, dc := range telegramDCs {
		row = fmt.Sprintf("%-6s", dc.Name)
		for _, v := range mtVariants {
			o := "-"
			for _, r := range rep.MTProto {
				if r.DC == dc.Name && r.Variant == v {
					o = outcomeCode[r.Outcome]
					if r.Detail != "" && r.Outcome == outOther {
						o += " (" + r.Detail + ")"
					}
				}
			}
			row += fmt.Sprintf("%-20s", o)
		}
		w("%s", row)
	}
	w("ok = получен корректный ответ resPQ.")

	w("")
	w("=== Чего пробник не проверяет ===")
	w("Голос Discord: для него нужен вход в аккаунт, пробник к аккаунтам не подключается.")
	w("")
	w("=== Как читать, ограничения ===")
	for _, l := range caveats {
		w("- %s", l)
	}

	w("")
	w("--- JSON ---")
	j, _ := json.MarshalIndent(rep, "", " ")
	w("%s", j)
	return b.String()
}

var caveats = []string{
	"Каждый способ на каждом лице проверен один раз (обычное соединение без обхода на chrome - дважды): единичная неудача может быть случайной.",
	"Рукопожатие делает uTLS по образцу Chrome; настоящий браузер может отличаться (порядок расширений, QUIC, ECH), и сеть может отнестись к нему иначе.",
	"Проверяется только IPv4. Один запуск в одной сети в одно время суток: вечером и днём результат может отличаться.",
	"Скорость измерена на одном файле небольшого размера; при малом объёме (менее 256 КБ) число только ориентировочное.",
	"Способы с TTL=1 и с срочным байтом (oob) зависят от пути до сервера и от того, как сервер читает срочные данные; сбой тут не всегда означает блокировку.",
	"Адреса дата-центров Telegram и тестовых файлов хостеров взяты из публичных списков и могут устареть: сбой одного адреса при исправных остальных ничего не говорит о сети.",
	"Одновременные проверки делят канал: на очень медленном соединении часть таймаутов может быть вызвана самой нагрузкой.",
	"Если в «Среде» сказано, что результаты искажены, их нельзя приписывать сети провайдера.",
}

var outcomeCode = map[string]string{
	outOK: "ok", outConnTimeout: "c-tmo", outRefused: "c-ref", outReset: "rst", outClosed: "fin", outSilence: "sil",
	outAlert: "alert", outCert: "cert", outOther: "oth", outSkipped: "skip", outNoAddr: "noadr", "": "-",
}

var dnsVerdict = map[string]string{
	"same":              "совпадают",
	"overlap":           "частично совпадают (для CDN это нормально)",
	"differ":            "РАЗНЫЕ (подмена или другой регион)",
	"system-empty":      "системный DNS пуст, а DoH ответил",
	"system-suspicious": "системный DNS вернул адрес-заглушку (частный/служебный)",
	"doh-unavailable":   "DoH недоступен, верим системному ответу",
	"unresolved":        noRealAddr,
}

func firstN(addrs []string, errText string) string {
	if len(addrs) == 0 {
		if errText != "" {
			return "пусто (" + errText + ")"
		}
		return "пусто"
	}
	s := strings.Join(addrs[:min(2, len(addrs))], ",")
	if len(addrs) > 2 {
		s += fmt.Sprintf(",+%d", len(addrs)-2)
	}
	return s
}

// dohLine says which DoH endpoints answered, telling "closed by address" from "closed altogether".
func dohLine(st []DoHStatus) string {
	var ok, bad []string
	var addrOK, nameOK, addrTotal, nameTotal int
	for _, s := range st {
		if s.ByAddr {
			addrTotal++
		} else {
			nameTotal++
		}
		switch {
		case s.OK && s.ByAddr:
			addrOK++
			ok = append(ok, s.Name)
		case s.OK:
			nameOK++
			ok = append(ok, s.Name)
		default:
			bad = append(bad, s.Name+" ("+outcomeCode[s.Error]+")")
		}
	}
	var verdict string
	switch {
	case len(ok) == 0:
		verdict = "DoH закрыт совсем: ни по адресу, ни по имени"
	case addrOK == 0 && nameOK > 0:
		verdict = "DoH закрыт по адресам (1.1.1.1, 8.8.8.8), но доступен по именам"
	case nameOK == 0 && addrOK > 0:
		verdict = "DoH доступен по адресам, по именам нет (возможно, системный DNS подменяет имена серверов)"
	default:
		verdict = "DoH доступен"
	}
	s := fmt.Sprintf("DoH: %s. Ответили: %s.", verdict, orNone(ok))
	if len(bad) > 0 {
		s += " Не ответили: " + strings.Join(bad, ", ") + "."
	}
	return s
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "никто"
	}
	return strings.Join(l, ", ")
}

func tlsOutcome(res []TLSResult, host, face, strategy string) string {
	for _, r := range res {
		if r.Host == host && r.Face == face && r.Strategy == strategy {
			return r.Outcome
		}
	}
	return ""
}

func speedLine(s SpeedResult) string {
	kind := ""
	if s.Control {
		kind = " (контроль)"
	}
	if s.Outcome != outOK {
		return fmt.Sprintf("%s%s: не измерено (%s %s)", s.Host, kind, outcomeCode[s.Outcome], s.Detail)
	}
	note := ""
	if s.Bytes < 256<<10 {
		note = ", мало данных: цифра ориентировочная"
	}
	return fmt.Sprintf("%s%s: %d кбит/с (%d байт, ответ через %d мс, чтение %d мс, способ %s на лице %s, конец чтения: %s%s)",
		s.Host, kind, s.Kbps, s.Bytes, s.TTFBMs, s.ReadMs, s.Strategy, s.Face, s.End, note)
}

// bigLines is the table of the foreign-hosting downloads and its summary line.
func bigLines(big []BigResult) []string {
	var out []string
	var tested, froze []string
	var stops []int64
	byProv := map[string]map[string]BigResult{}
	var order []string
	for _, r := range big {
		if byProv[r.Provider] == nil {
			byProv[r.Provider] = map[string]BigResult{}
			order = append(order, r.Provider)
		}
		byProv[r.Provider][r.TLS] = r
	}
	cell := func(r BigResult) string {
		if r.Outcome != outOK {
			return outcomeCode[r.Outcome] + " " + r.Detail
		}
		s := fmt.Sprintf("%d КБ, %s", r.Bytes>>10, r.End)
		if r.Freeze {
			s += " FREEZE-16K"
		}
		return s
	}
	for _, p := range order {
		a, b := byProv[p]["1.3"], byProv[p]["1.2"]
		out = append(out, fmt.Sprintf("%-14s TLS 1.3: %-32s TLS 1.2: %s", p, cell(a), cell(b)))
		got := false
		for _, r := range []BigResult{a, b} {
			if r.Outcome == outOK {
				got = true
			}
		}
		if got {
			tested = append(tested, p)
		}
		if a.Freeze || b.Freeze {
			froze = append(froze, p)
			for _, r := range []BigResult{a, b} {
				if r.Freeze {
					stops = append(stops, r.Bytes>>10)
					break
				}
			}
		}
	}
	if len(order) == 0 {
		return []string{"не проверялось"}
	}
	sort.Slice(stops, func(i, j int) bool { return stops[i] < stops[j] })
	line := fmt.Sprintf("Зарубежные датацентры: обрыв после %s КБ у %d из %d", medianKB(stops), len(froze), len(tested))
	if len(froze) > 0 {
		line += " (" + strings.Join(froze, ", ") + ")"
	}
	if len(tested) < len(order) {
		line += fmt.Sprintf("; ещё %d не удалось проверить (нет соединения или файла)", len(order)-len(tested))
	}
	return append(out, line+".")
}

func medianKB(s []int64) string {
	if len(s) == 0 {
		return "N"
	}
	return fmt.Sprintf("~%d", s[len(s)/2])
}

// hostFacts is what the matrix found for one host.
type hostFacts struct {
	direct   []string            // faces that open it with no strategy
	ways     map[string][]string // strategy -> faces that open it
	order    []string            // strategies of ways, ladder order
	outcomes map[string]int      // outcomes of everything tried, skipped rows aside
	connFail int                 // attempts that never connected
	noAddr   bool
}

func collect(rep *Report, host string) hostFacts {
	f := hostFacts{ways: map[string][]string{}, outcomes: map[string]int{}}
	names := ladderNames()
	for _, r := range rep.TLS {
		if r.Host != host {
			continue
		}
		switch r.Outcome {
		case outNoAddr:
			f.noAddr = true
		case outSkipped:
		case outOK:
			if r.Strategy == "plain" {
				f.direct = append(f.direct, r.Face)
			} else {
				f.ways[r.Strategy] = append(f.ways[r.Strategy], r.Face)
			}
		default:
			f.outcomes[r.Outcome]++
			if connectFail(r.Outcome) {
				f.connFail++
			}
		}
	}
	for _, n := range names {
		if _, ok := f.ways[n]; ok {
			f.order = append(f.order, n)
		}
	}
	return f
}

func ladderNames() (n []string) {
	for _, s := range dpi.Ladder() {
		n = append(n, s.Name)
	}
	return
}

// describe is the verdict on a host in one phrase.
func (f hostFacts) describe() string {
	switch {
	case f.noAddr:
		return noRealAddr + ": выводов нет"
	case slices.Contains(f.direct, "chrome"):
		return "открывается без обхода"
	case len(f.direct) > 0:
		return "без обхода открывается только на лице " + strings.Join(f.direct, ", ")
	case len(f.order) > 0:
		var parts []string
		for i, n := range f.order {
			if i == 4 {
				parts = append(parts, fmt.Sprintf("ещё %d", len(f.order)-4))
				break
			}
			fs := strings.Join(f.ways[n], ",")
			if len(f.ways[n]) == len(faces) {
				fs = "все лица"
			}
			parts = append(parts, n+" ["+fs+"]")
		}
		return "открывается способами: " + strings.Join(parts, ", ")
	}
	var oc []string
	total := 0
	for o, n := range f.outcomes {
		oc = append(oc, fmt.Sprintf("%s x%d", outcomeCode[o], n))
		total += n
	}
	sort.Strings(oc)
	if total > 0 && f.connFail == total {
		return "не открывается ничем: адрес недоступен, соединения нет (" + strings.Join(oc, ", ") + ")"
	}
	return "не открывается ничем: соединение есть, но дальше режут (" + strings.Join(oc, ", ") + ")"
}

// summarize says, per host and per service, how it opens, then the best strategies and the other measurements.
func summarize(rep *Report) []string {
	var out []string
	if rep.Environment.Distorted {
		out = append(out, "ВНИМАНИЕ. Результаты искажены (см. раздел «Среда»): выводы о сети провайдера делать нельзя.", "")
	}
	breaks := map[string][]string{} // strategy -> hosts that open as they are but not with it
	opened := map[string]map[string]bool{}
	notDirect := 0
	for _, svc := range services {
		var nDirect, nWays, nNone, nNoAddr int
		var lines []string
		for _, h := range svc.Hosts {
			f := collect(rep, h)
			switch {
			case f.noAddr:
				nNoAddr++
			case len(f.direct) > 0:
				nDirect++
				for _, r := range rep.TLS {
					if r.Host == h && r.Strategy != "plain" && r.Outcome != outOK && r.Outcome != outSkipped && r.Outcome != outNoAddr {
						breaks[r.Strategy] = append(breaks[r.Strategy], h)
					}
				}
			case len(f.order) > 0:
				nWays++
			default:
				nNone++
			}
			if !f.noAddr && !slices.Contains(f.direct, "chrome") {
				notDirect++
				for _, n := range f.order {
					if opened[n] == nil {
						opened[n] = map[string]bool{}
					}
					opened[n][h] = true
				}
			}
			lines = append(lines, fmt.Sprintf("    %s: %s", h, f.describe()))
		}
		head := fmt.Sprintf("%s: без обхода открывается %d из %d хостов", svc.Name, nDirect, len(svc.Hosts))
		if nWays > 0 {
			head += fmt.Sprintf(", только способами %d", nWays)
		}
		if nNone > 0 {
			head += fmt.Sprintf(", не открывается ничем %d", nNone)
		}
		if nNoAddr > 0 {
			head += fmt.Sprintf(", без настоящего адреса %d", nNoAddr)
		}
		out = append(out, head+".")
		out = append(out, lines...)
	}

	// The strategies that opened the most hosts that did not open as they were.
	type best struct {
		name string
		n    int
	}
	var bs []best
	for _, n := range ladderNames() {
		if len(opened[n]) > 0 {
			bs = append(bs, best{n, len(opened[n])})
		}
	}
	sort.SliceStable(bs, func(i, j int) bool { return bs[i].n > bs[j].n })
	if len(bs) > 0 {
		var l []string
		for _, b := range bs[:min(5, len(bs))] {
			l = append(l, fmt.Sprintf("%s (%d из %d)", b.name, b.n, notDirect))
		}
		out = append(out, "Лучшие способы (сколько хостов, не открывавшихся без обхода, они открыли): "+strings.Join(l, ", ")+".")
	} else if notDirect > 0 {
		out = append(out, "Лучшие способы: ни один способ не открыл ни одного хоста из тех, что не открывались без обхода.")
	}
	var names []string
	for _, n := range ladderNames() {
		if h := breaks[n]; len(h) > 0 {
			names = append(names, fmt.Sprintf("%s (%s)", n, strings.Join(h, ", ")))
		}
	}
	if len(names) == 0 {
		out = append(out, "Способы не ломали ни одного хоста, который открывался без обхода.")
	} else {
		out = append(out, "Способы, при которых не открылся хост, работавший без обхода: "+strings.Join(names, "; ")+".")
	}

	// DNS
	var empty, suspicious, differ, unresolved int
	for _, d := range rep.DNS {
		switch d.Verdict {
		case "system-empty":
			empty++
		case "system-suspicious":
			suspicious++
		case "differ":
			differ++
		case "unresolved":
			unresolved++
		}
	}
	out = append(out, dohLine(rep.DoH))
	out = append(out, fmt.Sprintf("DNS, имён всего %d: системный DNS пуст у %d, вернул заглушку у %d, расходится с DoH у %d; настоящий адрес не получен у %d.",
		len(rep.DNS), empty, suspicious, differ, unresolved))

	big := bigLines(rep.Big)
	out = append(out, big[len(big)-1])

	// QUIC
	for _, h := range quicHosts {
		var bare string
		var fakes []string
		for _, r := range rep.QUIC {
			switch {
			case r.Host != h:
			case r.Variant == "bare":
				bare = r.Outcome
			case r.Outcome == outOK:
				fakes = append(fakes, r.Variant)
			}
		}
		switch {
		case bare == outOK:
			out = append(out, fmt.Sprintf("QUIC %s: работает без подделок (с подделками успешно %d из %d вариантов).", h, len(fakes), len(quicVariants())-1))
		case len(fakes) > 0:
			out = append(out, fmt.Sprintf("QUIC %s: без подделок не работает (%s), с подделками работают: %s.", h, outcomeCode[bare], strings.Join(fakes, ", ")))
		default:
			out = append(out, fmt.Sprintf("QUIC %s: не работает ни без подделок (%s), ни с ними.", h, outcomeCode[bare]))
		}
	}

	// Messenger servers
	for _, v := range mtVariants {
		var ok, n int
		for _, r := range rep.MTProto {
			if r.Variant == v {
				n++
				if r.Outcome == outOK {
					ok++
				}
			}
		}
		out = append(out, fmt.Sprintf("Telegram, серверы, вариант %s: ответили %d из %d.", v, ok, n))
	}
	return out
}
