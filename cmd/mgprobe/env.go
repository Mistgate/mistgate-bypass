package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// Environment says whether the machine itself distorts the measurement: a resolver or a program that answers for
// the whole system with made-up addresses, bypass tools and VPN clients that are running, a default route that
// leaves through a tunnel, a packet-diverting driver. Only names from fixed lists and interface types as numbers
// go in: no process list, no interface names, no addresses of the machine.
type Environment struct {
	Distorted bool     `json:"distorted"`
	Reasons   []string `json:"reasons,omitempty"`
	DNSStub   []string `json:"dns_stub,omitempty"` // "name: kind of address" for control names answered with a stub
	Tools     []string `json:"tools,omitempty"`    // running programs from bypassTools
	Routes    []IfType `json:"route_interfaces,omitempty"`
	WinDivert string   `json:"windivert"`         // loaded, not-loaded or unknown
	Unknown   []string `json:"unknown,omitempty"` // what could not be checked
}

// IfType is the type of an interface a default route leaves through.
type IfType struct {
	Type   int    `json:"type"`
	Word   string `json:"word"`
	Normal bool   `json:"normal"` // Ethernet, Wi-Fi or mobile
}

// ifTypeWords names the interface types that matter (IANA ifType numbers).
var ifTypeWords = map[int]string{1: "other", 6: "Ethernet", 23: "PPP (PPPoE or a VPN)", 24: "loopback", 53: "virtual", 71: "Wi-Fi",
	131: "tunnel", 243: "mobile", 244: "mobile"}

func newIfType(t int) IfType {
	w, ok := ifTypeWords[t]
	if !ok {
		w = "unknown type"
	}
	return IfType{Type: t, Word: w, Normal: t == 6 || t == 71 || t == 243 || t == 244}
}

// matchTools returns, sorted and without repeats, the entries of bypassTools that are among the running programs.
// The comparison ignores case and a trailing .exe.
func matchTools(running []string) []string {
	var out []string
	for _, n := range running {
		n = strings.TrimSuffix(strings.ToLower(n), ".exe")
		if slices.Contains(bypassTools, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// checkEnvironment looks at the machine; what the platform cannot tell is listed in Unknown.
func (p *prober) checkEnvironment(ctx context.Context) Environment {
	var e Environment
	e.WinDivert = "unknown"
	if procs, err := listProcesses(); err != nil {
		e.Unknown = append(e.Unknown, "список программ")
	} else {
		e.Tools = matchTools(procs)
	}
	if types, err := defaultRouteTypes(); err != nil {
		e.Unknown = append(e.Unknown, "маршрут по умолчанию")
	} else {
		for _, t := range types {
			e.Routes = append(e.Routes, newIfType(t))
		}
	}
	if loaded, err := windivertLoaded(); err != nil {
		e.Unknown = append(e.Unknown, "драйвер WinDivert")
	} else if loaded {
		e.WinDivert = "loaded"
	} else {
		e.WinDivert = "not-loaded"
	}

	// The system resolver on every probed name: a real answer is a public address. A stub for a service name only is
	// how a router or a proxy that takes that service over shows itself.
	var hosts []string
	for _, s := range services {
		hosts = append(hosts, s.Hosts...)
	}
	for _, h := range hosts {
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		addrs, err := net.DefaultResolver.LookupNetIP(c, "ip4", h)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if k := stubKind(a.Unmap()); k != "" {
				e.DNSStub = append(e.DNSStub, h+": "+k)
				break
			}
		}
	}

	if len(e.DNSStub) > 0 {
		e.Reasons = append(e.Reasons, "системный DNS отвечает на имена служебными адресами (так делает прокси или VPN на компьютере или роутере) ("+strings.Join(e.DNSStub, "; ")+
			"): так отвечает чужая программа, подменяющая адреса для всей системы, или заглушка")
	}
	if len(e.Tools) > 0 {
		e.Reasons = append(e.Reasons, "запущены программы обхода или VPN: "+strings.Join(e.Tools, ", "))
	}
	for _, r := range e.Routes {
		if !r.Normal {
			note := ""
			if r.Type == 23 {
				note = " (для домашнего интернета с PPPoE это нормально, для VPN нет)"
			}
			e.Reasons = append(e.Reasons, fmt.Sprintf("маршрут по умолчанию идёт через интерфейс типа %d (%s), а не Ethernet, Wi-Fi или мобильный%s", r.Type, r.Word, note))
		}
	}
	if e.WinDivert == "loaded" {
		e.Reasons = append(e.Reasons, "загружен драйвер WinDivert: программа с ним перехватывает и меняет пакеты")
	}
	e.Distorted = len(e.Reasons) > 0
	return e
}

// lines is the environment as report and console lines.
func (e Environment) lines() []string {
	var out []string
	if e.Distorted {
		out = append(out,
			"ВНИМАНИЕ. Результаты искажены: на этом компьютере есть то, что меняет сетевой трафик. Проверка всё равно выполняется,",
			"но выводы о сети провайдера по этому отчёту делать нельзя. Закройте перечисленное и запустите пробник ещё раз.")
		for _, r := range e.Reasons {
			out = append(out, "  - "+r)
		}
	} else {
		out = append(out, "Признаков искажения не найдено: программ обхода и VPN, подмены DNS, туннельного маршрута и драйвера WinDivert нет.")
	}
	routes := "не удалось определить"
	if len(e.Routes) > 0 {
		var w []string
		for _, r := range e.Routes {
			w = append(w, fmt.Sprintf("%d (%s)", r.Type, r.Word))
		}
		routes = strings.Join(w, ", ")
	}
	windivert := map[string]string{"loaded": "загружен", "not-loaded": "не загружен", "unknown": "не удалось узнать"}[e.WinDivert]
	out = append(out, "Тип интерфейса маршрута по умолчанию: "+routes+". Драйвер WinDivert: "+windivert+".")
	if len(e.Unknown) > 0 {
		out = append(out, "Не удалось проверить: "+strings.Join(e.Unknown, ", ")+".")
	}
	return out
}
