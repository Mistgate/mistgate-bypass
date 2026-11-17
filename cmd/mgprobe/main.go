// mgprobe is a reachability probe: it tries ordinary-socket connection strategies against a fixed list of public
// hosts and writes a report of what worked. It makes outgoing connections only, needs no rights and changes
// nothing on the machine. The strategies themselves live in internal/dpi.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// Report is everything the run measured. It holds no machine name, user name, local or external address.
type Report struct {
	Tool        string        `json:"tool"`
	Version     string        `json:"version"`
	Time        string        `json:"time"`
	Windows     string        `json:"windows"`
	ElapsedSec  int           `json:"elapsed_s"`
	Seed        int           `json:"seed"`
	Environment Environment   `json:"environment"`
	DoH         []DoHStatus   `json:"doh_endpoints"`
	DNS         []DNSResult   `json:"dns"`
	TLS         []TLSResult   `json:"tls"`
	Big         []BigResult   `json:"big_files"`
	Speed       []SpeedResult `json:"speed"`
	QUIC        []QUICResult  `json:"quic"`
	MTProto     []MTResult    `json:"mtproto"`
}

func main() {
	setupConsole()
	p := newProber(os.Stdout)
	fmt.Printf("mgprobe v%s: проверка доступности сервисов. Это займёт до 6 минут. Ничего не устанавливается и не меняется.\n\n", version)
	rep := p.run(context.Background())
	text := render(rep)
	path := reportPath()
	if err := os.WriteFile(path, append([]byte("\xef\xbb\xbf"), text...), 0o644); err != nil { // the BOM lets Notepad read UTF-8
		fmt.Println("Не удалось записать отчёт:", err)
		fmt.Println(text) // better on the screen than lost
	} else {
		fmt.Printf("\nГотово. Отчёт: %s\n", path)
	}
	fmt.Print("Нажмите Enter, чтобы закрыть окно.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// reportPath puts the report next to the executable, or in the temp directory when that folder is read-only.
func reportPath() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if f, err := os.CreateTemp(dir, ".w"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return filepath.Join(dir, reportName)
		}
	}
	return filepath.Join(os.TempDir(), reportName)
}

// run does the measurements. The environment and DNS come first because everything else depends on them; then
// the TLS matrix, the foreign-hosting downloads, QUIC and the messenger checks run side by side, and the speed
// test follows the matrix. The time budget: environment 5 s, DNS 15 s, the matrix 270 s, speed 14 s.
func (p *prober) run(ctx context.Context) *Report {
	start := time.Now()
	rep := &Report{Tool: "mgprobe", Version: version, Time: start.Format(time.RFC3339), Windows: windowsVersion(), Seed: probeSeed}
	ctx, cancel := context.WithTimeout(ctx, 340*time.Second)
	defer cancel()

	// 0. The machine itself
	p.logf("[1/6] Среда: программы, маршрут, DNS")
	rep.Environment = p.checkEnvironment(ctx)
	for _, l := range rep.Environment.lines() {
		p.logf("%s", l)
	}

	// 1. DNS
	p.logf("\n[2/6] DNS: системный резолвер и DNS поверх HTTPS")
	var names []string
	add := func(h string) {
		if !slices.Contains(names, h) {
			names = append(names, h)
		}
	}
	for _, s := range services {
		for _, h := range s.Hosts {
			add(h)
		}
	}
	for _, t := range speedTargets {
		add(t.Host)
	}
	for _, h := range quicHosts {
		add(h)
	}
	for _, h := range bigHosts() {
		add(h)
	}
	dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
	defer dcancel()
	rep.DoH = p.probeDoH(dctx)
	p.logf("  %s", dohLine(rep.DoH))
	rep.DNS = make([]DNSResult, len(names))
	addrs := map[string][]netip.Addr{}
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.DNS[i] = p.resolve(dctx, n)
		}()
	}
	wg.Wait()
	for _, d := range rep.DNS {
		addrs[d.Name] = d.addrs
		p.logf("  %-30s %-18s адреса из: %s", d.Name, d.Verdict, d.Used)
	}

	// 2-5. TLS matrix, foreign hosting, QUIC, messenger servers
	p.logf("\n[3/6] TLS по TCP 443: каждый хост, каждый способ, три «лица»")
	var mu sync.Mutex
	tlsCtx, tlsCancel := context.WithTimeout(ctx, 270*time.Second)
	defer tlsCancel()
	for _, s := range services {
		for _, h := range s.Hosts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := p.hostMatrix(tlsCtx, h, addrs[h])
				mu.Lock()
				rep.TLS = append(rep.TLS, r...)
				mu.Unlock()
			}()
		}
	}
	bigCtx, bigCancel := context.WithTimeout(ctx, 90*time.Second)
	defer bigCancel()
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := p.runBig(bigCtx, addrs)
		mu.Lock()
		rep.Big = r
		mu.Unlock()
	}()
	quicCtx, quicCancel := context.WithTimeout(ctx, 75*time.Second)
	defer quicCancel()
	for _, h := range quicHosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := p.quicHost(quicCtx, h, addrs[h])
			mu.Lock()
			rep.QUIC = append(rep.QUIC, r...)
			mu.Unlock()
		}()
	}
	mtCtx, mtCancel := context.WithTimeout(ctx, 40*time.Second)
	defer mtCancel()
	for i, dc := range telegramDCs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := p.mtDC(mtCtx, dc.Name, dc.Addr, i+1)
			mu.Lock()
			rep.MTProto = append(rep.MTProto, r...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	p.logf("\n[4/6] Зарубежные датацентры, [5/6] QUIC и серверы Telegram: готово")

	// 6. Speed, on what the matrix found
	p.logf("\n[6/6] Скорость загрузки")
	speedCtx, speedCancel := context.WithTimeout(ctx, 14*time.Second)
	defer speedCancel()
	rep.Speed = make([]SpeedResult, len(speedTargets))
	for i, t := range speedTargets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.Speed[i] = p.speed(speedCtx, t, addrs[t.Host], rep.TLS)
		}()
	}
	wg.Wait()

	rep.ElapsedSec = int(time.Since(start).Seconds())
	sortReport(rep)
	return rep
}

// sortReport puts the concurrently collected rows in the order of the lists they came from.
func sortReport(rep *Report) {
	hostPos := map[string]int{}
	for _, s := range services {
		for _, h := range s.Hosts {
			hostPos[h] = len(hostPos)
		}
	}
	stratPos := map[string]int{}
	for i, s := range dpi.Ladder() {
		stratPos[s.Name] = i
	}
	facePos := map[string]int{}
	for i, f := range faces {
		facePos[f.Name] = i
	}
	slices.SortStableFunc(rep.TLS, func(a, b TLSResult) int {
		switch {
		case a.Host != b.Host:
			return hostPos[a.Host] - hostPos[b.Host]
		case a.Strategy != b.Strategy:
			return stratPos[a.Strategy] - stratPos[b.Strategy]
		}
		return facePos[a.Face] - facePos[b.Face]
	})
	bigPos := map[string]int{}
	for i, b := range bigFiles {
		bigPos[b.Name] = i
	}
	slices.SortStableFunc(rep.Big, func(a, b BigResult) int {
		if a.Provider != b.Provider {
			return bigPos[a.Provider] - bigPos[b.Provider]
		}
		return strings.Compare(b.TLS, a.TLS) // 1.3 first
	})
	qPos := map[string]int{}
	for i, v := range quicVariants() {
		qPos[v.name()] = i
	}
	hostIdx := func(h string) int { return slices.Index(quicHosts, h) }
	slices.SortStableFunc(rep.QUIC, func(a, b QUICResult) int {
		if a.Host != b.Host {
			return hostIdx(a.Host) - hostIdx(b.Host)
		}
		return qPos[a.Variant] - qPos[b.Variant]
	})
	mPos := map[string]int{}
	for i, v := range mtVariants {
		mPos[v] = i
	}
	slices.SortStableFunc(rep.MTProto, func(a, b MTResult) int {
		if a.DC != b.DC {
			return strings.Compare(a.DC, b.DC)
		}
		return mPos[a.Variant] - mPos[b.Variant]
	})
}
