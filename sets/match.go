package sets

import (
	"bytes"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// Match says where a host name belongs.
type Match struct {
	Service *Service
	Part    *Part // the ordinary part of the name; its quic-off part when that is the only one
}

// find is the longest-suffix lookup behind Match and BlocksQUIC. It runs for every new connection, so it works
// in a buffer on the stack and indexes the map with a conversion the compiler does not allocate for.
func (s *Set) find(host string) (entry, bool) {
	var buf [maxHost]byte
	n := len(host)
	if n > 0 && host[n-1] == '.' {
		n--
	}
	if n == 0 || n > maxHost {
		return entry{}, false
	}
	for i := 0; i < n; i++ {
		c := host[i]
		if c >= 0x80 {
			return entry{}, false // IDN is looked up in its ASCII form; anything else is not a name of ours
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	b := buf[:n]
	// The whole name, then each suffix that starts after a dot, as long as it still has a dot: the first entry
	// found is the longest. The index holds no one-label names, so the last label is not looked up.
	for i := 0; ; {
		j := bytes.IndexByte(b[i:], '.')
		if j < 0 {
			return entry{}, false
		}
		if e, ok := s.index[string(b[i:])]; ok {
			return e, true
		}
		i += j + 1
	}
}

// Match finds the service and part of a host name: by the name itself or the longest domain it is under.
// Case and a final dot do not matter; an internationalised name is matched in its ASCII (xn--) form.
// It does not allocate.
func (s *Set) Match(host string) (Match, bool) {
	e, ok := s.find(host)
	if !ok {
		return Match{}, false
	}
	sv := &s.Services[e.svc]
	if e.part >= 0 {
		return Match{sv, &sv.Parts[e.part]}, true
	}
	return Match{sv, &sv.Parts[e.quic]}, true
}

// BlocksQUIC says whether QUIC to the host is to be refused in the country: the name has a quic-off part and the
// country's section lists its service.
func (s *Set) BlocksQUIC(country, host string) bool {
	e, ok := s.find(host)
	return ok && e.quic >= 0 && s.section(country).quicOff[s.Services[e.svc].ID]
}

// section is the country's, or the general one for a country the file does not list. A country is two lower-case
// letters; anything else is just another unknown country.
func (s *Set) section(country string) section {
	if sec, ok := s.sections[country]; ok {
		return sec
	}
	return s.sections["*"]
}

// Candidates are the strategies to try for a part, in order, after the ordinary connection has failed.
// The part's own list for the country (or "*") wins over the country's. The list is shared: do not modify it.
func (s *Set) Candidates(country string, m Match) []dpi.Strategy {
	if m.Part == nil || m.Part.Kind != KindTLS {
		return nil
	}
	if l, ok := m.Part.quick[country]; ok {
		return l
	}
	if l, ok := m.Part.quick["*"]; ok {
		return l
	}
	return s.section(country).quick
}

// Site are the strategies to try for a site that belongs to no service (the person's own), in order.
// The list is shared: do not modify it.
func (s *Set) Site(country string) []dpi.Strategy { return s.section(country).quick }

// Catalog is what the window needs, ready for JSON. It carries no domain names or addresses.
type Catalog struct {
	Seq        uint64           `json:"seq"`
	DateUnix   int64            `json:"date_unix"`
	Categories []string         `json:"categories"`
	Services   []CatalogService `json:"services"`
}

type CatalogService struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Icon       string        `json:"icon"`
	Categories []string      `json:"categories"`
	Ways       bool          `json:"ways"` // there is something to try in the country; when false the window hides the service
	Parts      []CatalogPart `json:"parts"`
}

type CatalogPart struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Supported bool   `json:"supported"` // false: the window says "soon"
}

// Catalog lists the services as the window shows them in the country. Hidden parts are left out;
// they still count toward Ways.
func (s *Set) Catalog(country string) Catalog {
	c := Catalog{Seq: s.Seq, DateUnix: s.Date.Unix(), Categories: append([]string{}, s.categories...), Services: make([]CatalogService, 0, len(s.Services))}
	for i := range s.Services {
		sv := &s.Services[i]
		cs := CatalogService{ID: sv.ID, Name: sv.Name, Icon: sv.Icon, Categories: append([]string{}, sv.Categories...), Parts: []CatalogPart{}}
		for j := range sv.Parts {
			p := &sv.Parts[j]
			if len(s.Candidates(country, Match{sv, p})) > 0 {
				cs.Ways = true
			}
			if !p.Hidden {
				cs.Parts = append(cs.Parts, CatalogPart{ID: p.ID, Kind: p.Kind, Supported: p.Supported()})
			}
		}
		c.Services = append(c.Services, cs)
	}
	return c
}
