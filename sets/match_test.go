package sets

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t testing.TB, data string) *Set {
	t.Helper()
	s, err := parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// nested has a service whose part holds a domain and another part of it a name below that domain.
const nested = `{"v":1,"seq":1,"countries":{"*":{"quick":[6]}},"services":[
  {"id":"a","name":"A","parts":[
    {"id":"all","kind":"tls","domains":["example.com","xn--e1afmkfd.xn--p1ai"]},
    {"id":"deep","kind":"tls","domains":["api.eu.example.com"]}]},
  {"id":"b","name":"B","parts":[{"id":"x","kind":"tls","domains":["example.org"]}]}]}`

func whereIs(s *Set, host string) string {
	m, ok := s.Match(host)
	if !ok {
		return "-"
	}
	return m.Service.ID + "/" + m.Part.ID
}

func TestMatch(t *testing.T) {
	s := mustParse(t, nested)
	for host, want := range map[string]string{
		"example.com":                          "a/all", // the name itself
		"www.example.com":                      "a/all", // below it
		"a.b.c.example.com":                    "a/all",
		"api.eu.example.com":                   "a/deep", // the longest domain wins
		"x.api.eu.example.com":                 "a/deep",
		"eu.example.com":                       "a/all",
		"EXAMPLE.Com":                          "a/all", // case does not matter
		"www.Example.COM.":                     "a/all", // nor does a dot at the end
		"example.org":                          "b/x",
		"xn--80ak6aa92e.xn--e1afmkfd.xn--p1ai": "a/all", // internationalised names come in their ASCII form
		"notexample.com":                       "-",     // a suffix of the text, not of the labels
		"example.com.evil.net":                 "-",
		"com":                                  "-",
		"example":                              "-",
		"":                                     "-",
		".":                                    "-",
		"..":                                   "-",
		".example.com":                         "a/all",
		"пример.рф":                            "-", // not in ASCII form: nothing to match
		"example.com:443":                      "-", // a name, not an address with a port
		"93.184.216.34":                        "-",
		strings.Repeat("a.", 200) + "example.com": "-", // longer than a name can be
	} {
		if got := whereIs(s, host); got != want {
			t.Errorf("%q: got %s, want %s", host, got, want)
		}
	}
}

func TestMatchAllocatesNothing(t *testing.T) {
	s := Embedded()
	hosts := []string{"www.youtube.com", "RR3---sn-abc.googlevideo.com.", "unknown.example.net", "a.b.c.d.e.f.discord.com"}
	if n := testing.AllocsPerRun(100, func() {
		for _, h := range hosts {
			s.Match(h)
			s.BlocksQUIC("ru", h)
		}
	}); n != 0 {
		t.Fatalf("%v allocations", n)
	}
}

// The names of the measured networks belong where the strategies for them are.
func TestMatchEmbedded(t *testing.T) {
	s := Embedded()
	for host, want := range map[string]string{
		"www.youtube.com":                   "yt/site",
		"i.ytimg.com":                       "yt/site",
		"redirector.googlevideo.com":        "yt/video",
		"rr1---sn-4g5ednsl.googlevideo.com": "yt/video",
		"youtubei.googleapis.com":           "yt/api",
		"discord.com":                       "dc/chat",
		"gateway.discord.gg":                "dc/chat",
		"cdn.discordapp.com":                "dc/chat",
		"media.discordapp.net":              "dc/chat",
		"www.googleapis.com":                "-", // other APIs of the same company are not YouTube
		"www.google.com":                    "-",
	} {
		if got := whereIs(s, host); got != want {
			t.Errorf("%q: got %s, want %s", host, got, want)
		}
	}
}

func nums(t *testing.T, s *Set, host, country string) []int {
	t.Helper()
	m, ok := s.Match(host)
	if !ok {
		t.Fatalf("%s is not matched", host)
	}
	var out []int
	for _, st := range s.Candidates(country, m) {
		out = append(out, st.Num)
	}
	return out
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCandidates(t *testing.T) {
	s := mustParse(t, `{"v":1,"seq":1,"strategies":{"30":"cut:m"},
	  "countries":{"aa":{"quick":[6,30]},"bb":{"quick":[7]},"*":{"quick":[16,6]}},
	  "services":[{"id":"a","name":"A","parts":[
	    {"id":"site","kind":"tls","domains":["site.example"]},
	    {"id":"api","kind":"tls","domains":["api.example"],"quick":{"aa":[16],"*":[8]}},
	    {"id":"none","kind":"tls","domains":["none.example"],"quick":{"*":[]}},
	    {"id":"call","kind":"voice","domains":["call.example"]}]}]}`)
	for _, c := range []struct {
		host, country string
		want          []int
	}{
		{"site.example", "aa", []int{6, 30}},
		{"site.example", "bb", []int{7}},
		{"site.example", "zz", []int{16, 6}}, // a country the file does not list gets the general section
		{"site.example", "", []int{16, 6}},
		{"site.example", "AA", []int{16, 6}}, // codes are lower case; this is just an unknown one
		{"api.example", "aa", []int{16}},     // the part's own list for the country
		{"api.example", "bb", []int{8}},      // its own "*" beats the country's list
		{"api.example", "zz", []int{8}},
		{"none.example", "aa", nil}, // an empty list is "no way", not "use the country's"
		{"call.example", "aa", nil}, // a kind the library does not act on
	} {
		if got := nums(t, s, c.host, c.country); !eq(got, c.want) {
			t.Errorf("%s in %q: got %v, want %v", c.host, c.country, got, c.want)
		}
	}
	for country, want := range map[string][]int{"aa": {6, 30}, "bb": {7}, "zz": {16, 6}} {
		var got []int
		for _, st := range s.Site(country) {
			got = append(got, st.Num)
		}
		if !eq(got, want) {
			t.Errorf("own site in %q: got %v, want %v", country, got, want)
		}
	}
	if s.Candidates("aa", Match{}) != nil {
		t.Error("no match, no candidates")
	}
}

func TestCandidatesOrderOfEmbedded(t *testing.T) {
	s := Embedded()
	// Measured: only these three open the YouTube API name in the first country; the others open the rest.
	if got := nums(t, s, "youtubei.googleapis.com", "ru"); !eq(got, []int{16, 18, 20}) {
		t.Errorf("api in ru: %v", got)
	}
	// The first two are the ones that worked on both measured networks, so an unknown network starts with them.
	if got := nums(t, s, "www.youtube.com", "xx"); len(got) < 2 || got[0] != 6 || got[1] != 16 {
		t.Errorf("an unknown country starts with %v", got)
	}
	// What failed in a measured network is not offered first there.
	tr := nums(t, s, "discord.com", "tr")
	for _, n := range tr[:3] {
		if n == 2 || n == 8 || n == 15 {
			t.Errorf("tr starts with %v", tr)
		}
	}
}

func TestBlocksQUIC(t *testing.T) {
	s := mustParse(t, small)
	for _, c := range []struct {
		country, host string
		want          bool
	}{
		{"aa", "www.example.com", true},
		{"aa", "EXAMPLE.com.", true},
		{"bb", "www.example.com", false}, // the section of "*" has no quic_off
		{"aa", "other.net", false},
		{"aa", "", false},
	} {
		if got := s.BlocksQUIC(c.country, c.host); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	e := Embedded()
	if !e.BlocksQUIC("ru", "www.youtube.com") || !e.BlocksQUIC("ru", "rr1.googlevideo.com") || e.BlocksQUIC("tr", "www.youtube.com") {
		t.Error("QUIC to YouTube is refused where the strategies need it and not where YouTube opens")
	}
	if e.BlocksQUIC("ru", "discord.com") || e.BlocksQUIC("ru", "youtubei.googleapis.com") {
		t.Error("only the names of a quic-off part")
	}
}

func TestCatalog(t *testing.T) {
	s := Embedded()
	cat := s.Catalog("ru")
	if cat.Seq != s.Seq || cat.DateUnix != s.Date.Unix() || len(cat.Services) != len(s.Services) || len(cat.Categories) == 0 {
		t.Fatalf("%+v", cat)
	}
	byID := map[string]CatalogService{}
	for _, sv := range cat.Services {
		byID[sv.ID] = sv
	}
	yt := byID["yt"]
	if !yt.Ways || yt.Name != "YouTube" || yt.Icon == "" || len(yt.Categories) == 0 {
		t.Fatalf("%+v", yt)
	}
	for _, p := range yt.Parts {
		if p.ID == "api" {
			t.Error("a hidden part is not shown")
		}
	}
	if len(yt.Parts) != 3 || !yt.Parts[0].Supported {
		t.Errorf("parts of yt: %+v", yt.Parts)
	}
	if dc := byID["dc"]; !dc.Ways || dc.Parts[len(dc.Parts)-1].Supported {
		t.Errorf("voice is not supported yet: %+v", dc)
	}
	for _, id := range []string{"tg", "wa", "ig", "fb"} {
		if byID[id].Ways {
			t.Errorf("%s has no way", id)
		}
	}
	// Ready for JSON and free of the names the engine matches on.
	b, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	var back Catalog
	if err := json.Unmarshal(b, &back); err != nil || len(back.Services) != len(cat.Services) {
		t.Fatalf("round trip: %v", err)
	}
	for _, sv := range s.Services {
		for _, p := range sv.Parts {
			for _, d := range append(p.Domains, p.Checks...) {
				if strings.Contains(string(b), d) {
					t.Errorf("the catalog carries %q", d)
				}
			}
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("lists are empty lists, not null: %s", b)
	}
}

func BenchmarkMatch(b *testing.B) {
	s := Embedded()
	// The names of a connection: a service's deep name, an ordinary host, one that is only a miss.
	hosts := []string{"rr3---sn-4g5e6nzl.googlevideo.com", "www.youtube.com", "static.xx.fbcdn.example.net", "cdn.discordapp.com"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Match(hosts[i&3])
	}
}

func BenchmarkBlocksQUIC(b *testing.B) {
	s := Embedded()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.BlocksQUIC("ru", "rr3---sn-4g5e6nzl.googlevideo.com")
	}
}
