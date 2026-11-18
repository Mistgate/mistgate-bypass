package sets

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// small is a valid file with one service of two parts, for the tests to break one thing at a time.
const small = `{
  "v": 1, "seq": 5, "date_unix": 1700000000,
  "strategies": { "21": "rec:s+2; cut:s+1; oob:0" },
  "countries": {
    "aa": { "quick": [6, 21], "quic_off": ["svc"] },
    "*":  { "quick": [16] }
  },
  "categories": ["popular"],
  "services": [
    { "id": "svc", "name": "Service", "icon": "globe", "categories": ["popular"],
      "parts": [
        { "id": "site", "kind": "tls", "domains": ["example.com"], "checks": ["https://www.example.com/"] },
        { "id": "quic", "kind": "quic-off", "domains": ["example.com"] } ] } ],
  "controls": { "*": ["https://control.example.net/"] }
}`

func keys(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(priv ed25519.PrivateKey, data string) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(data))) + "\n")
}

// mustCode fails the test unless err is an *Error with the code, and is not a panic's way out.
func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := Code(err); err == nil || got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

func TestOpenAcceptsSignedFile(t *testing.T) {
	pub, priv := keys(t)
	s, err := OpenWith(pub, []byte(small), sign(priv, small), 5)
	if err != nil {
		t.Fatal(err)
	}
	if s.Seq != 5 || s.Date.Unix() != 1700000000 || len(s.Services) != 1 || len(s.Services[0].Parts) != 2 {
		t.Fatalf("read wrongly: %+v", s)
	}
	if st := s.Site("aa"); len(st) != 2 || st[0].Num != 6 || st[1].Num != 21 || st[1].Spec().String() != "rec:s+2; cut:s+1; oob:0" {
		t.Fatalf("aa candidates: %+v", st)
	}
}

func TestOpenRefusesWhatIsNotTheProjects(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	good := sign(priv, small)
	tampered := strings.Replace(small, `"seq": 5`, `"seq": 6`, 1)
	for name, c := range map[string]struct {
		key  ed25519.PublicKey
		data string
		sig  []byte
	}{
		"changed file":          {pub, tampered, good},
		"another key":           {otherPub, small, good},
		"signed by another":     {pub, small, sign(otherPriv, small)},
		"no signature":          {pub, small, nil},
		"not base64":            {pub, small, []byte("!!!not base64!!!")},
		"short signature":       {pub, small, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32)))},
		"key of the wrong size": {pub[:10], small, good},
		// The file is garbage as well: the signature is the first thing checked, so the answer is still about it.
		"garbage and no signature": {pub, "not json at all", nil},
	} {
		_, err := OpenWith(c.key, []byte(c.data), c.sig, 0)
		if Code(err) != CodeBadSig {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOpenRefusesRollback(t *testing.T) {
	pub, priv := keys(t)
	sig := sign(priv, small)
	_, err := OpenWith(pub, []byte(small), sig, 6)
	mustCode(t, err, CodeRollback)
	if _, err := OpenWith(pub, []byte(small), sig, 5); err != nil { // the same seq again is not a rollback
		t.Fatal(err)
	}
}

func TestOpenRefusesBigFile(t *testing.T) {
	pub, priv := keys(t)
	big := small + strings.Repeat(" ", MaxFileSize)
	_, err := OpenWith(pub, []byte(big), sign(priv, big), 0)
	mustCode(t, err, CodeTooLarge)
}

// Until the owner puts the project key in, nothing that arrives from outside can be accepted.
func TestOpenWithoutProjectKey(t *testing.T) {
	if ProjectKey != "" {
		t.Skip("the project key is set")
	}
	_, priv := keys(t)
	_, err := Open([]byte(small), sign(priv, small), 0)
	mustCode(t, err, CodeNoKey)
}

func TestProjectKeyShape(t *testing.T) {
	if ProjectKey == "" {
		return
	}
	if b, err := hex.DecodeString(ProjectKey); err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("ProjectKey is not 32 bytes in hex")
	}
}

func TestStrategyNumbersAreFree(t *testing.T) {
	if FirstCustom != len(dpi.Ladder())+1 {
		t.Fatalf("FirstCustom is %d, the ladder has %d strategies", FirstCustom, len(dpi.Ladder()))
	}
}

// Every way a file can be wrong is an error with a code, never a panic and never a half-built set.
func TestParseRefuses(t *testing.T) {
	rep := func(old, new string) string {
		if !strings.Contains(small, old) {
			t.Fatalf("test bug: %q not in the base file", old)
		}
		return strings.Replace(small, old, new, 1)
	}
	manyServices := func(n int) string {
		var sb strings.Builder
		sb.WriteString(`{"v":1,"seq":1,"countries":{"*":{"quick":[6]}},"services":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"id":"s%d","name":"S","parts":[{"id":"p","kind":"tls"}]}`, i)
		}
		sb.WriteString("]}")
		return sb.String()
	}
	nums := func(n int) string { return strings.TrimSuffix(strings.Repeat("6,", n), ",") }
	for name, c := range map[string]struct{ data, code string }{
		"empty":                        {"", CodeBadJSON},
		"garbage":                      {"\x00\xff{{{", CodeBadJSON},
		"array":                        {"[1,2]", CodeBadJSON},
		"trailing data":                {small + " {}", CodeBadJSON},
		"unknown version":              {rep(`"v": 1`, `"v": 2`), CodeBadVersion},
		"future version, other shape":  {`{"v": 9, "seq": "later", "services": 5}`, CodeBadVersion},
		"no version":                   {rep(`"v": 1, `, ``), CodeBadVersion},
		"no seq":                       {rep(`"seq": 5, `, ``), CodeBadField},
		"negative seq":                 {rep(`"seq": 5`, `"seq": -5`), CodeBadJSON},
		"wrong type":                   {rep(`"quick": [16]`, `"quick": "16"`), CodeBadJSON},
		"no default section":           {rep(`"*":  { "quick": [16] }`, `"zz": { "quick": [16] }`), CodeNoDefault},
		"country in capitals":          {rep(`"aa":`, `"AA":`), CodeBadField},
		"country of 3 letters":         {rep(`"aa":`, `"aaa":`), CodeBadField},
		"spec outside grammar":         {rep(`rec:s+2; cut:s+1; oob:0`, `cut:banana`), CodeBadSpec},
		"empty spec":                   {rep(`rec:s+2; cut:s+1; oob:0`, ` `), CodeBadSpec},
		"redefines a permanent number": {rep(`"21":`, `"5":`), CodeBadField},
		"number of a device search":    {rep(`"21":`, `"1000":`), CodeBadField},
		"number not canonical":         {rep(`"21":`, `"021":`), CodeBadField},
		"unknown strategy in a list":   {rep(`[6, 21]`, `[6, 22]`), CodeUnknownRef},
		"plain as a candidate":         {rep(`[6, 21]`, `[1, 6]`), CodeBadField},
		"repeat in a list":             {rep(`[6, 21]`, `[6, 6]`), CodeDuplicate},
		"too long a list":              {rep(`[6, 21]`, `[`+nums(MaxCandidates+1)+`]`), CodeLimit},
		"quic_off names no service":    {rep(`["svc"]`, `["nothing"]`), CodeUnknownRef},
		"category not declared":        {rep(`"icon": "globe", "categories": ["popular"]`, `"icon": "globe", "categories": ["other"]`), CodeUnknownRef},
		"category listed twice":        {rep(`"icon": "globe", "categories": ["popular"]`, `"icon": "globe", "categories": ["popular","popular"]`), CodeUnknownRef},
		"id in capitals":               {rep(`"id": "svc"`, `"id": "Svc"`), CodeBadField},
		"no name":                      {rep(`"name": "Service"`, `"name": ""`), CodeBadField},
		"part twice":                   {rep(`"id": "quic"`, `"id": "site"`), CodeBadField},
		"no parts":                     {rep(`"parts": [`, `"parts": [],"x": [`), CodeLimit},
		"domain of one label":          {rep(`"domains": ["example.com"], "checks"`, `"domains": ["com"], "checks"`), CodeBadField},
		"domain in capitals":           {rep(`"domains": ["example.com"], "checks"`, `"domains": ["Example.com"], "checks"`), CodeBadField},
		"domain with a dot at the end": {rep(`"domains": ["example.com"], "checks"`, `"domains": ["example.com."], "checks"`), CodeBadField},
		"domain that is an address":    {rep(`"domains": ["example.com"], "checks"`, `"domains": ["10.0.0.1"], "checks"`), CodeBadField},
		"domain in two parts":          {rep(`"domains": ["example.com"] } ]`, `"domains": ["example.com"] }, {"id":"more","kind":"tls","domains":["example.com"]} ]`), CodeDuplicate},
		"check over http":              {rep(`https://www.example.com/`, `http://www.example.com/`), CodeBadField},
		"check with a login":           {rep(`https://www.example.com/`, `https://user:pw@www.example.com/`), CodeBadField},
		"control not an address":       {rep(`https://control.example.net/`, `control`), CodeBadField},
		"too many services":            {manyServices(MaxServices + 1), CodeLimit},
	} {
		if c.code == "" {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic: %v", name, r)
				}
			}()
			if _, err := parse([]byte(c.data)); Code(err) != c.code {
				t.Errorf("%s: got %v, want code %s", name, err, c.code)
			}
		}()
	}
	if _, err := parse([]byte(manyServices(MaxServices))); err != nil {
		t.Errorf("exactly MaxServices is allowed: %v", err)
	}
}

func TestParseRefusesRepeats(t *testing.T) {
	const head = `{"v":1,"seq":1,"countries":{"*":{"quick":[6]}},"services":[`
	for name, body := range map[string]string{
		"a name in two services": `{"id":"a","name":"A","parts":[{"id":"p","kind":"tls","domains":["example.com"]}]},
			{"id":"b","name":"B","parts":[{"id":"p","kind":"tls","domains":["example.com"]}]}`,
		"a service twice": `{"id":"a","name":"A","parts":[{"id":"p","kind":"tls"}]},
			{"id":"a","name":"B","parts":[{"id":"p","kind":"tls"}]}`,
		"a name twice in a part": `{"id":"a","name":"A","parts":[{"id":"p","kind":"tls","domains":["example.com","example.com"]}]}`,
	} {
		_, err := parse([]byte(head + body + `]}`))
		if Code(err) != CodeDuplicate {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A file of a later release has fields this code does not know, a part kind it cannot act on, and still reads.
func TestParseKeepsWhatItDoesNotKnow(t *testing.T) {
	later := strings.NewReplacer(
		`"v": 1,`, `"v": 1, "min_client": "9.0.0", "dns": {"doh": []},`,
		`"icon": "globe",`, `"icon": "globe", "tone": "rose", "countries": ["*"],`,
		`"id": "site",`, `"id": "site", "ports": ["1-2"], "weight": 3,`,
		`"quick": [16] }`, `"quick": [16], "deep": true }`,
	).Replace(small)
	later = strings.Replace(later, `"parts": [`, `"parts": [{"id":"call","kind":"voice","ports":["19294-19344"]},`, 1)
	s, err := parse([]byte(later))
	if err != nil {
		t.Fatal(err)
	}
	p := &s.Services[0].Parts[0]
	if p.ID != "call" || p.Supported() {
		t.Fatalf("a part of a kind the library does not know: %+v", p)
	}
	if len(s.Candidates("aa", Match{&s.Services[0], p})) != 0 {
		t.Fatal("a part that is not supported has no candidates")
	}
}

func TestEmbedded(t *testing.T) {
	s := Embedded()
	if s != Embedded() || s.Seq == 0 {
		t.Fatal("the embedded set is parsed once")
	}
	// Whatever a country can try is a strategy dpi can run: the specs were parsed with the file.
	for c, sec := range s.sections {
		if len(sec.quick) == 0 {
			t.Errorf("%s has nothing to try", c)
		}
		for _, st := range sec.quick {
			if _, err := dpi.ParseSpec(st.Spec().String()); err != nil || st.Num <= 1 {
				t.Errorf("%s: strategy %d: %v", c, st.Num, err)
			}
		}
	}
	if _, ok := s.sections["*"]; !ok {
		t.Fatal("no general section")
	}
	// The format was proven on "the service is here and there is no way": the window gets such services and hides them.
	var with, without int
	for _, sv := range s.Catalog("ru").Services {
		if sv.Ways {
			with++
		} else {
			without++
		}
	}
	if with < 2 || without < 1 {
		t.Fatalf("services with ways %d, without %d", with, without)
	}
}

// The embedded set is checked by the same gate as a downloaded one: signed by a test key it passes Open.
func TestEmbeddedFileThroughOpen(t *testing.T) {
	pub, priv := keys(t)
	s, err := OpenWith(pub, embedded, sign(priv, string(embedded)), Embedded().Seq)
	if err != nil || s.Seq != Embedded().Seq {
		t.Fatalf("%v", err)
	}
	_, err = OpenWith(pub, embedded, sign(priv, string(embedded)), Embedded().Seq+1)
	mustCode(t, err, CodeRollback)
}

func TestErrorIsReadable(t *testing.T) {
	_, err := parse([]byte(`{"v":1,"seq":1,"strategies":{"21":"cut:banana"},"countries":{"*":{}}}`))
	if !errors.Is(err, dpi.ErrBadSpec) || Code(err) != CodeBadSpec {
		t.Fatalf("%v", err)
	}
	if Code(errors.New("other")) != "" || Code(nil) != "" {
		t.Fatal("not ours")
	}
}
