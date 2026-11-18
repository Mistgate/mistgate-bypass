package sets

import (
	_ "embed"
	"sync"
)

//go:embed bypass.json
var embedded []byte

// Embedded is the set that is part of the program: the fallback before any file has been downloaded, and when the
// downloaded one is refused. Its seq is the floor for Open's cur.
//
// It is read with the same strict parser as a downloaded file but is not signed. The signature protects a file that
// travels over a network and through hands of third parties; this one is compiled into the program, and whoever
// can change it can change ProjectKey beside it, so a signature would prove nothing. TestEmbedded keeps it valid.
func Embedded() *Set { return embeddedSet() }

var embeddedSet = sync.OnceValue(func() *Set {
	s, err := parse(embedded)
	if err != nil {
		panic(err) // the file is code: TestEmbedded parses it
	}
	return s
})
