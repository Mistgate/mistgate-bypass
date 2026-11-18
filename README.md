# mistgate-bypass

Connection strategies that let a client reach a service whose first packet a middlebox on the path filters, without
a remote server, and a probe that measures which of them work on a given network.

- `dpi/` — the library: parsing of a TLS ClientHello, the ladder of strategies that cut and order its first bytes on
  an ordinary socket, the wrapper that applies one to a connection, decoy datagrams before the first UDP packet.
  Standard library and `golang.org/x/sys` only.
- `dpitest/` — a stand-in for the filter of a network, for tests: a TCP proxy on loopback that drops a connection when its
  first flight matches a predicate (the name whole in one segment, or in one TLS record, or in the first two segments,
  a block on the address), so that a test can ask which strategies get through. Standard library only.
- `sets/` — the set of strategies as a signed file: which strategies to try for which service in which country, the
  catalogue of services, the match of a host name to a service, and the set built into the library.
- `flow/` — the ladder a new TLS connection climbs: the ordinary connection first, then, if the server stays silent, the
  strategies one after the other beside it, the first connection that is answered kept; single-flight per name, the
  memory of what each network has taught (in RAM, and on disk without the names of other people's sites), and the
  events that tell a window what opened by what. Tested against `dpitest`.
- `cmd/mgprobe/` — the probe: one Windows program, no installation and no administrator rights. It makes outgoing
  connections only, changes nothing on the machine and writes `mgprobe-report.txt` beside itself. The report carries no
  computer or user name, no local or public address of the user, no adapter or Wi-Fi names.

## Build and test

```
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mgprobe.exe ./cmd/mgprobe
```

## Credits

The decoy QUIC Initial in `cmd/mgprobe/fake/` and the ideas behind several strategies come from zapret2 by bol-van
(MIT License, see `cmd/mgprobe/fake/LICENSE.zapret2.txt`).

## License

GNU Affero General Public License v3.0, the same as the Mistgate panel and client: see `LICENSE`. Third-party
material is listed in `NOTICE`.
