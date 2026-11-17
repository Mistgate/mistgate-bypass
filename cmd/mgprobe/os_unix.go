//go:build unix

package main

import (
	"context"
	"errors"
	"os/exec"
	"path"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

// run is a short-lived system tool, read-only: ps, route, ip, sw_vers.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func osVersion() string {
	if runtime.GOOS == "darwin" {
		if v, err := run("sw_vers", "-productVersion"); err == nil {
			return "macOS " + strings.TrimSpace(v) + " (" + runtime.GOARCH + ")"
		}
	}
	return runtime.GOOS + " (" + runtime.GOARCH + ")"
}

func setupConsole() {}

func isReset(err error) bool   { return errors.Is(err, syscall.ECONNRESET) }
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// listProcesses returns the program names of the running processes, without their paths.
func listProcesses() ([]string, error) {
	out, err := run("ps", "-axo", "comm=")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, path.Base(line))
		}
	}
	return names, nil
}

// defaultRouteTypes asks the routing table which interface a packet to a public address would leave through, for one
// address from each half of the address space, and turns the name of the interface into a type: only the type leaves
// this function. Nothing is sent.
func defaultRouteTypes() ([]int, error) {
	var out []int
	for _, a := range []string{"8.8.8.8", "200.1.1.1"} {
		name, err := routeInterface(a)
		if err != nil {
			return nil, err
		}
		if t := ifTypeOfName(name); !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

func routeInterface(addr string) (string, error) {
	if runtime.GOOS == "darwin" {
		out, err := run("route", "-n", "get", addr)
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "interface:" {
				return f[1], nil
			}
		}
		return "", errors.New("no interface in the route")
	}
	out, err := run("ip", "-o", "route", "get", addr)
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	for i := range f {
		if f[i] == "dev" && i+1 < len(f) {
			return f[i+1], nil
		}
	}
	return "", errors.New("no interface in the route")
}

// ifTypeOfName maps an interface name to the IANA type the report uses. macOS calls both Ethernet and Wi-Fi "enN",
// so both come out as Ethernet there.
func ifTypeOfName(name string) int {
	for _, p := range []string{"utun", "tun", "tap", "wg", "ipsec", "gif", "stf", "tailscale", "zt"} {
		if strings.HasPrefix(name, p) {
			return 131 // tunnel
		}
	}
	switch {
	case strings.HasPrefix(name, "ppp"):
		return 23
	case strings.HasPrefix(name, "wl"):
		return 71
	case strings.HasPrefix(name, "en"), strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "bridge"):
		return 6
	case strings.HasPrefix(name, "pdp_ip"), strings.HasPrefix(name, "rmnet"), strings.HasPrefix(name, "wwan"):
		return 243
	case strings.HasPrefix(name, "lo"):
		return 24
	}
	return 1
}

// There is no such driver outside Windows.
func windivertLoaded() (bool, error) { return false, nil }
