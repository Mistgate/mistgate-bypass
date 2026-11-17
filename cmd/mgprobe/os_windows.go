//go:build windows

package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d (build %d)", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// setupConsole switches the console to UTF-8 so the non-Latin progress lines are readable.
func setupConsole() { _ = windows.SetConsoleOutputCP(65001) }

func isReset(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED) || errors.Is(err, syscall.ECONNRESET)
}

func isRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}

// listProcesses returns the executable names of the running processes (a snapshot, readable without rights).
func listProcesses() ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var names []string
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		names = append(names, windows.UTF16ToString(e.ExeFile[:]))
	}
	return names, nil
}

// defaultRouteTypes asks the routing table which interface a packet to a public address would leave through,
// for one address from each half of the address space (so a 0.0.0.0/1 + 128.0.0.0/1 pair is seen too), and
// returns the types of those interfaces. Nothing is sent. Only the type number leaves this function.
func defaultRouteTypes() ([]int, error) {
	types, err := adapterTypes()
	if err != nil {
		return nil, err
	}
	var out []int
	for _, a := range [][4]byte{{8, 8, 8, 8}, {200, 1, 1, 1}} {
		var idx uint32
		if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: a}, &idx); err != nil {
			return nil, err
		}
		t, ok := types[idx]
		if !ok {
			return nil, errors.New("no adapter for the best interface")
		}
		if !slices.Contains(out, int(t)) {
			out = append(out, int(t))
		}
	}
	return out, nil
}

// adapterTypes maps interface index to interface type; names and addresses are not looked at.
func adapterTypes() (map[uint32]uint32, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	for try := 0; try < 4; try++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		m := map[uint32]uint32{}
		for a := aa; a != nil; a = a.Next {
			m[a.IfIndex] = a.IfType
			if a.Ipv6IfIndex != 0 {
				m[a.Ipv6IfIndex] = a.IfType
			}
		}
		return m, nil
	}
	return nil, errors.New("adapter list too large")
}

// windivertLoaded looks for a running driver service whose name starts with WinDivert. The service manager lets
// any user list services, so no rights are needed.
func windivertLoaded() (bool, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return false, err
	}
	defer windows.CloseServiceHandle(m)
	var buf []byte
	var need, count uint32
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_DRIVER, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &need, &count, nil, nil)
		if err == nil {
			break
		}
		if err != syscall.ERROR_MORE_DATA || need <= uint32(len(buf)) {
			return false, err
		}
		buf = make([]byte, need)
	}
	if count == 0 {
		return false, nil
	}
	for _, s := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(count)) {
		if strings.HasPrefix(strings.ToLower(windows.UTF16PtrToString(s.ServiceName)), "windivert") &&
			s.ServiceStatusProcess.CurrentState == windows.SERVICE_RUNNING {
			return true, nil
		}
	}
	return false, nil
}
