//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func windowsVersion() string { return "not Windows" }
func setupConsole()          {}

func isReset(err error) bool   { return errors.Is(err, syscall.ECONNRESET) }
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// The environment checks are implemented for Windows only.
func listProcesses() ([]string, error)  { return nil, errors.ErrUnsupported }
func defaultRouteTypes() ([]int, error) { return nil, errors.ErrUnsupported }
func windivertLoaded() (bool, error)    { return false, errors.ErrUnsupported }
