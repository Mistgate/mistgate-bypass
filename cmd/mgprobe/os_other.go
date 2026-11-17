//go:build !windows && !unix

package main

import (
	"errors"
	"runtime"
	"syscall"
)

func osVersion() string { return runtime.GOOS }
func setupConsole()     {}

func isReset(err error) bool   { return errors.Is(err, syscall.ECONNRESET) }
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// The environment checks are implemented for Windows and Unix systems.
func listProcesses() ([]string, error)  { return nil, errors.ErrUnsupported }
func defaultRouteTypes() ([]int, error) { return nil, errors.ErrUnsupported }
func windivertLoaded() (bool, error)    { return false, errors.ErrUnsupported }
