//go:build !windows

package rpc

import "syscall"

func setUmask(m int) int { return syscall.Umask(m) }
