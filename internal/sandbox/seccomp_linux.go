// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

func applySeccomp(cfg SeccompConfig, mode Mode) (string, error) {
	if !seccomp.Supported() {
		err := errors.New("seccomp syscall not supported by this kernel")
		if mode == ModeBestEffort || mode == ModeTry {
			return "", err
		}
		return "", err
	}

	actionName, action, err := denyAction(cfg.DenyAction)
	if err != nil {
		return "", err
	}

	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: action,
					Names:  deniedSyscalls(),
				},
			},
		},
	}

	if err := seccomp.LoadFilter(filter); err != nil {
		if mode == ModeBestEffort && isSeccompUnavailable(err) {
			return "", err
		}
		return "", fmt.Errorf("load filter: %w", err)
	}

	return "denylist+" + actionName, nil
}

func denyAction(name string) (string, seccomp.Action, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "errno":
		return "errno", seccomp.ActionErrno | seccomp.Action(syscall.EPERM), nil
	case "kill_thread", "kill":
		return "kill_thread", seccomp.ActionKillThread, nil
	case "kill_process":
		return "kill_process", seccomp.ActionKillProcess, nil
	case "trap":
		return "trap", seccomp.ActionTrap, nil
	case "log":
		return "log", seccomp.ActionLog, nil
	default:
		return "", 0, fmt.Errorf("seccomp deny_action %q is invalid", name)
	}
}

func isSeccompUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOSYS || errno == syscall.EPERM || errno == syscall.EINVAL
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "invalid argument")
}

func deniedSyscalls() []string {
	return []string{
		"acct",
		"add_key",
		"bpf",
		"clock_adjtime",
		"clock_settime",
		"create_module",
		"delete_module",
		"fanotify_init",
		"finit_module",
		"get_kernel_syms",
		"get_mempolicy",
		"init_module",
		"iopl",
		"ioperm",
		"kcmp",
		"kexec_file_load",
		"kexec_load",
		"keyctl",
		"lookup_dcookie",
		"mbind",
		"mount",
		"move_pages",
		"name_to_handle_at",
		"nfsservctl",
		"open_by_handle_at",
		"perf_event_open",
		"personality",
		"pivot_root",
		"process_vm_readv",
		"process_vm_writev",
		"ptrace",
		"query_module",
		"quotactl",
		"reboot",
		"request_key",
		"set_mempolicy",
		"setns",
		"settimeofday",
		"stime",
		"swapon",
		"swapoff",
		"sysfs",
		"_sysctl",
		"umount",
		"umount2",
		"unshare",
		"uselib",
		"userfaultfd",
		"ustat",
		"vm86",
		"vm86old",
	}
}
