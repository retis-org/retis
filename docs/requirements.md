# Requirements

All the following requirements are for commands collecting events only; such as
the `collect` sub-command.

- The Retis binary needs `CAP_SYS_ADMIN`, `CAP_BPF` and `CAP_SYSLOG` to be set.
- The running kernel should have been compiled with the right
  [set of options](#kernel-kconfig-options).
- Access to `/sys/kernel/btf` and `/proc/kallsyms` to parse kernel functions and
  types.
- `tracefs` should be mounted to `/sys/kernel/tracing` or
  `/sys/kernel/debug/tracing` to allow filtering functions and events (or
  `--allow-system-changes` must be set).

## Kernel Kconfig options

In order to collect events Retis requires some options to be set in the running
kernel:

- `CONFIG_BPF_SYSCALL`
- `CONFIG_DEBUG_FS`
- `CONFIG_DEBUG_INFO_BTF`
- `CONFIG_KALLSYMS_ALL`
- `CONFIG_KPROBES`
- `CONFIG_PERF_EVENTS` (to retrieve stack traces & probably more)

## Supported operating systems

Those are operating systems we know are compatible with running Retis. The list
is not exhaustive and Retis should be able to run on other distributions.

| Operating system | Notes                                                |
| ---------------- | ---------------------------------------------------- |
| Fedora           | All officially supported versions including Rawhide  |
| RHEL9            |                                                      |
| CentOS Stream 9  |                                                      |
| RHEL8            | >= 8.6                                               |
| CentOS Stream 8  | >= 8.6                                               |
| Ubuntu Jammy     |                                                      |

