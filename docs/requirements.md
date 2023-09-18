# Requirements

All requirements are for commands collecting events, for now only `collect`.

Mandatory requirements:

- Retis needs `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_SYSLOG` and access to all files
  listed in the [requirements](#requirements).

- The following kernel configuration:
  - `CONFIG_BPF_SYSCALL=y`.
  - `CONFIG_DEBUG_INFO_BTF=y` to parse kernel functions and types.

- Access to `/sys/kernel/btf` and `/proc/kallsyms`.

Not strictly required but best for user experience and feature scope:

- The following kernel configuration:
  - `CONFIG_KPROBES=y` to allow using kprobes.
  - `CONFIG_PERF_EVENTS=y` to retrieve stack traces (& probably more).

- `debugfs` mounted to `/sys/kernel/debug` to allow filtering functions and
  events.

- `/etc/os-release` to gather information about the current distribution.

## Supported operating systems

Those are operating systems we know are compatible with running Retis. Of course
the list is not exhaustive (let us know if we can add new lines).

| Operating system | Notes                                                |
| ---------------- | ---------------------------------------------------- |
| Fedora           | All officially supported versions including Rawhide  |
| RHEL9            |                                                      |
| CentOS Stream 9  |                                                      |
| RHEL8            | >= 8.6                                               |
| Ubuntu Jammy     |                                                      |

