#ifndef __GENERIC_VMLINUX_H__
#define __GENERIC_VMLINUX_H__

#ifdef __TARGET_ARCH_x86
#include <x86_64/vmlinux.h>
#elif __TARGET_ARCH_arm64
#include <aarch64/vmlinux.h>
#else
#error "Usupported architecture. Please select an architecture in the list: x86_64, aarch64."
#endif

#endif
