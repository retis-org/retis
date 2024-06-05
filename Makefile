ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LLC := llc
CLANG := clang
OBJCOPY := llvm-objcopy

CARGO := cargo
DEFAULT_ARCH := $(patsubst target_arch="%",%,$(filter target_arch="%",$(shell rustc --print cfg)))
CARGO_CFG_TARGET_ARCH := $(if $(ARCH),$(ARCH),$(DEFAULT_ARCH))

RELEASE_VERSION = $(shell tools/localversion)
RELEASE_NAME ?= $(shell $(CARGO) metadata --no-deps --format-version=1 | jq -r '.packages | .[] | select(.name=="retis") | .metadata.misc.release_name')

export LLC CLANG CARGO_CFG_TARGET_ARCH OBJCOPY RELEASE_NAME RELEASE_VERSION RUSTFLAGS

PRINT = echo

VERBOSITY := $(filter 1,$(V))

ifeq ($(VERBOSITY),)
    Q=@
    MAKE += -s
    CARGO += -q
define out_console
    $(PRINT) -e "[$(1)]\t$(2)"
endef

.SILENT:
endif

ifeq ($(NOVENDOR),)
    # This MUST be kept in sync with API_HEADERS under lib.rs in libbpf-sys
    LIBBPF_API_HEADERS := bpf.h \
                          libbpf.h \
                          btf.h \
                          bpf_helpers.h \
                          bpf_helper_defs.h \
                          bpf_tracing.h \
                          bpf_endian.h \
                          bpf_core_read.h \
                          libbpf_common.h \
                          usdt.bpf.h

    LIBBPF_SYS_LIBBPF_BASE_PATH := $(dir $(shell cargo metadata --format-version=1 | jq -r '.packages | .[] | select(.name == "libbpf-sys") | .manifest_path'))
    LIBBPF_SYS_LIBBPF_INCLUDES :=  $(wildcard $(addprefix $(LIBBPF_SYS_LIBBPF_BASE_PATH)/libbpf/src/, $(LIBBPF_API_HEADERS)))
    LIBBPF_INCLUDES := $(ROOT_DIR)/retis/src/.out
endif

# Taking errno.h from libc instead of linux headers.
# TODO: Remove when we fix proper header dependencies.
INCLUDES_ALL := $(abspath $(wildcard $(shell find retis/src -type d -path '*/bpf/include') \
                                     /usr/include/x86_64-linux-gnu))
INCLUDES_ALL += $(LIBBPF_INCLUDES)

INCLUDES := $(addprefix -I, $(INCLUDES_ALL))

EBPF_PROBES := $(abspath $(wildcard retis/src/core/probe/*/bpf))

EBPF_HOOKS := $(abspath $(wildcard retis/src/module/*/bpf))

all: debug

install: release
	$(CARGO) $(CARGO_OPTS) install $(CARGO_INSTALL_OPTS) --path=. --offline --frozen

define build
	$(call out_console,CARGO,$(strip $(2)) ...)
	jobs=$(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS))); \
	CARGO_BUILD_JOBS=$${jobs:-1} \
	$(CARGO) $(CARGO_OPTS) $(1) $(CARGO_CMD_OPTS)
endef

debug: ebpf
	$(call build, build, building retis (debug))

release: RUSTFLAGS += -D warnings
release: ebpf
	$(call build, build --release, building retis (release))

test: ebpf
	$(call build, test, building and running tests)

bench: ebpf
	$(call build, build -F benchmark --release, building benchmarks)

ifeq ($(NOVENDOR),)
$(LIBBPF_INCLUDES): $(LIBBPF_SYS_LIBBPF_INCLUDES)
	-mkdir -p $(LIBBPF_INCLUDES)/bpf
	cp $^ $(LIBBPF_INCLUDES)/bpf/
endif

ebpf: $(EBPF_PROBES) $(EBPF_HOOKS)

$(EBPF_PROBES): OUT_NAME := PROBE
$(EBPF_HOOKS):  OUT_NAME := HOOK
$(EBPF_PROBES) $(EBPF_HOOKS): $(LIBBPF_INCLUDES)
	$(call out_console,$(OUT_NAME),building $@ ...)
	CFLAGS="$(INCLUDES)" \
	$(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $@ $(TGT)

clean-ebpf:
	$(call out_console,CLEAN,cleaning ebpf progs...)
	for i in $(EBPF_PROBES) $(EBPF_HOOKS); do \
	    $(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $$i clean; \
	done
	-if [ -n "$(LIBBPF_INCLUDES)" ]; then \
	    rm -rf $(LIBBPF_INCLUDES); \
	fi

clean: clean-ebpf
	$(call out_console,CLEAN,cleaning retis ...)
	$(CARGO) clean

help:
	$(PRINT) 'all                 --  Builds the tool (both eBPF programs and retis).'
	$(PRINT) 'bench               --  Builds benchmarks.'
	$(PRINT) 'clean               --  Deletes all the files generated during the build process'
	$(PRINT) '	                  (eBPF and rust directory).'
	$(PRINT) 'clean-ebpf          --  Deletes all the files generated during the build process'
	$(PRINT) '	                  (eBPF only).'
	$(PRINT) 'ebpf                --  Builds only the eBPF programs.'
	$(PRINT) 'install             --  Installs Retis.'
	$(PRINT) 'release             --  Builds Retis with the release option.'
	$(PRINT) 'test                --  Builds and runs unit tests.'
	$(PRINT)
	$(PRINT) 'Optional variables that can be used to override the default behavior:'
	$(PRINT) 'V                   --  If set to 1 the verbose output will be printed.'
	$(PRINT) '                        cargo verbosity is set to default.'
	$(PRINT) '                        To override `cargo` behavior please refer to $$(CARGO_OPTS),'
	$(PRINT) '                        $$(CARGO_CMD_OPTS) and for the install $$(CARGO_INSTALL_OPTS).'
	$(PRINT) '                        For further `cargo` customization please refer to configuration'
	$(PRINT) '                        environment variables'
	$(PRINT) '                        (https://doc.rust-lang.org/cargo/reference/environment-variables.html).'
	$(PRINT) 'CARGO_CMD_OPTS      --  Changes `cargo` subcommand default behavior (e.g. --release for `build`).'
	$(PRINT) 'CARGO_INSTALL_OPTS  --  Changes `cargo` install subcommand default behavior.'
	$(PRINT) 'CARGO_OPTS          --  Changes `cargo` default behavior (e.g. --verbose).'
	$(PRINT) 'NOVENDOR            --  Avoid to self detect and consume the vendored headers'
	$(PRINT) '                        shipped with libbpf-sys.'

.PHONY: all bench clean clean-ebpf ebpf $(EBPF_PROBES) $(EBPF_HOOKS) help install release test
