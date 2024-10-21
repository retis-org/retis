ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LLC := llc
CLANG := clang
OBJCOPY := llvm-objcopy

CARGO := cargo $(CARGO_OPTS)
DEFAULT_ARCH := $(patsubst target_arch="%",%,$(filter target_arch="%",$(shell rustc --print cfg)))
ARCH := $(if $(CARGO_BUILD_TARGET),$(firstword $(subst -, ,$(CARGO_BUILD_TARGET))),$(DEFAULT_ARCH))

RELEASE_VERSION = $(shell tools/localversion)
RELEASE_NAME ?= $(shell $(CARGO) metadata --no-deps --format-version=1 | jq -r '.packages | .[] | select(.name=="retis") | .metadata.misc.release_name')

export ARCH CFLAGS CLANG LCC OBJCOPY RELEASE_NAME RELEASE_VERSION RUSTFLAGS

PRINT = printf

define help_once
    @$(PRINT) '$(1)\n'
endef

VERBOSITY := $(filter 1,$(V))

ifeq ($(VERBOSITY),)
    Q=@
    MAKE += -s
    CARGO += -q
define out_console
    $(PRINT) "[$(1)]\t$(2)\n"
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
	$(CARGO) install $(CARGO_INSTALL_OPTS) --path=$(ROOT_DIR)/retis --offline --frozen

define build
	$(call out_console,CARGO,$(strip $(2)) ...)
	jobs=$(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS))); \
	CARGO_BUILD_JOBS=$${jobs:-1} \
	$(CARGO) $(1) $(CARGO_CMD_OPTS)
endef

debug: ebpf
	$(call build, build, building retis (debug))

release: ebpf
	$(eval RUSTFLAGS += -D warnings)
	$(call build, build --release, building retis (release))

test: ebpf
ifeq ($(COV),1)
	$(CARGO) llvm-cov clean --workspace -q
	$(call build,llvm-cov $(if $(VERBOSITY),,-q),running tests with coverage)
else
	$(call build,test,building and running tests)
endif

bench: ebpf
	$(call build, build -F benchmark --release, building benchmarks)

ifeq ($(COV),1)
report:
	$(CARGO) llvm-cov report --html
endif

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
	CFLAGS_INCLUDES="$(INCLUDES)" \
	$(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $@

rust-analyzer:
	$(CARGO) check --quiet --message-format=json --all-targets --keep-going

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
ifeq ($(COV),1)
	$(CARGO) llvm-cov clean --workspace
endif
	$(CARGO) clean

help:
	$(call help_once,all                 --  Builds the tool (both eBPF programs and retis).)
	$(call help_once,bench               --  Builds benchmarks.)
	$(call help_once,clean               --  Deletes all the files generated during the build process)
	$(call help_once,                        (eBPF and rust directory).)
	$(call help_once,clean-ebpf          --  Deletes all the files generated during the build process)
	$(call help_once,                        (eBPF only).)
	$(call help_once,ebpf                --  Builds only the eBPF programs.)
	$(call help_once,install             --  Installs Retis.)
	$(call help_once,release             --  Builds Retis with the release option.)
	$(call help_once,rust-analyzer       --  Runs cargo check. The target is always verbose regardless of $$(V).)
	$(call help_once,test                --  Builds and runs unit tests.)
	$(call help_once)
	$(call help_once,Optional variables that can be used to override the default behavior:)
	$(call help_once,V                   --  If set to 1 the verbose output will be printed.)
	$(call help_once,                        cargo verbosity is set to default.)
	$(call help_once,                        To override `cargo` behavior please refer to $$(CARGO_OPTS),)
	$(call help_once,                        $$(CARGO_CMD_OPTS) and for the install $$(CARGO_INSTALL_OPTS).)
	$(call help_once,                        For further `cargo` customization please refer to configuration)
	$(call help_once,                        environment variables)
	$(call help_once,                        (https://doc.rust-lang.org/cargo/reference/environment-variables.html).)
	$(call help_once,CARGO_CMD_OPTS      --  Changes `cargo` subcommand default behavior (e.g. --features <features> for `build`).)
	$(call help_once,CARGO_INSTALL_OPTS  --  Changes `cargo` install subcommand default behavior.)
	$(call help_once,CARGO_OPTS          --  Changes `cargo` default behavior (e.g. --verbose).)
	$(call help_once,NOVENDOR            --  Avoid to self detect and consume the vendored headers)
	$(call help_once,                        shipped with libbpf-sys.)
	$(call help_once,COV                 --  enable code coverage for testing.)

.PHONY: all bench clean clean-ebpf ebpf $(EBPF_PROBES) $(EBPF_HOOKS) help install release test
