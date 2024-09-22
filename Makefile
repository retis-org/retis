ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
LLC := llc
CLANG := clang
OBJCOPY := llvm-objcopy

CARGO := cargo
BINDGEN := bindgen
DEFAULT_ARCH := $(patsubst target_arch="%",%,$(filter target_arch="%",$(shell rustc --print cfg)))
ARCH := $(if $(CARGO_BUILD_TARGET),$(firstword $(subst -, ,$(CARGO_BUILD_TARGET))),$(DEFAULT_ARCH))

RELEASE_VERSION = $(shell tools/localversion)
RELEASE_NAME ?= $(shell $(CARGO) metadata --no-deps --format-version=1 | jq -r '.packages | .[] | select(.name=="retis") | .metadata.misc.release_name')

# Needs to be set because of PT_REGS_PARMx() and any other target
# specific facility.
x86_64 := x86
aarch64 := arm64
powerpc64 := powerpc
s390x := s390
# Mappings takes precedence over custom ARCH
BPF_ARCH := $(if $($(ARCH)),$($(ARCH)),$(ARCH))

BPF_CFLAGS := -target bpf \
              -Wall \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -fno-stack-protector \
              -Werror \
              -D__TARGET_ARCH_$(BPF_ARCH) \
              -O2

export BPF_ARCH BPF_CFLAGS CFLAGS CLANG LCC OBJCOPY RELEASE_NAME RELEASE_VERSION RUSTFLAGS

PRINT = printf

VERBOSITY := $(filter 1,$(V))

ifeq ($(VERBOSITY),)
    Q=@
    MAKE += -s
    CARGO += -q
define out_console
    $(PRINT) "[$(1)]\t$(2)\n"
endef

.SILENT:
else
define out_console
    :
endef
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
	$(CARGO) $(CARGO_OPTS) install $(CARGO_INSTALL_OPTS) --path=$(ROOT_DIR)/retis --offline --frozen

# Skip out path and vmlinux.h
BINDINGS := $(shell find $(ROOT_DIR)/retis/src -name '*.[ch]' -not -name 'vmlinux.h' -not -path '*/.out/*' -exec grep -l "__binding" {} \;)
gen-bindings:
	-mkdir -p $(ROOT_DIR)/retis/src/bindings; \
	for binding in $(BINDINGS); do \
	    $(call out_console,BINDINGS,processing $$binding ...); \
	    annotations="`$(ROOT_DIR)/tools/annotations.py "$$binding" "uapi" $(INCLUDES) $(BPF_CFLAGS)`"; \
	    opts=; \
	    for a in $$annotations; do opts="--allowlist-item $$a $$opts"; done; \
	    [ -z "$$opts" ] && continue; \
	    fname=$${binding##*/}; \
	    out_path=$(ROOT_DIR)/retis/src/bindings/$${fname%%.*}_uapi.rs; \
	    $(BINDGEN) --no-layout-tests \
	               --with-derive-default \
	               --no-prepend-enum-name \
	               $$binding \
	               $$opts \
	               -o $$out_path \
	               -- $(INCLUDES) $(BPF_CFLAGS); \
	    $(call out_console,BINDINGS,generated bindings in "$$out_path" ...); \
	done

define build
	$(call out_console,CARGO,$(strip $(2)) ...)
	jobs=$(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS))); \
	CARGO_BUILD_JOBS=$${jobs:-1} \
	$(CARGO) $(CARGO_OPTS) $(1) $(CARGO_CMD_OPTS)
endef

debug: ebpf
	$(call build, build, building retis (debug))

release: $(eval RUSTFLAGS += -D warnings)
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
	CFLAGS_INCLUDES="$(INCLUDES)" \
	$(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $@

clean-bindings:
	$(call out_console,CLEAN,cleaning bindings ...)
	-find $(ROOT_DIR)/retis/src/bindings -type f -not -name 'mod.rs' -name '*.rs' -exec rm -f {} \;

clean-ebpf:
	$(call out_console,CLEAN,cleaning ebpf progs ...)
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
	$(PRINT) 'gen-bindings        --  Generate Rust bindings for bpf programs.'
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
	$(PRINT) 'CARGO_CMD_OPTS      --  Changes `cargo` subcommand default behavior (e.g. --features <features> for `build`).'
	$(PRINT) 'CARGO_INSTALL_OPTS  --  Changes `cargo` install subcommand default behavior.'
	$(PRINT) 'CARGO_OPTS          --  Changes `cargo` default behavior (e.g. --verbose).'
	$(PRINT) 'NOVENDOR            --  Avoid to self detect and consume the vendored headers'
	$(PRINT) '                        shipped with libbpf-sys.'

.PHONY: all bench clean clean-bindings clean-ebpf ebpf $(EBPF_PROBES) $(EBPF_HOOKS) gen-bindings help install release test
