ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
LLC := llc
OBJCOPY := llvm-objcopy

CARGO := cargo $(CARGO_OPTS)
BINDGEN := bindgen

define retis_set_version
RELEASE_VERSION := $(shell tools/localversion)
RELEASE_NAME := $(shell $(CARGO) metadata --no-deps --format-version=1 | jq -r '.packages | .[] | select(.name=="retis") | .metadata.misc.release_name')
export RELEASE_NAME RELEASE_VERSION
endef

RELEASE_FLAGS = -Dwarnings
# The flag below must be passed to the linker because
# there's an issue that strips a section required for the
# tests (.stapsdt.base). This is a temporary workaround and
# will be removed once the issue gets fixed.
RUSTFLAGS_KEEP_SECS := -Clink-arg=-Wl,--no-gc-sections

define ebpf_set_vars
DEFAULT_ARCH := $(patsubst target_arch="%",%,$(filter target_arch="%",$(shell rustc --print cfg)))
ARCH := $(if $(CARGO_BUILD_TARGET),$(firstword $(subst -, ,$(CARGO_BUILD_TARGET))),$$(DEFAULT_ARCH))

# Needs to be set because of PT_REGS_PARMx() and any other target
# specific facility.
x86_64 := x86
aarch64 := arm64
powerpc64 := powerpc
s390x := s390
# Mappings takes precedence over custom ARCH
BPF_ARCH := $(if $$($$(ARCH)),$$($$(ARCH)),$$(ARCH))

BPF_CFLAGS_PAHOLE := \
	-Wno-gnu-variable-sized-type-not-at-end

BPF_CFLAGS := -target bpf \
              -Wall \
              -Werror \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-unused-command-line-argument \
              $$(BPF_CFLAGS_PAHOLE) \
              -fno-stack-protector \
              -D__TARGET_ARCH_$$(BPF_ARCH) \
              -O2
endef

export LCC OBJCOPY

PRINT = printf
CONTAINER_RUNTIME := podman

define help_once
    @$(PRINT) '$(1)\n'
endef

VERBOSITY := $(filter 1,$(V))

ifeq ($(VERBOSITY),)
    Q=@
    MAKE += -s
    CARGO += -q
define out_console
    $(PRINT) '%-12s %s\n' "[$(1)]" "$(2)"
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

INCLUDES_ALL := $(abspath $(wildcard $(shell find retis/src -type d -path '*/bpf/include')))
INCLUDES_ALL += $(LIBBPF_INCLUDES)

INCLUDES := $(addprefix -I, $(INCLUDES_ALL))

EBPF_PROBES := $(abspath $(wildcard retis/src/core/probe/*/bpf))

EBPF_HOOKS := $(abspath $(wildcard retis/src/collect/collector/*/bpf))

all: debug

install: release
	RUSTFLAGS="$(RUSTFLAGS) $(RELEASE_FLAGS)" \
	$(CARGO) install $(CARGO_INSTALL_OPTS) --path=$(ROOT_DIR)/retis --offline --frozen

# Skip out path and vmlinux.h
BINDINGS := $(shell find $(ROOT_DIR)/retis/src -name '*.[ch]' -not -name 'vmlinux.h' -not -path '*/.out/*' -exec grep -l "__binding" {} \;)
gen-bindings: clean-bindings
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
	               -- -D__BINDGEN__ $(INCLUDES) $(BPF_CFLAGS); \
	    $(call out_console,BINDINGS,generated bindings in "$$out_path" ...); \
	done

define build
	$(call out_console,CARGO,$(strip $(2)) ...)
	jobs=$(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS))); \
	CARGO_BUILD_JOBS=$${jobs:-1} \
	RUSTFLAGS="$(RUSTFLAGS) $(3)" \
	$(CARGO) $(1) $(CARGO_CMD_OPTS)
endef

debug: ebpf
	$(eval $(call retis_set_version))
	$(call build,build,building retis (debug))

release: ebpf
	$(eval $(call retis_set_version))
	$(call build,build --release,building retis (release),$(RELEASE_FLAGS))

test: ebpf
ifeq ($(COV),1)
	$(CARGO) llvm-cov clean --workspace -q
	$(call build,llvm-cov $(if $(VERBOSITY),,-q),running tests with coverage,$(RUSTFLAGS_KEEP_SECS))
else
	$(call build,test,building and running tests,$(RUSTFLAGS_KEEP_SECS))
endif

functional-tests:
	for script in tests/next/*.sh; do \
		[ "$$LIST_TESTS" == "1" ] && echo "$$script:"; \
		$$script; \
	done

functional-tests-list: export LIST_TESTS=1
functional-tests-list: functional-tests

bench: ebpf
	$(eval $(call retis_set_version))
	$(call build,build -F benchmark --release,building benchmarks)

ifeq ($(NOVENDOR),)
$(LIBBPF_INCLUDES): $(LIBBPF_SYS_LIBBPF_INCLUDES)
	-mkdir -p $(LIBBPF_INCLUDES)/bpf
	cp $^ $(LIBBPF_INCLUDES)/bpf/
endif

ebpf_prereqs:
	$(eval $(call ebpf_set_vars))

ebpf: ebpf_prereqs $(EBPF_PROBES) $(EBPF_HOOKS)

$(EBPF_PROBES): OUT_NAME := PROBE
$(EBPF_HOOKS):  OUT_NAME := HOOK
$(EBPF_PROBES) $(EBPF_HOOKS): $(LIBBPF_INCLUDES)
	$(call out_console,$(OUT_NAME),building $@ ...)
	CFLAGS="$(BPF_CFLAGS) $(INCLUDES)" \
	$(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $@

pylib:
	$(call out_console,MATURIN,Building python bindings ...)
	$(CONTAINER_RUNTIME) run --rm --name retis_build_maturin \
		--security-opt label=disable -v $$PWD:/io \
		ghcr.io/pyo3/maturin build -m retis-events/Cargo.toml -F python-lib

pytest-deps:
	@which tox &> /dev/null || (echo "Please install tox ('pip install tox')."; exit 1)

pytest: pytest-deps
	$(call out_console,TOX,Testing python bindings ...)
	cd retis-events && tox

define analyzer_tmpl
  $(1): CARGO_CMD_OPTS ?= $(if $(filter 1,$(RA)),--quiet --message-format=json --all-targets --keep-going,)
  $(1): PRINT +=$(if $(filter 1,$(RA)),>/dev/null,)
  $(1):
	$$(call build,$$(@), running $$@)
endef

$(foreach tgt,check clippy,$(eval $(call analyzer_tmpl,$(tgt))))

check-rust:
	$(call build, fmt --check, check format)
	# No need to run `check` in addition to `clippy`, it's a superset.
	$(call build, clippy $(if $(VERBOSITY),,--quiet), running clippy)
	$(call build, clippy $(if $(VERBOSITY),,--quiet) -F benchmark, running clippy on benchmarks)

check-ebpf:
	$(call out_console,CHECKPATCH,checking eBPF coding style ...)
	base_hash=$$(git merge-base $${BASE_COMMIT:-main} HEAD); \
	git diff $${base_hash} -- '*/bpf/*' | ./tools/checkpatch/checkpatch.pl --no-tree --ignore=SPDX_LICENSE_TAG,FILE_PATH_CHANGES,EMAIL_SUBJECT,VOLATILE -q || restyle=$$?; \
	[ -z "$$restyle" ]

check-python:
	$(call out_console,FLAKE8,checking Python coding style ...)
	python3 -m flake8 tests
	$(call out_console,BLACK,checking Python coding style ...)
	python3 -m black --check $(if $(VERBOSITY),,--quiet) --diff tests/*.py tests/next/include/*.py

checks: check-rust check-ebpf check-python

report-cov:
	$(CARGO) llvm-cov report $(CARGO_CMD_OPTS)

clean-bindings:
	$(call out_console,CLEAN,cleaning bindings ...)
	-find $(ROOT_DIR)/retis/src/bindings -type f -not -name 'mod.rs' -name '*.rs' -exec rm -f {} \;

clean-cov:
	$(CARGO) llvm-cov clean --workspace

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
	$(call help_once,Generic targets:)
	$(call help_once, all                   --  Builds the tool (both eBPF programs and retis).)
	$(call help_once, install               --  Installs Retis.)
	$(call help_once, release               --  Builds Retis with the release option.)
	$(call help_once, checks                --  Runs linters for Rust/eBPF/Python.)
	$(call help_once, test                  --  Builds and runs unit tests.)
	$(call help_once, clean                 --  Deletes all the files generated during the build process.)
	$(call help_once)
	$(call help_once,Below are listed lower level targets and optional variables.)
	$(call help_once)
	$(call help_once,Building targets:)
	$(call help_once, bench                 --  Builds benchmarks.)
	$(call help_once, ebpf                  --  Builds only the eBPF programs.)
	$(call help_once, pylib                 --  Builds the python bindings.)
	$(call help_once, report-cov            --  Generate coverage report after code coverage testing.)
	$(call help_once, gen-bindings          --  Generate Rust bindings for bpf programs.)
	$(call help_once)
	$(call help_once,Cleaning targets:)
	$(call help_once, clean-ebpf            --  Deletes all the files eBPF generated during the build process.)
	$(call help_once, clean-cov             --  Deletes all the files generated during code coverage testing.)
	$(call help_once)
	$(call help_once,Testing targets:)
	$(call help_once, check-rust            --  Runs format and linter checks.)
	$(call help_once, check-ebpf            --  Checks eBPF coding style for commits in current branch.)
	$(call help_once,                       --  Requires `BASE_COMMIT` env variable to be set otherwise `main` is assumed.)
	$(call help_once, check-python          --  Runs format and linter checks on Python files.)
	$(call help_once, check                 --  Runs cargo check.)
	$(call help_once, clippy                --  Runs cargo clippy.)
	$(call help_once, functional-tests      --  Runs functional tests. Set $$(TESTS) to run specfic tests. E.g. TESTS="test0 test1".)
	$(call help_once, functional-tests-list --  Lists functional tests.)
	$(call help_once, pytest                --  Tests the python bindings (requires "tox" installed).)
	$(call help_once)
	$(call help_once,Optional variables that can be used to override the default behavior:)
	$(call help_once, V                     --  If set to 1 the verbose output will be printed.)
	$(call help_once,                           The cargo verbosity is set to default.)
	$(call help_once,                           To override `cargo` behavior please refer to $$(CARGO_OPTS))
	$(call help_once,                           $$(CARGO_CMD_OPTS) and for the install $$(CARGO_INSTALL_OPTS).)
	$(call help_once,                           For further `cargo` customization please refer to configuration)
	$(call help_once,                           environment variables)
	$(call help_once,                           (https://doc.rust-lang.org/cargo/reference/environment-variables.html).)
	$(call help_once, CARGO_CMD_OPTS        --  Changes `cargo` subcommand default behavior (e.g. --features <features> for `build`).)
	$(call help_once, CARGO_INSTALL_OPTS    --  Changes `cargo` install subcommand default behavior.)
	$(call help_once, CARGO_OPTS            --  Changes `cargo` default behavior (e.g. --verbose).)
	$(call help_once, NOVENDOR              --  Avoid to self detect and consume the vendored headers)
	$(call help_once,                           shipped with libbpf-sys.)
	$(call help_once, RA                    --  Applies to check and clippy and runs those targets with the options needed)
	$(call help_once,                           for rust-analyzer. When $$(RA) is used $$(V) becomes ineffective.)
	$(call help_once, COV                   --  Enable code coverage for testing. Applies only to the target "test".)
	$(call help_once,                           Requires llvm-cov and preferably rustup toolchain.)

.PHONY: all bench ebpf ebpf_prereqs $(EBPF_PROBES) $(EBPF_HOOKS) gen-bindings help install release pylib report-cov
.PHONY: test pytest-deps pytest check-ebpf functional-tests functional-tests-list check-rust check-python checks
.PHONY: clean clean-bindings clean-cov clean-ebpf
