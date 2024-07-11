# Needs to be set because of PT_REGS_PARMx() and any other target
# specific facility.
x86_64 := x86
aarch64 := arm64
powerpc64 := powerpc
s390x := s390
# Mappings takes precedence over custom ARCH
BPF_ARCH := $(if $($(ARCH)),$($(ARCH)),$(ARCH))

LOCAL_INCLUDE := $(abspath $(wildcard ./include))
INCLUDES_EXTRA := $(if $(LOCAL_INCLUDE),$(addprefix -I,$(LOCAL_INCLUDE)),)
OUT_DIR := .out
OBJS := $(patsubst %.c,$(OUT_DIR)/%.o,$(wildcard *.c))
DEP := $(OBJS:%.o=%.d)
BPF_CFLAGS := -target bpf \
              -Wall \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -fno-stack-protector \
              -Werror \
              -D__TARGET_ARCH_$(BPF_ARCH) \
	      -O2
CFLAGS += $(CFLAGS_INCLUDES)

ALL_REQ := $(OBJS)

all: $(ALL_REQ)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)/

$(OBJS): | $(OUT_DIR)

$(OUT_DIR)/%.o: %.c
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) $(INCLUDES_EXTRA) -MMD -c -g -o $@ $<
	$(OBJCOPY) --strip-debug $@

-include $(DEP)

clean:
	-rm -rf $(OUT_DIR)

.PHONY: clean
