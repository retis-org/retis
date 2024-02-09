# Needs to be set because of PT_REGS_PARMx() and any other target
# specific facility.
ARCH := x86
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
              -D __TARGET_ARCH_$(ARCH) \
	      -O2

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
