OUT_DIR := .out
OBJS := $(patsubst %.c,$(OUT_DIR)/%.o,$(wildcard *.c))
DEP := $(OBJS:%.o=%.d)

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
