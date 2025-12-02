PLUGIN_NAME = retis

SRC_FILES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OUTFILE = $(PLUGIN_NAME).so

CC = gcc
CFLAGS = -Wall -fPIC -I. $(shell pkg-config --cflags wireshark json-c)
LDFLAGS = -shared $(shell pkg-config --libs wireshark json-c)

WIRESHARK_VERSION_FULL := $(shell pkg-config --modversion wireshark)
WIRESHARK_VERSION := $(shell echo $(WIRESHARK_VERSION_FULL) | cut -d. -f1,2)

WIRESHARK_PLUGIN_BASE_DIR ?= $(HOME)/.local/lib/wireshark/plugins
WIRESHARK_PLUGIN_DIR := $(WIRESHARK_PLUGIN_BASE_DIR)/$(WIRESHARK_VERSION)/epan

.PHONY: all clean check install

all: check $(OUTFILE)

check:
	@pkg-config --exists wireshark || (echo "Wireshark development headers not found. Please install them (e.g., 'wireshark-devel')." && false)
	@pkg-config --exists json-c || (echo "Json-c development headers not found. Please install them (e.g., 'json-c-devel')." && false)

$(OUTFILE): $(SRC_FILES) $(HEADERS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

install: all
	@mkdir -p "$(WIRESHARK_PLUGIN_DIR)"
	@cp -v $(OUTFILE) "$(WIRESHARK_PLUGIN_DIR)"

clean:
	@rm -f $(OUTFILE)
