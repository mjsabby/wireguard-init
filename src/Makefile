CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-unused-function
CFLAGS += -Wmissing-prototypes -Wstrict-prototypes
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -I../vendor/wireguard-tools/src

LDFLAGS ?=

WG_SRC_DIR = ../vendor/wireguard-tools/src
WG_OBJS = $(WG_SRC_DIR)/encoding.o $(WG_SRC_DIR)/ipc.o $(WG_SRC_DIR)/curve25519.o

.PHONY: all clean

all: wireguard-init

$(WG_SRC_DIR)/%.o: $(WG_SRC_DIR)/%.c
	$(MAKE) -C $(WG_SRC_DIR) $(@F)

wireguard-init: wireguard-init.c $(WG_OBJS)
	@echo "Building static wireguard-init..."
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $< $(WG_OBJS)
	@echo "Build successful!"

clean:
	rm -f wireguard-init *.o
