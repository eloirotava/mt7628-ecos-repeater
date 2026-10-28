# ntun client (github.com/eloirotava/ntun, client sources at 308e5e0)
# built into the firmware; sys_ecos.c replaces sys_libc.c / sys_nolibc.c.
include $(TOPDIR)/.config
include $(TOPDIR)/rules.mak

EXTRA_CFLAGS += -std=gnu99 -DNTUN_ECOS -Dmain=ntun_client_main

ALL_OBJS = client.o noise.o blake2s.o c25519.o aead.o sha2.o util.o sys_ecos.o ntun_ecos.o

MODULE = $(shell pwd | sed "s/.*\///" ).o

all: $(MODULE)

$(MODULE): $(ALL_OBJS:.o=.d)
	$(XLD) -r $(ENDIAN) -o $(MODULE) $(ALL_OBJS)

clean:
	rm -f $(MODULE) $(ALL_OBJS)
