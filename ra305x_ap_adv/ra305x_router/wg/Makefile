# Minimal WireGuard client. Crypto (blake2s, c25519, aead) and dns_resolve
# come from the ntun module, linked into the same firmware.
include $(TOPDIR)/.config
include $(TOPDIR)/rules.mak

# gnu89 inline: eCos headers use extern inline, which C99 would emit in every object
EXTRA_CFLAGS += -std=gnu99 -fgnu89-inline -DNTUN_ECOS
EXTRA_CFLAGS += -I$(TOPDIR)/ntun -I$(TOPDIR)/ntun/compat

ALL_OBJS = wg_proto.o wg_if.o wg_ecos.o

MODULE = $(shell pwd | sed "s/.*\///" ).o

all: $(MODULE)

$(MODULE): $(ALL_OBJS:.o=.d)
	$(XLD) -r $(ENDIAN) -o $(MODULE) $(ALL_OBJS)

clean:
	rm -f $(MODULE) $(ALL_OBJS)
