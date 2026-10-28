# wg54 for Linux 2.4 MIPS32r1 little endian (BCM5354), static, no libc.
#   make                build/wg54 (stripped) and build/wg54.elf
# Built in CI (.github/workflows/wg54.yml) with Ubuntu's gcc-mipsel-linux-gnu.

CROSS ?= mipsel-linux-gnu-
CC     = $(CROSS)gcc
R      = ../ra305x_ap_adv/ra305x_router

SRC = wg54.c sys24.c mips24.S $(R)/wg/wg_proto.c \
	$(R)/crypto/blake2s.c $(R)/crypto/c25519.c $(R)/crypto/aead.c $(R)/crypto/sha2.c

# -march=mips32: the BCM5354 (4KEc) has no MIPS32r2 instructions.
# No -lgcc: Debian's libgcc is MIPS32r2 and PIC; sys24.c has what is needed.
# Ubuntu's gcc fortifies by default, which calls __memcpy_chk from the libc.
CFLAGS = -Os -Wall -Wextra -march=mips32 -mno-abicalls -fno-pic -G0 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
	-ffunction-sections -fdata-sections -fno-tree-loop-distribute-patterns \
	-I$(R)/wg -I$(R)/crypto
LDFLAGS = -static -nostdlib -Wl,-z,noexecstack -Wl,--gc-sections -Wl,-e,__start \
	-Wl,--build-id=none -Wl,-z,norelro
STRIP_R = -R .comment -R .pdr -R .mdebug.abi32 -R .MIPS.abiflags -R .reginfo -R .gnu.attributes

build/wg54: $(SRC) $(R)/wg/wg_proto.h | build
	$(CC) $(CFLAGS) $(LDFLAGS) -o build/wg54.elf $(SRC)
	cp build/wg54.elf $@
	$(CROSS)strip -s $(STRIP_R) $@
	cp wg54.sh boot.sh build/

build:
	mkdir -p build

clean:
	rm -rf build
.PHONY: clean
