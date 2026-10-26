/* Network-only RAM image loader for the MT7628 eCos experiment.
 * check/boot are read-only. install is an explicit, validated flash operation.
 */
#include <cyg/kernel/kapi.h>
#include <cyg/hal/hal_arch.h>
#include <cyg/hal/hal_intr.h>
#include <cyg/hal/hal_cache.h>
#include <cyg/infra/diag.h>
#include <network.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define RB_MAX_PAYLOAD (1024U * 1024U)
#define RB_LOAD 0x80500000U
#define RB_TRAMP 0xa0000100U
#define RB_ETH_DMA ((volatile unsigned int *)0xb0100a04U)
#define RB_WIFI_DMA ((volatile unsigned int *)0xb0304208U)
#define RB_WDT_STATUS ((volatile unsigned int *)0xb0000100U)

extern unsigned char ramboot_jump_start[], ramboot_jump_end[];
#ifdef CONFIG_HARDWARE_WATCHDOG
extern void Watchdog_network_test(void);
#endif

static cyg_thread rb_thread;
static cyg_handle_t rb_handle;
static cyg_sem_t rb_sem;
static unsigned char rb_stack[8192];
static volatile int rb_started, rb_busy;
static const char * volatile rb_state = "idle";
static const char * volatile rb_error = "none";
static volatile unsigned int rb_received;
static struct in_addr rb_server;
static char rb_file[128];
static int rb_boot;
static int rb_install, rb_install_check;

static unsigned int rb_be32(const unsigned char *p)
{
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

static unsigned int rb_crc32(const unsigned char *p, unsigned int n)
{
    unsigned int crc = ~0U;
    unsigned int i;
    while (n--) {
        crc ^= *p++;
        for (i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

static int rb_header(const unsigned char *p, unsigned int *total)
{
    unsigned char h[64];
    unsigned int size;
    if (rb_be32(p) != 0x27051956U) {
        rb_error = "not a uImage";
        return -1;
    }
    memcpy(h, p, sizeof(h));
    memset(h + 4, 0, 4);
    if (rb_crc32(h, sizeof(h)) != rb_be32(p + 4)) {
        rb_error = "header CRC mismatch";
        return -1;
    }
    size = rb_be32(p + 12);
    if (size < 128 || size > RB_MAX_PAYLOAD) {
        rb_error = "payload size out of bounds";
        return -1;
    }
    if (rb_be32(p + 16) != RB_LOAD || rb_be32(p + 20) != RB_LOAD ||
        p[29] != 5 || p[30] != 1 || p[31] != 0) {
        rb_error = "requires MIPS standalone zxrouter at 0x80500000";
        return -1;
    }
    *total = size + 64;
    return 0;
}

static int rb_fetch(unsigned char **result, unsigned int *result_size)
{
    struct sockaddr_in peer, from;
    unsigned char packet[516], last[256];
    unsigned char *image = NULL;
    unsigned int expected = 0, used = 0, block = 1, last_size;
    unsigned int retries = 0;
    cyg_tick_count_t deadline = cyg_current_time() + 4500;
    int fd, connected = 0, n, ready;
    socklen_t fromlen;

    memset(&peer, 0, sizeof(peer));
    peer.sin_len = sizeof(peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(69);
    peer.sin_addr = rb_server;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { rb_error = "cannot open TFTP socket"; return -1; }
    last[0] = 0; last[1] = 1;
    memcpy(last + 2, rb_file, strlen(rb_file) + 1);
    memcpy(last + 3 + strlen(rb_file), "octet", 6);
    last_size = (unsigned int)strlen(rb_file) + 9;
    if (sendto(fd, last, last_size, 0, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        rb_error = "cannot send TFTP request"; goto fail;
    }
    while (cyg_current_time() < deadline) {
        struct timeval wait = {2, 0};
        fd_set rd;
        FD_ZERO(&rd); FD_SET(fd, &rd);
        ready = select(fd + 1, &rd, NULL, NULL, &wait);
        if (ready < 0) {
            if (errno == EINTR) continue;
            rb_error = "TFTP select failed"; goto fail;
        }
        if (ready == 0) {
            if (++retries > 5) { rb_error = "TFTP timeout"; goto fail; }
            sendto(fd, last, last_size, 0, (struct sockaddr *)&peer, sizeof(peer));
            continue;
        }
        fromlen = sizeof(from);
        n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &fromlen);
        if (n < 4 || from.sin_addr.s_addr != rb_server.s_addr ||
            (connected && from.sin_port != peer.sin_port)) continue;
        if (packet[0] == 0 && packet[1] == 5) {
            rb_error = "TFTP server rejected file"; goto fail;
        }
        if (packet[0] != 0 || packet[1] != 3) continue;
        if (((unsigned int)packet[2] << 8 | packet[3]) == block - 1 && connected) {
            sendto(fd, last, last_size, 0, (struct sockaddr *)&peer, sizeof(peer));
            continue;
        }
        if (((unsigned int)packet[2] << 8 | packet[3]) != block) continue;
        if (!connected) { peer = from; connected = 1; }
        retries = 0;
        if (block == 1) {
            if (n < 68) { rb_error = "truncated image header"; goto fail; }
            if (rb_header(packet + 4, &expected) < 0) goto fail;
            image = malloc(expected);
            if (!image) { rb_error = "not enough contiguous RAM"; goto fail; }
            diag_printf("ramboot: receiving %u bytes\n", expected);
        }
        if ((unsigned int)(n - 4) > expected - used) {
            rb_error = "file exceeds declared size"; goto fail;
        }
        memcpy(image + used, packet + 4, n - 4);
        used += n - 4;
        rb_received = used;
        last[0] = 0; last[1] = 4;
        last[2] = packet[2]; last[3] = packet[3]; last_size = 4;
        sendto(fd, last, last_size, 0, (struct sockaddr *)&peer, sizeof(peer));
        block++;
        if (n < 516) {
            if (used != expected) { rb_error = "truncated image"; goto fail; }
            close(fd);
            if (rb_crc32(image + 64, used - 64) != rb_be32(image + 24)) {
                rb_error = "payload CRC mismatch";
                free(image); return -1;
            }
            /* The branch delay slot precedes the SDK zload destination word. */
            if (image[72] != 0 || image[73] != 4 || image[74] != 0 || image[75] != 0x80) {
                rb_error = "unsupported decompression destination";
                free(image); return -1;
            }
            *result = image; *result_size = used;
            return 0;
        }
    }
    rb_error = "TFTP total time limit";
fail:
    close(fd);
    if (image) free(image);
    return -1;
}

/* Called with interrupts disabled; no memory is overwritten on failure. */
static int rb_dma_stop(unsigned int *eth, unsigned int *wifi)
{
    unsigned int n;
    *eth = *RB_ETH_DMA; *wifi = *RB_WIFI_DMA;
    *RB_ETH_DMA = *eth & ~5U;
    *RB_WIFI_DMA = *wifi & ~5U;
    __asm__ volatile("sync" ::: "memory");
    for (n = 0; n < 500000; n++)
        if (((*RB_ETH_DMA | *RB_WIFI_DMA) & 10U) == 0) return 0;
    return -1;
}

static void rb_dma_restore(unsigned int eth, unsigned int wifi)
{
    *RB_WIFI_DMA = wifi; *RB_ETH_DMA = eth;
    __asm__ volatile("sync" ::: "memory");
}

static int rb_launch(unsigned char *image, unsigned int size)
{
    CYG_INTERRUPT_STATE irq;
    unsigned int eth, wifi, n = (unsigned int)(ramboot_jump_end - ramboot_jump_start);
    void (*jump)(unsigned int, unsigned int, unsigned int, unsigned int);
    if (n == 0 || n > 0x300) { rb_error = "invalid trampoline size"; return -1; }
    diag_printf("ramboot: CRC OK; launching in RAM, flash untouched\n");
    cyg_thread_delay(100);
    HAL_DISABLE_INTERRUPTS(irq);
    if (rb_dma_stop(&eth, &wifi) < 0) {
        rb_dma_restore(eth, wifi);
        HAL_RESTORE_INTERRUPTS(irq);
        rb_error = "DMA did not become idle; launch cancelled";
        return -1;
    }
    HAL_DCACHE_SYNC();
    memcpy((void *)RB_TRAMP, ramboot_jump_start, n);
    __asm__ volatile("sync" ::: "memory");
    /* Give the next image a full hardware watchdog period to initialize. */
    *RB_WDT_STATUS = 1U << 9;
    jump = (void *)RB_TRAMP;
    jump(((unsigned int)(image + 64)) | 0x20000000U,
         RB_LOAD | 0x20000000U, size - 64, RB_LOAD);
    for (;;) { /* If an unexpected return occurs, let the watchdog recover. */ }
}

/* Explicit network installation; called only after rb_fetch validates uImage. */
#include <cyg/io/flash.h>
#include <flash_policy.h>
extern void watchdog_tmr_func(void);

static int rb_flash_geometry(unsigned int size, int erase)
{
    cyg_flash_info_t info;
    cyg_flashaddr_t err;
    unsigned int pos, end = TF_FW_FIRST + size, last = 0;
    int i, j, covered = 0;
    if (!tf_span(TF_FW_FIRST,size,TF_FW_FIRST,TF_FLASH_END) ||
        cyg_flash_get_info(0,&info) || info.start != 0 || info.end != TF_FLASH_END-1) {
        rb_error = "unexpected flash geometry"; return -1;
    }
    pos = info.start;
    for (i=0; i<info.num_block_infos; i++) {
        for (j=0; j<info.block_info[i].blocks; j++) {
            unsigned int n = info.block_info[i].block_size;
            if (pos < end && pos+n > TF_FW_FIRST) {
                if (!n || pos < TF_FW_FIRST || !tf_span(pos,n,TF_FW_FIRST,TF_FLASH_END)) {
                    rb_error = "erase would cross a protected boundary"; return -1;
                }
                if (!covered && pos != TF_FW_FIRST) { rb_error="unaligned firmware partition";return -1; }
                covered = 1; last = pos+n;
                if (erase) {
                    watchdog_tmr_func();
                    if (cyg_flash_erase(pos,n,&err)) { rb_error="flash erase failed";return -1; }
                    watchdog_tmr_func();
                }
            }
            pos += n;
        }
    }
    if (!covered || last < end) { rb_error="firmware is not covered by flash blocks";return -1; }
    if (!erase) diag_printf("ramboot: install plan firmware=[%08x,%08x), erase end=%08x; boot/config/calibration preserved\n",TF_FW_FIRST,end,last);
    return 0;
}

static int rb_flash_verify(unsigned int addr, const unsigned char *bytes, unsigned int len)
{
    unsigned char buf[256];
    cyg_flashaddr_t err;
    while (len) {
        unsigned int n = len > sizeof(buf) ? sizeof(buf) : len;
        watchdog_tmr_func();
        if (cyg_flash_read(addr,buf,n,&err) || memcmp(buf,bytes,n)) return -1;
        addr += n; bytes += n; len -= n;
    }
    return 0;
}

static int rb_flash_install(const unsigned char *image, unsigned int size)
{
    cyg_flashaddr_t err;
    unsigned int off;
    if (size < 192 || size > RB_MAX_PAYLOAD+64 || rb_flash_geometry(size,0)) return -1;
    rb_state = "erasing";
    if (rb_flash_geometry(size,1)) return -1;
    rb_state = "programming";
    /* Commit the boot header LAST, after the complete payload is verified. */
    for (off=64; off<size;) {
        unsigned int n = size-off > 4096 ? 4096 : size-off;
        watchdog_tmr_func();
        if (cyg_flash_program(TF_FW_FIRST+off,image+off,n,&err)) {
            rb_error="flash payload programming failed";return -1;
        }
        off += n;
    }
    rb_state = "verifying";
    if (rb_flash_verify(TF_FW_FIRST+64,image+64,size-64)) {
        rb_error="flash payload readback mismatch";return -1;
    }
    watchdog_tmr_func();
    if (cyg_flash_program(TF_FW_FIRST,image,64,&err) || rb_flash_verify(TF_FW_FIRST,image,size)) {
        rb_error="flash header/final readback failed";return -1;
    }
    return 0;
}

static int rb_flash_crc(unsigned int addr,unsigned int len,unsigned int *result)
{
    unsigned char buf[256];
    cyg_flashaddr_t err;
    unsigned int crc=~0U,i,j;
    while (len) {
        unsigned int n=len>sizeof(buf)?sizeof(buf):len;
        if (cyg_flash_read(addr,buf,n,&err)) return -1;
        for (i=0;i<n;i++) {
            crc ^= buf[i];
            for(j=0;j<8;j++)crc=(crc>>1)^(0xedb88320U & (0U-(crc&1U)));
        }
        addr+=n;len-=n;watchdog_tmr_func();
    }
    *result=~crc;return 0;
}

static int rb_flash_info(void)
{
    unsigned int crc;
    if (rb_flash_crc(0,TF_CFG_SECTOR_FIRST,&crc))return -1;
    diag_printf("flash boot-env crc32=%08x\n",crc);
    if (rb_flash_crc(TF_CFG_SECTOR_FIRST,TF_CFG_SECTOR_END-TF_CFG_SECTOR_FIRST,&crc))return -1;
    diag_printf("flash config-sector crc32=%08x\n",crc);
    if (rb_flash_crc(TF_CFG_SECTOR_END,TF_FW_FIRST-TF_CFG_SECTOR_END,&crc))return -1;
    diag_printf("flash calibration crc32=%08x\n",crc);
    return 0;
}

static int rb_flash_read_config(const char *start,const char *count)
{
    unsigned char buf[256];
    unsigned int addr,len,i;
    cyg_flashaddr_t err;
    char *end;
    addr=strtoul(start,&end,0);if(*end)return -1;
    len=strtoul(count,&end,0);if(*end || len>sizeof(buf) ||
        !tf_span(addr,len,TF_CFG_SECTOR_FIRST,TF_CFG_SECTOR_END))return -1;
    if (cyg_flash_read(addr,buf,len,&err))return -1;
    diag_printf("flash-data %08x ",addr);
    for(i=0;i<len;i++)diag_printf("%02x",buf[i]);
    diag_printf("\n");return 0;
}

static void rb_worker(cyg_addrword_t unused)
{
    for (;;) {
        unsigned char *image = NULL;
        unsigned int size = 0;
        cyg_semaphore_wait(&rb_sem);
        rb_state = "downloading";
        if (rb_fetch(&image, &size) < 0) {
            rb_state = "failed";
            diag_printf("ramboot: refused: %s\n", rb_error);
        } else {
            rb_state = "checked";
            diag_printf("ramboot: image validated (%u bytes), mode=%s\n", size,
                        rb_boot ? "boot" : "check only");
            if (rb_install || rb_install_check) {
                if (rb_flash_geometry(size,0) || (rb_install && rb_flash_install(image,size))) {
                    rb_state="failed";
                    diag_printf("ramboot: installation refused/failed: %s\n",rb_error);
                } else rb_state=rb_install ? "installed" : "install_checked";
            } else if (rb_boot) {
                rb_state = "booting";
                if (rb_launch(image, size) < 0) {
                    rb_state = "failed";
                    diag_printf("ramboot: refused: %s\n", rb_error);
                }
            }
            free(image);
        }
        rb_busy = 0;
    }
}

int cmd_ramboot(int argc, char **argv)
{
    if (argc == 1 && !strcmp(argv[0],"flash-info")) return rb_flash_info();
    if (argc == 3 && !strcmp(argv[0],"flash-read")) return rb_flash_read_config(argv[1],argv[2]);
    if (argc == 1 && !strcmp(argv[0], "status")) {
        diag_printf("ramboot v1: state=%s busy=%d received=%u error=%s\n",
                    rb_state, rb_busy, rb_received, rb_error);
        return 0;
    }
    if (argc == 1 && !strcmp(argv[0], "watchdog-test")) {
#ifdef CONFIG_HARDWARE_WATCHDOG
        Watchdog_network_test();
#else
        diag_printf("ramboot: hardware watchdog unavailable\n");
#endif
        return 0;
    }
    if (argc == 1 && !strcmp(argv[0], "dma-check")) {
        CYG_INTERRUPT_STATE irq;
        unsigned int eth, wifi;
        int result;
        HAL_DISABLE_INTERRUPTS(irq);
        result = rb_dma_stop(&eth, &wifi);
        rb_dma_restore(eth, wifi);
        HAL_RESTORE_INTERRUPTS(irq);
        diag_printf("ramboot: DMA stop/restore %s eth=%08x wifi=%08x\n",
                    result == 0 ? "OK" : "FAILED", eth, wifi);
        return result;
    }
    if (!((argc==3 && (!strcmp(argv[0],"check") || !strcmp(argv[0],"boot") ||
                         !strcmp(argv[0],"install-check"))) ||
          (argc==4 && !strcmp(argv[0],"install") && !strcmp(argv[3],"CONFIRM-FLASH")))) {
        diag_printf("ramboot status | dma-check | watchdog-test | flash-info\n"
                    "ramboot check|boot|install-check <TFTP-IP> <uImage-file>\n"
                    "ramboot install <TFTP-IP> <uImage-file> CONFIRM-FLASH\n"
                    "ramboot flash-read <config-sector-offset> <1..256-bytes>\n");
        return -1;
    }
    if (rb_busy) { diag_printf("ramboot: busy\n"); return -1; }
    if (strlen(argv[2]) == 0 || strlen(argv[2]) >= sizeof(rb_file)) return -1;
    rb_server.s_addr = inet_addr(argv[1]);
    if (rb_server.s_addr == INADDR_NONE || rb_server.s_addr == 0) {
        diag_printf("ramboot: invalid TFTP IPv4 address\n"); return -1;
    }
    strcpy(rb_file, argv[2]);
    rb_boot = !strcmp(argv[0], "boot");
    rb_install=!strcmp(argv[0],"install");
    rb_install_check=!strcmp(argv[0],"install-check");
    rb_received = 0; rb_error = "none"; rb_busy = 1; rb_state = "queued";
    if (!rb_started) {
        cyg_semaphore_init(&rb_sem, 0);
        cyg_thread_create(10, rb_worker, 0, "RAMBoot_thread", rb_stack,
                          sizeof(rb_stack), &rb_handle, &rb_thread);
        rb_started = 1;
        cyg_thread_resume(rb_handle);
    }
    cyg_semaphore_post(&rb_sem);
    diag_printf("ramboot: queued %s from %s (%s)\n", rb_file, argv[1], argv[0]);
    return 0;
}
