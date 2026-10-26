#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef unsigned int cyg_flashaddr_t;
typedef struct { unsigned int block_size,blocks; } block_info_t;
typedef struct { unsigned int start,end,num_block_infos; block_info_t *block_info; } cyg_flash_info_t;
static unsigned char flashmem[0x200000];
static block_info_t blocks={65536,32};
static cyg_flash_info_t geometry={0,0x1fffff,1,&blocks};
static int erases,programs,fail_program,corrupt_payload,bad_geometry;
static unsigned int last_program;
static const char *rb_error="none",*rb_state="idle";
#define RB_MAX_PAYLOAD (1024U*1024U)
static int diag_printf(const char *format,...) { return 0; }
static void watchdog_tmr_func(void) {}
static int cyg_flash_get_info(int index,cyg_flash_info_t *info) { *info=geometry; if(bad_geometry)info->end++;return 0; }
static int cyg_flash_erase(unsigned int addr,unsigned int len,cyg_flashaddr_t *error) { assert(addr>=0x50000 && len && addr+len<=0x200000);erases++;memset(flashmem+addr,255,len);return 0; }
static int cyg_flash_program(unsigned int addr,const void *source,unsigned int len,cyg_flashaddr_t *error) {
 unsigned int i;const unsigned char *p=source;assert(addr>=0x50000 && len && addr+len<=0x200000);
 programs++;last_program=addr;if(fail_program && programs==fail_program)return -1;
 for(i=0;i<len;i++){assert((flashmem[addr+i]&p[i])==p[i]);flashmem[addr+i]&=p[i];}
 if(corrupt_payload && addr>0x50000)flashmem[addr]^=1;
 return 0;
}
static int cyg_flash_read(unsigned int addr,void *dest,unsigned int len,cyg_flashaddr_t *error) { assert(addr+len<=0x200000);memcpy(dest,flashmem+addr,len);return 0; }
/* IMPLEMENTATION */
static void reset(void) { unsigned int i;for(i=0;i<sizeof(flashmem);i++)flashmem[i]=(i*13+7)&255;erases=programs=fail_program=corrupt_payload=bad_geometry=0;last_program=0;rb_error="none";blocks.block_size=65536;blocks.blocks=32; }
int main(void) {
 unsigned char *image=malloc(755688),*before=malloc(sizeof(flashmem));unsigned int i,crc;
 for(i=0;i<755688;i++)image[i]=(i*7+11)&255;
 assert(tf_span(0x31000,0x5000,TF_CFG_FIRST,TF_CFG_END));
 assert(!tf_span(0x30000,1,TF_CFG_FIRST,TF_CFG_END));
 assert(!tf_span(0x35fff,2,TF_CFG_FIRST,TF_CFG_END));
 assert(!tf_span(0xfffffff0,32,TF_CFG_FIRST,TF_CFG_END));
 assert(!tf_span(0x31000,0,TF_CFG_FIRST,TF_CFG_END));
 reset();memcpy(before,flashmem,sizeof(flashmem));assert(rb_flash_geometry(755688,0)==0);assert(erases==0 && programs==0);assert(!memcmp(before,flashmem,sizeof(flashmem)));
 assert(rb_flash_install(image,755688)==0);assert(erases==12);assert(last_program==0x50000);assert(!memcmp(flashmem,before,0x50000));assert(!memcmp(flashmem+0x50000,image,755688));assert(!memcmp(flashmem+0x110000,before+0x110000,0xf0000));
 reset();fail_program=2;assert(rb_flash_install(image,755688)<0);assert(flashmem[0x50000]==255 && flashmem[0x5003f]==255);assert(!memcmp(flashmem,before,0x50000));
 reset();corrupt_payload=1;assert(rb_flash_install(image,755688)<0);assert(flashmem[0x50000]==255);assert(!memcmp(flashmem,before,0x50000));
 reset();bad_geometry=1;assert(rb_flash_install(image,755688)<0);assert(erases==0 && programs==0);
 reset();blocks.block_size=0x30000;blocks.blocks=11;assert(rb_flash_geometry(755688,0)<0);assert(erases==0 && programs==0);
 reset();assert(rb_flash_install(image,0)<0);assert(rb_flash_install(image,0xffffffff)<0);assert(erases==0 && programs==0);
 reset();assert(rb_flash_crc(0,9,&crc)==0);assert(crc!=0);
 free(before);free(image);puts("PASS: config bounds/overflow, dry run, firmware range, header-last, payload verification and failure rejection");return 0;
}
