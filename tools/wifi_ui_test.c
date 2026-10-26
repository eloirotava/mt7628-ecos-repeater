#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef int cyg_handle_t; typedef int cyg_thread; typedef int cyg_sem_t; typedef unsigned long cyg_addrword_t;
typedef struct { int method; } http_req;
#define METHOD_POST 1
static const char *names[8], *values[8];
static char cfg[64][256], output[4096];
static int sets, fail_at=-1;
static char *WEB_query(http_req *req,const char *key) { int i; for(i=0;i<8;i++)if(names[i]&&!strcmp(names[i],key))return (char *)values[i];return NULL; }
static void WEB_printf(http_req *req,const char *fmt,...) { va_list ap;va_start(ap,fmt);vsnprintf(output+strlen(output),sizeof(output)-strlen(output),fmt,ap);va_end(ap); }
static void CFG_get_str(int id,char *out) { strcpy(out,cfg[id]); }
static int CFG_set_str(int id,char *val) { sets++; if(sets==fail_at)return -1;strcpy(cfg[id],val);return 0; }
static int CFG_commit(int flags) { assert(flags==CFG_NO_EVENT);return 1; }
static void cyg_thread_delay(int n) {}
static void cyg_semaphore_init(cyg_sem_t *s,int n) {}
static void cyg_semaphore_wait(cyg_sem_t *s) {}
static void cyg_semaphore_post(cyg_sem_t *s) {}
static void cyg_thread_create(int priority,void (*f)(cyg_addrword_t),cyg_addrword_t arg,const char *name,void *stack,size_t size,cyg_handle_t *handle,cyg_thread *thread) {}
static void cyg_thread_resume(cyg_handle_t h) {}
static int CFG_save_user(void) { return 0; }
/* IMPLEMENTATION */
static int wifi_ui_restart(void) { return 0; }
static http_req post={METHOD_POST};
static void setup(const char *mode) {
 int i; const char *n[]={"MODE","SSID","PASSWORD","CHANNEL","UPLINK_SSID","UPLINK_PASSWORD","UPLINK_SECURITY",NULL};
 const char *v[]={mode,"Test AP","test-pass-123","6","Test uplink","uplink-pass-123","wpa2",NULL};
 for(i=0;i<8;i++){names[i]=n[i];values[i]=v[i];}
 for(i=0;i<64;i++)strcpy(cfg[i],"original");
 sets=0;fail_at=-1;output[0]=0;wifi_ui_busy=0;
}
static void rejected(void) { CGI_wifi_apply(&post);assert(!strncmp(output,"ERROR:",6));assert(sets==0); }
int main(void) {
 int i; http_req get={0};
 setup("invalid");rejected();
 setup("ap");values[2]="short";rejected();
 setup("ap");values[1]="bad\nSSID";rejected();
 setup("ap");values[1]="123456789012345678901234567890123";rejected();
 setup("ap");values[3]="6bad";rejected();
 setup("ap");values[3]="0";rejected();
 setup("repeater");values[6]="wpa3";rejected();
 setup("repeater");values[5]="short";rejected();
 setup("ap");CGI_wifi_apply(&get);assert(sets==0);assert(strstr(output,"POST required"));
 setup("ap");wifi_ui_busy=1;rejected();
 setup("ap");names[7]="SAVE";values[7]="invalid";rejected();
 setup("ap");names[7]="SAVE";values[7]="1";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(wifi_ui_save_pending==1);
 setup("ap");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(wifi_ui_save_pending==0);assert(!strcmp(cfg[CFG_SYS_OPMODE],"3"));assert(!strcmp(cfg[CFG_LAN_IP_MODE],"0"));assert(!strcmp(cfg[CFG_LAN_DHCPD_EN],"0"));assert(!strcmp(cfg[CFG_WLN_AutoSSID],"1"));assert(!strcmp(cfg[CFG_WLN_ApCliEnable],"0"));assert(!strcmp(cfg[CFG_WLN_MACRepeaterEn],"0"));assert(!strcmp(cfg[CFG_WLN_AuthMode],"WPA2PSK;OPEN;OPEN;OPEN"));
 setup("repeater");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliEnable],"1"));assert(!strcmp(cfg[CFG_WLN_MACRepeaterEn],"1"));assert(!strcmp(cfg[CFG_WLN_ApCliAuthMode],"WPA2PSK"));assert(!strcmp(cfg[CFG_WLN_ApCliWPAPSK],"uplink-pass-123"));
 setup("repeater");values[6]="open";values[5]=NULL;CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliEncrypType],"NONE"));assert(!strcmp(cfg[CFG_WLN_ApCliWPAPSK],""));
 setup("repeater");values[6]="mixed";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliAuthMode],"WPAPSKWPA2PSK"));
 setup("ap");fail_at=7;CGI_wifi_apply(&post);assert(strstr(output,"ERROR:"));for(i=0;i<64;i++)assert(!strcmp(cfg[i],"original"));
 setup("ap");strcpy(cfg[CFG_WLN_SSID1],"</script>\"&");CGI_wifi_state(&post);assert(strstr(output,"\\u003c/script\\u003e"));assert(!strstr(output,"</script>"));assert(!strstr(output,"test-pass"));
 puts("PASS: server validation, AP/repeater mapping, open/mixed security, rollback and JSON escaping");
 return 0;
}
