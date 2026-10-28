#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask)
{
    char a[20]; const char *sl = strchr(s, '/'); struct in_addr in; int bits;
    if (!sl || sl - s >= (int)sizeof a) return -1;
    memcpy(a, s, sl - s); a[sl - s] = 0; bits = atoi(sl + 1);
    if (bits < 8 || bits > 30 || !inet_aton(a, &in)) return -1;
    *ip = in.s_addr; *mask = htonl(~(0xffffffffUL >> bits));
    if ((*ip & ~*mask) == 0 || (*ip | *mask) == 0xffffffffUL) return -1;
    return 0;
}
typedef int cyg_handle_t; typedef int cyg_thread; typedef int cyg_sem_t; typedef unsigned long cyg_addrword_t;
typedef struct { int method; } http_req;
#define METHOD_POST 1
static const char *names[12], *values[12];
static char cfg[64][256], output[8192];
static int sets, fail_at=-1;
static char *WEB_query(http_req *req,const char *key) { int i; for(i=0;i<12;i++)if(names[i]&&!strcmp(names[i],key))return (char *)values[i];return NULL; }
static void WEB_printf(http_req *req,const char *fmt,...) { va_list ap;va_start(ap,fmt);vsnprintf(output+strlen(output),sizeof(output)-strlen(output),fmt,ap);va_end(ap); }
static int slot(int id) { return id >= 9001 ? 50 + id - 9001 : id; }
static void CFG_get_str(int id,char *out) { strcpy(out,cfg[slot(id)]); }
static int CFG_set_str(int id,char *val) { sets++; if(sets==fail_at)return -1;strcpy(cfg[slot(id)],val);return 0; }
static int CFG_commit(int flags) { assert(flags==CFG_NO_EVENT);return 1; }
static void cyg_thread_delay(int n) {}
static void cyg_semaphore_init(cyg_sem_t *s,int n) {}
static void cyg_semaphore_wait(cyg_sem_t *s) {}
static void cyg_semaphore_post(cyg_sem_t *s) {}
static void cyg_thread_create(int priority,void (*f)(cyg_addrword_t),cyg_addrword_t arg,const char *name,void *stack,size_t size,cyg_handle_t *handle,cyg_thread *thread) {}
static void cyg_thread_resume(cyg_handle_t h) {}
static int save_fail;
static int CFG_save_user(void) { return save_fail ? -1 : 0; }
const char sys_cust_ver[]="test-1";
const unsigned int sys_build_time=1700000000;
static long long cyg_current_time(void) { return 12345; }
int CFG_telnet_allowed(void) { return 0; }
int HTTPD_reconf;
#define MON_CMD_REBOOT 2
static int reboots;
static void mon_snd_cmd(int cmd) { assert(cmd==MON_CMD_REBOOT); reboots++; }
int wg_ecos_state(void) { return 4; }
const char *wg_ecos_status(void) { return "Connected to 164.163.10.88:51820"; }
int wg_ecos_public_key(char b64[45]) { strcpy(b64,"cfMOYfs5ZT4ic035jD9qCG4UM/KgpdfZNUNhynZ2KS4="); return 0; }
long wg_ecos_handshake_age(void) { return 12; }
void wg_ecos_counters(unsigned long *rx, unsigned long *tx) { *rx = 436; *tx = 380; }
int wg_b64_decode32(unsigned char out[32], const char *s) { size_t i; (void)out; if (strlen(s) != 44 || s[43] != '=') return -1; for (i = 0; i < 43; i++) if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", s[i])) return -1; return 0; }
const int CLI_boot_ids[8] = { 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008 };
const char *CLI_boot_result(int n) { return n == 0 ? "ok" : "unknown command"; }
const char *ramboot_web_state(void) { return "idle"; }
const char *ramboot_web_error(void) { return "none"; }
int ramboot_web_busy(void) { return 0; }
/* IMPLEMENTATION */
static int wifi_ui_restart(void) { return 0; }
static int uplink_up=1;
static int wifi_ui_uplink_connected(void) { return uplink_up; }
static http_req post={METHOD_POST};
static void setup(const char *mode) {
 int i; const char *n[]={"MODE","SSID","PASSWORD","CHANNEL","UPLINK_SSID","UPLINK_PASSWORD","UPLINK_SECURITY",NULL};
 const char *v[]={mode,"Test AP","test-pass-123","6","Test uplink","uplink-pass-123","wpa2",NULL};
 for(i=0;i<12;i++){names[i]=i<8?n[i]:NULL;values[i]=i<8?v[i]:NULL;}
 for(i=0;i<64;i++)strcpy(cfg[i],"original");
 sets=0;fail_at=-1;output[0]=0;wifi_ui_busy=0;save_fail=0;HTTPD_reconf=0;reboots=0;
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
 setup("ap");names[7]="SAVE";values[7]="0";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(wifi_ui_save_pending==0);
 setup("ap");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(wifi_ui_save_pending==1);assert(!strcmp(cfg[CFG_SYS_OPMODE],"3"));assert(!strcmp(cfg[CFG_LAN_IP_MODE],"0"));assert(!strcmp(cfg[CFG_LAN_DHCPD_EN],"0"));assert(!strcmp(cfg[CFG_WLN_AutoSSID],"1"));assert(!strcmp(cfg[CFG_WLN_ApCliEnable],"0"));assert(!strcmp(cfg[CFG_WLN_MACRepeaterEn],"0"));assert(!strcmp(cfg[CFG_WLN_AuthMode],"WPA2PSK;OPEN;OPEN;OPEN"));
 setup("repeater");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliEnable],"1"));assert(!strcmp(cfg[CFG_WLN_MACRepeaterEn],"1"));assert(!strcmp(cfg[CFG_WLN_ApCliAuthMode],"WPA2PSK"));assert(!strcmp(cfg[CFG_WLN_ApCliWPAPSK],"uplink-pass-123"));
 setup("repeater");values[6]="open";values[5]=NULL;CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliEncrypType],"NONE"));assert(!strcmp(cfg[CFG_WLN_ApCliWPAPSK],""));
 setup("repeater");values[6]="mixed";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliAuthMode],"WPAPSKWPA2PSK"));
 setup("ap");fail_at=7;CGI_wifi_apply(&post);assert(strstr(output,"ERROR:"));for(i=0;i<64;i++)assert(!strcmp(cfg[i],"original"));
 setup("ap");strcpy(cfg[CFG_WLN_SSID1],"</script>\"&");CGI_wifi_state(&post);assert(strstr(output,"\\u003c/script\\u003e"));assert(!strstr(output,"</script>"));assert(!strstr(output,"test-pass"));
 /* Device network security */
 setup("ap");names[8]="DEVICE_SECURITY";values[8]="open";values[2]="";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_AuthMode],"OPEN;OPEN;OPEN;OPEN"));assert(!strcmp(cfg[CFG_WLN_EncrypType],"NONE;NONE;NONE;NONE"));assert(!strcmp(cfg[CFG_WLN_WPAPSK1],""));
 setup("ap");values[2]=NULL;CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_AuthMode],"OPEN;OPEN;OPEN;OPEN"));
 setup("ap");names[8]="DEVICE_SECURITY";values[8]="wpa2";values[2]="";strcpy(cfg[CFG_WLN_AuthMode],"WPA2PSK;OPEN;OPEN;OPEN");strcpy(cfg[CFG_WLN_WPAPSK1],"stored-pass-1");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_WPAPSK1],"stored-pass-1"));
 setup("ap");names[8]="DEVICE_SECURITY";values[8]="wpa2";values[2]="";strcpy(cfg[CFG_WLN_AuthMode],"OPEN;OPEN;OPEN;OPEN");rejected();
 setup("ap");names[8]="DEVICE_SECURITY";values[8]="wep";rejected();
 /* Stored uplink password is kept only for the same uplink SSID */
 setup("repeater");values[5]="";strcpy(cfg[CFG_WLN_ApCliSsid],"Test uplink");strcpy(cfg[CFG_WLN_ApCliWPAPSK],"uplink-stored-1");CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_ApCliWPAPSK],"uplink-stored-1"));
 setup("repeater");values[5]="";strcpy(cfg[CFG_WLN_ApCliSsid],"Other");strcpy(cfg[CFG_WLN_ApCliWPAPSK],"uplink-stored-1");rejected();
 /* State reports uplink status in repeater mode and never passwords */
 setup("repeater");strcpy(cfg[CFG_WLN_ApCliEnable],"1");strcpy(cfg[CFG_SYS_ADMPASS],"secret-admin");CGI_wifi_state(&post);assert(strstr(output,"\"uplink_status\":\"connected\""));assert(strstr(output,"\"admin_password_set\":1"));assert(!strstr(output,"secret-admin"));assert(strstr(output,"\"chip\":\"MT7628KN\""));
 /* Administration */
#define ADMIN(u,p,c,cur) do{setup("ap");names[0]="USER";values[0]=(u);names[1]="PASSWORD";values[1]=(p);names[2]="CONFIRM";values[2]=(c);names[3]="CURRENT";values[3]=(cur);for(i=4;i<12;i++)names[i]=NULL;}while(0)
 ADMIN("admin","new-pass-1","new-pass-1","");strcpy(cfg[CFG_SYS_ADMPASS],"");CGI_admin_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_ADMPASS],"new-pass-1"));assert(HTTPD_reconf==1);
 ADMIN("admin","new-pass-1","new-pass-2","");strcpy(cfg[CFG_SYS_ADMPASS],"");CGI_admin_apply(&post);assert(strstr(output,"do not match"));assert(sets==0);
 ADMIN("ad min","new-pass-1","new-pass-1","");CGI_admin_apply(&post);assert(strstr(output,"ERROR"));assert(sets==0);
 ADMIN("ad:min","new-pass-1","new-pass-1","");CGI_admin_apply(&post);assert(strstr(output,"ERROR"));assert(sets==0);
 ADMIN("admin","short","short","");strcpy(cfg[CFG_SYS_ADMPASS],"");CGI_admin_apply(&post);assert(strstr(output,"ERROR"));assert(sets==0);
 ADMIN("admin","new-pass-1","new-pass-1","wrong");strcpy(cfg[CFG_SYS_ADMPASS],"old-pass-1");CGI_admin_apply(&post);assert(strstr(output,"current password"));assert(sets==0);
 ADMIN("admin","new-pass-1","new-pass-1","old-pass-1");strcpy(cfg[CFG_SYS_ADMPASS],"old-pass-1");CGI_admin_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_ADMPASS],"new-pass-1"));
 ADMIN("admin","","","old-pass-1");strcpy(cfg[CFG_SYS_ADMPASS],"old-pass-1");CGI_admin_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_ADMPASS],""));
 ADMIN("admin","new-pass-1","new-pass-1","");strcpy(cfg[CFG_SYS_ADMPASS],"");save_fail=1;CGI_admin_apply(&post);assert(strstr(output,"saving"));
 ADMIN("admin","new-pass-1","new-pass-1","");CGI_admin_apply(&get);assert(strstr(output,"POST required"));assert(sets==0);
 setup("repeater");strcpy(cfg[CFG_WLN_ApCliEnable],"1");uplink_up=0;CGI_wifi_state(&post);assert(strstr(output,"\"uplink_status\":\"disconnected\""));uplink_up=1;
 /* WireGuard */
#define WGK "YrZ7dX/8XFcP54QatyBWLDXipzhGnLWtvf1iPwG9bCA="
#define WG(e,a,k,h,p,ka,psk) do{setup("ap");names[0]="ENABLED";values[0]=(e);names[1]="ADDRESS";values[1]=(a);names[2]="PEER_PUBLIC_KEY";values[2]=(k);names[3]="ENDPOINT";values[3]=(h);names[4]="PORT";values[4]=(p);names[5]="KEEPALIVE";values[5]=(ka);names[6]="PRESHARED_KEY";values[6]=(psk);for(i=7;i<12;i++)names[i]=NULL;}while(0)
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25","");strcpy(cfg[CFG_SYS_ADMPASS],"admin-pass-1");CGI_wg_apply(&post);assert(!strcmp(output,"OK"));assert(reboots==1);assert(!strcmp(cfg[CFG_SYS_WG_ADDR],"10.8.0.30/24"));assert(!strcmp(cfg[CFG_SYS_WG_PEER],WGK));assert(!strcmp(cfg[CFG_SYS_WG_KEEPALIVE],"25"));assert(!strcmp(cfg[CFG_SYS_WG_PSK],""));
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25","keep");strcpy(cfg[CFG_SYS_ADMPASS],"x");strcpy(cfg[CFG_SYS_WG_PSK],"stored");CGI_wg_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_WG_PSK],"stored"));
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25",WGK);strcpy(cfg[CFG_SYS_ADMPASS],"x");CGI_wg_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_WG_PSK],WGK));
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25","");strcpy(cfg[CFG_SYS_ADMPASS],"");CGI_wg_apply(&post);assert(strstr(output,"admin password"));assert(sets==0&&reboots==0);
 WG("1","",WGK,"br.example","51820","25","");strcpy(cfg[CFG_SYS_ADMPASS],"x");CGI_wg_apply(&post);assert(strstr(output,"required"));assert(sets==0);
 WG("0","","","","51820","25","");CGI_wg_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_WG_EN],"0"));
 WG("1","10.8.0.30",WGK,"br.example","51820","25","");CGI_wg_apply(&post);assert(strstr(output,"address"));assert(sets==0);
 WG("1","10.8.0.300/24",WGK,"br.example","51820","25","");CGI_wg_apply(&post);assert(strstr(output,"address"));assert(sets==0);
 WG("1","10.8.0.30/40",WGK,"br.example","51820","25","");CGI_wg_apply(&post);assert(strstr(output,"address"));assert(sets==0);
 WG("1","10.8.0.30/24","short","br.example","51820","25","");CGI_wg_apply(&post);assert(strstr(output,"peer public key"));assert(sets==0);
 WG("1","10.8.0.30/24",WGK,"bad host","51820","25","");CGI_wg_apply(&post);assert(strstr(output,"endpoint"));assert(sets==0);
 WG("1","10.8.0.30/24",WGK,"br.example","0","25","");CGI_wg_apply(&post);assert(strstr(output,"port"));assert(sets==0);
 WG("1","10.8.0.30/24",WGK,"br.example","51820","9999","");CGI_wg_apply(&post);assert(strstr(output,"keepalive"));assert(sets==0);
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25","bad");CGI_wg_apply(&post);assert(strstr(output,"preshared"));assert(sets==0);
 WG("1","10.8.0.30/24",WGK,"br.example","51820","25","");CGI_wg_apply(&get);assert(strstr(output,"POST required"));assert(sets==0);
 setup("ap");strcpy(cfg[CFG_SYS_WG_EN],"1");strcpy(cfg[CFG_SYS_WG_PSK],"secret-psk");CGI_wifi_state(&post);assert(strstr(output,"\"wireguard\":{\"enabled\":1"));assert(strstr(output,"\"state\":\"connected\""));assert(strstr(output,"\"preshared_key_set\":1"));assert(strstr(output,"\"handshake_age\":12"));assert(!strstr(output,"secret-psk"));
 /* Startup script */
#define SU(a,b) do{setup("ap");for(i=0;i<12;i++)names[i]=NULL;names[0]="COMMAND1";values[0]=(a);names[1]="COMMAND3";values[1]=(b);}while(0)
 SU("net route add 10.9.0.0 255.255.0.0 192.168.1.2","");strcpy(cfg[51],"keep me");CGI_startup_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[50],"net route add 10.9.0.0 255.255.0.0 192.168.1.2"));assert(!strcmp(cfg[52],""));assert(!strcmp(cfg[51],"keep me"));assert(reboots==0);
 SU("bad\nline","");CGI_startup_apply(&post);assert(strstr(output,"printable"));assert(sets==0);
 {static char longline[260];memset(longline,'a',201);longline[201]=0;SU(longline,"");CGI_startup_apply(&post);assert(strstr(output,"longer"));assert(sets==0);}
 SU("x","");CGI_startup_apply(&get);assert(strstr(output,"POST required"));assert(sets==0);
 SU("x","");save_fail=1;CGI_startup_apply(&post);assert(strstr(output,"saving"));
 setup("ap");strcpy(cfg[50],"net route add a b c");strcpy(cfg[51],"");CGI_wifi_state(&post);assert(strstr(output,"\"startup\":[{\"command\":\"net route add a b c\",\"result\":\"ok\"},{\"command\":\"\",\"result\":\"\"}"));
 puts("PASS: startup script validation, keep/clear semantics, no restart and state");
 /* Router (WISP) mode */
 setup("router");names[8]="DEVICE_SECURITY";values[8]="open";values[2]="";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(reboots==1);
 assert(!strcmp(cfg[CFG_SYS_OPMODE],"2"));assert(!strcmp(cfg[CFG_LAN_IP_MODE],"1"));assert(!strcmp(cfg[CFG_LAN_IP],"10.0.1.1"));assert(!strcmp(cfg[CFG_LAN_MSK],"255.255.255.0"));
 assert(!strcmp(cfg[CFG_LAN_DHCPD_EN],"1"));assert(!strcmp(cfg[CFG_LAN_DHCPD_START],"10.0.1.100"));assert(!strcmp(cfg[CFG_LAN_DHCPD_END],"10.0.1.199"));
 assert(!strcmp(cfg[CFG_WLN_ApCliEnable],"1"));assert(!strcmp(cfg[CFG_WLN_MACRepeaterEn],"0"));assert(!strcmp(cfg[CFG_WLN_ApCliSsid],"Test uplink"));
 setup("router");names[8]="LAN_ADDRESS";values[8]="192.168.50.1/24";names[9]="LAN_DHCP";values[9]="0";names[10]="UPLINK_BSSID";values[10]="28:ee:52:37:d2:71";CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));
 assert(!strcmp(cfg[CFG_LAN_IP],"192.168.50.1"));assert(!strcmp(cfg[CFG_LAN_DHCPD_EN],"0"));assert(!strcmp(cfg[CFG_WLN_ApCliBssid],"28:ee:52:37:d2:71"));
 setup("router");names[8]="LAN_ADDRESS";values[8]="10.0.1.0/24";CGI_wifi_apply(&post);assert(strstr(output,"LAN_ADDRESS"));assert(sets==0);
 setup("router");names[8]="UPLINK_BSSID";values[8]="zz:ee:52:37:d2:71";CGI_wifi_apply(&post);assert(strstr(output,"UPLINK_BSSID"));assert(sets==0);
 /* leaving router mode also restarts; the extra networks' entries are kept */
 setup("ap");strcpy(cfg[CFG_SYS_OPMODE],"2");strcpy(cfg[CFG_WLN_ApCliEnable],"1");strcpy(cfg[CFG_WLN_AuthMode],"OPEN;WPA2PSK;OPEN;OPEN");strcpy(cfg[CFG_WLN_BssidNum],"3");
 CGI_wifi_apply(&post);assert(!strcmp(output,"OK"));assert(reboots==1);assert(!strcmp(cfg[CFG_SYS_OPMODE],"3"));assert(!strcmp(cfg[CFG_WLN_AuthMode],"WPA2PSK;WPA2PSK;OPEN;OPEN"));assert(!strcmp(cfg[CFG_WLN_BssidNum],"3"));
 /* Networks */
#define NETSETUP() do{setup("ap");for(i=0;i<12;i++)names[i]=NULL;strcpy(cfg[CFG_SYS_OPMODE],"2");strcpy(cfg[CFG_WLN_ApCliEnable],"1");strcpy(cfg[CFG_LAN_IP],"10.0.1.1");strcpy(cfg[CFG_LAN_MSK],"255.255.255.0");strcpy(cfg[CFG_SYS_WG_ADDR],"10.8.0.30/24");strcpy(cfg[CFG_WLN_AuthMode],"OPEN;OPEN;OPEN;OPEN");strcpy(cfg[CFG_WLN_EncrypType],"NONE;NONE;NONE;NONE");strcpy(cfg[CFG_WLN_NoForwarding],"0;0;0;0");}while(0)
#define Q(k,v) do{for(i=0;i<12&&names[i];i++);names[i]=(k);values[i]=(v);}while(0)
 NETSETUP();Q("COUNT","3");Q("SSID2","guest");Q("SECURITY2","open");Q("ADDRESS2","10.0.2.1/24");Q("ISOLATE2","1");Q("SSID3","iot");Q("SECURITY3","wpa2");Q("PASSWORD3","iot-pass-123");Q("ADDRESS3","10.0.3.1/24");Q("INTERNET3","1");Q("REACH3","lan,net2");
 CGI_networks_apply(&post);assert(!strcmp(output,"OK"));assert(reboots==1);assert(!strcmp(cfg[CFG_WLN_BssidNum],"3"));assert(!strcmp(cfg[CFG_WLN_SSID2],"guest"));assert(!strcmp(cfg[CFG_SYS_NET2_IP],"10.0.2.1/24"));
 assert(!strcmp(cfg[CFG_WLN_AuthMode],"OPEN;OPEN;WPA2PSK;OPEN"));assert(!strcmp(cfg[CFG_WLN_EncrypType],"NONE;NONE;AES;NONE"));assert(!strcmp(cfg[CFG_WLN_NoForwarding],"0;1;0;0"));
 assert(!strcmp(cfg[CFG_WLN_WPAPSK3],"iot-pass-123"));assert(!strcmp(cfg[CFG_SYS_NET3_REACH],"lan,net2"));assert(!strcmp(cfg[CFG_SYS_NET2_INTERNET],"1"));
 NETSETUP();Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","open");Q("ADDRESS2","10.0.1.129/25");CGI_networks_apply(&post);assert(strstr(output,"overlaps the LAN"));assert(sets==0);
 NETSETUP();Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","open");Q("ADDRESS2","10.8.0.1/16");CGI_networks_apply(&post);assert(strstr(output,"WireGuard"));assert(sets==0);
 NETSETUP();Q("COUNT","3");Q("SSID2","a");Q("SECURITY2","open");Q("ADDRESS2","10.0.2.1/24");Q("SSID3","b");Q("SECURITY3","open");Q("ADDRESS3","10.0.2.200/24");CGI_networks_apply(&post);assert(strstr(output,"overlaps ADDRESS2"));assert(sets==0);
 NETSETUP();strcpy(cfg[CFG_SYS_OPMODE],"3");Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","open");Q("ADDRESS2","10.0.2.1/24");CGI_networks_apply(&post);assert(strstr(output,"router mode"));assert(sets==0);
 NETSETUP();strcpy(cfg[CFG_SYS_OPMODE],"3");Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","open");CGI_networks_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_SYS_NET2_IP],""));
 NETSETUP();Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","open");Q("REACH2","lan,everything");CGI_networks_apply(&post);assert(strstr(output,"REACH2"));assert(sets==0);
 NETSETUP();Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","wpa2");CGI_networks_apply(&post);assert(strstr(output,"PASSWORD2 is required"));assert(sets==0);
 NETSETUP();strcpy(cfg[CFG_WLN_AuthMode],"OPEN;WPA2PSK;OPEN;OPEN");strcpy(cfg[CFG_WLN_WPAPSK2],"stored-key-22");Q("COUNT","2");Q("SSID2","guest");Q("SECURITY2","wpa2");CGI_networks_apply(&post);assert(!strcmp(output,"OK"));assert(!strcmp(cfg[CFG_WLN_WPAPSK2],"stored-key-22"));
 NETSETUP();Q("COUNT","5");CGI_networks_apply(&post);assert(strstr(output,"COUNT"));assert(sets==0);
 NETSETUP();Q("COUNT","2");Q("SSID2","x");Q("SECURITY2","open");CGI_networks_apply(&get);assert(strstr(output,"POST required"));
 /* state */
 NETSETUP();strcpy(cfg[CFG_WLN_BssidNum],"2");strcpy(cfg[CFG_WLN_SSID2],"guest");strcpy(cfg[CFG_SYS_NET2_IP],"10.0.2.1/24");strcpy(cfg[CFG_SYS_NET2_INTERNET],"1");strcpy(cfg[CFG_LAN_DHCPD_EN],"1");strcpy(cfg[CFG_WLN_WPAPSK2],"secret-net-key");
 CGI_wifi_state(&post);assert(strstr(output,"\"mode\":\"router\""));assert(strstr(output,"\"lan\":{\"address\":\"10.0.1.1/24\",\"dhcp\":1}"));
 assert(strstr(output,"{\"id\":2,\"enabled\":1,\"ssid\":\"guest\",\"security\":\"open\",\"isolate\":0,\"address\":\"10.0.2.1/24\""));assert(strstr(output,"{\"id\":3,\"enabled\":0"));assert(!strstr(output,"secret-net-key"));
  setup("ap");CGI_wifi_state(&post);assert(strstr(output,"\"firmware\":{\"busy\":0,\"state\":\"idle\",\"error\":\"none\"}"));
 puts("PASS: router mode, per-SSID list preservation, networks validation/overlaps/apply and state");
 puts("PASS: WireGuard validation, preshared key handling, admin requirement, save+restart and state");
 puts("PASS: admin credentials validation, current-password check and save");
 puts("PASS: server validation, AP/repeater mapping, open/mixed security, rollback and JSON escaping");
 return 0;
}
