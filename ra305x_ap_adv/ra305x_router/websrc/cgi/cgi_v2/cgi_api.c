/****************************************************************************
 * Ralink Tech Inc.
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

    Module Name:
    cfg_api.c

    Abstract:

    Revision History:
    Who         When            What
    --------    ----------      ------------------------------------------
*/

//==============================================================================
//                                INCLUDE FILES
//==============================================================================
// begin
#include <sys/types.h>
#include <network.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <cyg/kernel/kapi.h>
#include <cyg/io/flash.h>
#include <cyg/infra/diag.h>
#include <ifaddrs.h>
#include <cyg/io/eth/eth_drv_stats.h>
#include <cyg/io/eth/eth_drv.h>
#include <cyg/io/eth/netdev.h>

#include <config.h>
#include <http_proc.h>
#include <http_conf.h>
#include <cfg_net.h>
#include <sys_status.h>
#include <net/route.h>
#include <net/if.h>
#include <stdlib.h>
#include <cfg_id.h>

#if	MODULE_SYSLOG
#include <eventlog.h>
#endif

#include <cfg_def.h>
#include <cfg_net.h>
#include <time.h>
#include <cgi_api.h>

#if defined(RT3052) || defined(RT3352) || defined(RT6352) || defined(MT7620)||defined(CONFIG_MT7628_ASIC)
#define	SYS_TX_ANTENNA	2
#define	SYS_RX_ANTENNA	2
#else
#define	SYS_TX_ANTENNA	1
#define	SYS_RX_ANTENNA	1
#endif

//==============================================================================
//                                    MACROS
//==============================================================================

//==============================================================================
//                               TYPE DEFINITIONS
//==============================================================================

//==============================================================================
//                               Porting from APSoC
//==============================================================================

static int	security_index = 0;
static int	bssid_index = 0;
static int	ssid_index = 0;
static int	current_ssid_num = 1;
int 		g_wsc_configured = 0;
static multi_ssid_s	mBSSID[4];
static wds_tbl_s	mWDS[4];

static int g_new_version;
int		site_survey_count = 0;
char		if_addr[16] = {0};
char		if_net[16] = {0};
char		if_hw[18] = {0};

time_t wps_status_start_time = 0;
time_t system_start_time = 0;
int wps_status_flag = 0;

//==============================================================================
//                               LOCAL VARIABLES
//==============================================================================
char *upgrade_file=0;
//char *upgrade_mem=0;
http_upload_content *upgrade_mem=0;
int upgrade_file_len=0;
unsigned int upgrade_time_stamp=0;
unsigned char	wlan_tx_rx_count[100];


char PING_Result[350];
extern char SavePingResult[60];
//==============================================================================
//                          LOCAL FUNCTION PROTOTYPES
//==============================================================================


//==============================================================================
//                              EXTERNAL FUNCTIONS
//==============================================================================
#ifdef	CONFIG_ZWEB
extern int zweb_location;
#endif
extern int opmode; /*1:Gateway, 2:Apcli as WAN port, 3:Repeater Mode */


//------------------------------------------------------------------------------
// FUNCTION
//
//
// DESCRIPTION
//
//  
// PARAMETERS
//
//  
// RETURN
//
//  
//------------------------------------------------------------------------------

extern struct	radix_node_head *rt_tables[AF_MAX+1];

typedef	struct cgi_cmd_t
{
	char * cmd;
	int (*func)(http_req *req);
} cgi_cmd;

int CGI_do_wan_connect(http_req *req);
int CGI_do_rt_add(http_req *req);
int system2(char *str);
int CGI_do_wireless_simple_config_device(http_req *req);
int CGI_do_wireless_security(http_req *req);
/*add by seen*/
void CGI_do_update_mac(http_req *req);

/*end add*/
//add by rong
int IsHexChar(char ch);
unsigned char CharToValue(char c);
unsigned char TwoCharToByte(char h,char l);
//end add
int CGI_do_sys_config(http_req *req);
int CGI_do_sys_log(http_req *req);
int CGI_do_secure_log(http_req *req);
int CGI_do_sys_chk_pass(http_req *req);
int CGI_do_lan_dhcp_clients(http_req *req);
int CGI_set_ap_only(http_req *req);
int CGI_do_sys_log_mail(http_req *req);
int CGI_do_ntp_config(http_req *req);
int CGI_upgrade(http_req *req);
int CGI_upgrade_upload(http_req *req);
int CGI_upgrade_save(http_req *req);
void CGI_upgrade_free(void);
int CGI_do_vpn_connect(http_req *req);
int OidQueryInformation(unsigned short OidQueryCode, char *DeviceName, void *ptr, unsigned long PtrLength);
int  parse_config_file(void);
int save_mbss_value_to_flash(int save_level);
void ConverterStringToDisplay(char *str);
void ConverterStringToDisplay2(char *str);

cgi_cmd ps_cgi_cmds[]=
{
	{ "SYS_CONF", &CGI_do_sys_config },
#if	MODULE_SYSLOG
	{ "SYS_LOG", &CGI_do_sys_log },
	{ "SECURE_LOG",&CGI_do_secure_log},
#endif
	{ "SYS_PASS", &CGI_do_sys_chk_pass },
	{ "WAN_CON", &CGI_do_wan_connect },
	{ "SYS_UPG", &CGI_upgrade },
	{ "SYS_ULD", &CGI_upgrade_upload },
#if	MODULE_DHCPS
	{ "LAN_DHC", &CGI_do_lan_dhcp_clients },
#endif
	{ "RT_ADD"  , &CGI_do_rt_add },
	{ "WIRELESS_SECURITY", &CGI_do_wireless_security },
	{ "WIRELESS_SIMPLE_CONFIG_DEVICE", &CGI_do_wireless_simple_config_device },
	{ "ACL", &CGI_do_wireless_security },
	{ "UPDATE_MAC", &CGI_do_update_mac },//add by seen
};

cgi_cmd as_cgi_cmds[]=
{
#if		MODULE_SYSLOG
	{ "SYS_LOG_MAIL", &CGI_do_sys_log_mail },
#endif
#ifdef CONFIG_NTP
	{ "NTP", &CGI_do_ntp_config },
#endif
};


struct cfgobj_list_t;

/* Open file descriptors (sockets included) out of CYGNUM_FILEIO_NFD; shown
 * in the state to catch descriptor leaks ("Too many open files"). */
#include <cyg/fileio/fileio.h>
int wifi_ui_open_fds(void)
{
    int fd, n = 0;
    for (fd = 0; fd < CYGNUM_FILEIO_NFD; fd++) {
        cyg_file *fp = cyg_fp_get(fd);
        if (fp) { n++; cyg_fp_free(fp); }
    }
    return n;
}

/* English AP/repeater UI. Explicit saves or volatile previews. */
static volatile int wifi_ui_busy;
static unsigned int wifi_ui_revision;
static volatile int wifi_ui_error;
static int wifi_ui_save_pending;
static int wifi_ui_saved;
extern int CFG_save_user(void);
static const char *wifi_ui_stage = "idle";
static cyg_handle_t wifi_ui_handle;
static cyg_thread wifi_ui_thread;
static char wifi_ui_stack[16384];
static cyg_sem_t wifi_ui_wake;

static int wifi_ui_restart(void);
static int wifi_ui_is_router(void);
static int wifi_ui_is_gateway(void);
static void net_state(http_req *req);
extern int CFG_telnet_allowed(void);
static int wifi_ui_uplink_connected(void);
extern int wg_ecos_state(void);
extern const char *wg_ecos_status(void);
extern int wg_ecos_public_key(char b64[45]);
extern long wg_ecos_handshake_age(void);
extern void wg_ecos_counters(unsigned long *rx, unsigned long *tx);
extern int wg_b64_decode32(unsigned char out[32], const char *s);
extern const char *CLI_boot_result(int n);
#ifndef CLI_BOOT_LINES
#define CLI_BOOT_LINES 16 /* cli/cmd_boot.h */
#endif
extern const int CLI_boot_ids[CLI_BOOT_LINES];
extern const char *ramboot_web_state(void);
extern const char *ramboot_web_error(void);
extern int ramboot_web_busy(void);

static void wifi_ui_worker(cyg_addrword_t arg)
{
    for (;;) {
        cyg_semaphore_wait(&wifi_ui_wake);
        cyg_thread_delay(100); /* Let HTTP return before disconnecting Wi-Fi. */
        wifi_ui_error = wifi_ui_restart();
        if (!wifi_ui_error && wifi_ui_save_pending) {
            wifi_ui_stage="saving_config";
            if (CFG_save_user()) wifi_ui_error=-3;
            else wifi_ui_saved=1;
        }
        wifi_ui_stage = wifi_ui_error ? "failed" : "idle";
        wifi_ui_busy = 0;
    }
}

static int wifi_ui_text(const char *s, int min, int max)
{
    int n = 0;
    if (!s) return 0;
    while (*s) {
        unsigned char ch = (unsigned char)*s++;
        if (ch < 32 || ch == 127) return 0;
        n++;
    }
    return n >= min && n <= max;
}

static int wifi_ui_key(const char *s)
{
    int i;
    if (!wifi_ui_text(s, 8, 63)) return 0;
    for (i=0; s[i]; i++) if ((unsigned char)s[i] > 126) return 0;
    return 1;
}

/* JSON escaping also prevents an SSID from closing the enclosing script. */
static void wifi_ui_json(http_req *req, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    WEB_printf(req, "\"");
    for (; *p; p++) {
        if (*p == '"' || *p == '\\') WEB_printf(req, "\\%c", *p);
        else if (*p < 32 || *p == '<' || *p == '>' || *p == '&')
            WEB_printf(req, "\\u%04x", *p);
        else WEB_printf(req, "%c", *p);
    }
    WEB_printf(req, "\"");
}

void CGI_wifi_state(http_req *req)
{
    char val[256];
    CFG_get_str(CFG_WLN_ApCliEnable, val);
    WEB_printf(req, "{\"busy\":%d,\"revision\":%u,\"error\":%d,\"saved\":%d,\"stage\":\"%s\",\"mode\":\"%s\",\"ssid\":", wifi_ui_busy, wifi_ui_revision, wifi_ui_error, wifi_ui_saved, wifi_ui_stage,
               wifi_ui_is_gateway() ? "gateway" : wifi_ui_is_router() ? "router" : atoi(val) ? "repeater" : "ap");
    CFG_get_str(CFG_WLN_SSID1, val); wifi_ui_json(req,val);
    WEB_printf(req, ",\"uplink\":");
    CFG_get_str(CFG_WLN_ApCliSsid, val); wifi_ui_json(req,val);
    CFG_get_str(CFG_WLN_Channel, val);
    WEB_printf(req, ",\"channel\":%d,\"security\":", atoi(val));
    CFG_get_str(CFG_WLN_ApCliAuthMode, val); wifi_ui_json(req,val);
    CFG_get_str(CFG_WLN_AuthMode, val);
    WEB_printf(req, ",\"device_security\":\"%s\"", strncmp(val,"OPEN",4) ? "wpa2" : "open");
    CFG_get_str(CFG_SYS_USERS, val);
    WEB_printf(req, ",\"admin_user\":"); wifi_ui_json(req,val);
    CFG_get_str(CFG_SYS_ADMPASS, val);
    WEB_printf(req, ",\"admin_password_set\":%d,\"telnet\":%d", val[0] != '\0', CFG_telnet_allowed());
    WEB_printf(req, ",\"chip\":\"MT7628KN\",\"version\":"); wifi_ui_json(req,sys_cust_ver);
    WEB_printf(req, ",\"build\":%u,\"uptime\":%u", sys_build_time, (unsigned int)(cyg_current_time()/100));
    CFG_get_str(CFG_WLN_ApCliEnable, val);
    if (atoi(val)) {
        int up = wifi_ui_uplink_connected();
        WEB_printf(req, ",\"uplink_status\":\"%s\"", up > 0 ? "connected" : up == 0 ? "disconnected" : "unknown");
    }
    {
        static const char *const names[] = { "off", "starting", "clock", "handshake", "connected", "error" };
        char pub[45];
        unsigned long rx, tx;
        int st = wg_ecos_state();
        CFG_get_str(CFG_SYS_WG_EN, val);
        WEB_printf(req, ",\"wireguard\":{\"enabled\":%d,\"address\":", atoi(val) == 1);
        CFG_get_str(CFG_SYS_WG_ADDR, val); wifi_ui_json(req, val);
        WEB_printf(req, ",\"peer_public_key\":");
        CFG_get_str(CFG_SYS_WG_PEER, val); wifi_ui_json(req, val);
        WEB_printf(req, ",\"endpoint\":");
        CFG_get_str(CFG_SYS_WG_HOST, val); wifi_ui_json(req, val);
        CFG_get_str(CFG_SYS_WG_PORT, val);
        WEB_printf(req, ",\"port\":%d", atoi(val));
        CFG_get_str(CFG_SYS_WG_KEEPALIVE, val);
        {
            extern int wg_ecos_watchdog_minutes(void);
            char wd[8];
            wd[0] = '\0'; CFG_get_str(CFG_SYS_WG_WATCHDOG, wd);
            WEB_printf(req, ",\"watchdog\":%d", atoi(wd));
        }
        WEB_printf(req, ",\"keepalive\":%d,\"dns\":", atoi(val));
        val[0] = '\0'; CFG_get_str(CFG_SYS_WG_DNS, val); wifi_ui_json(req, val[0] ? val : "1.1.1.1");
        val[0] = '\0'; CFG_get_str(CFG_SYS_WG_TRANSPORT, val);
        WEB_printf(req, ",\"transport\":\"%s\",\"wss_path\":", strcmp(val, "wss") ? "udp" : "wss");
        val[0] = '\0'; CFG_get_str(CFG_SYS_WG_WSS_PATH, val); wifi_ui_json(req, val);
        WEB_printf(req, ",\"wss_name\":");
        val[0] = '\0'; CFG_get_str(CFG_SYS_WG_WSS_NAME, val); wifi_ui_json(req, val);
        WEB_printf(req, ",\"wss_key\":");
        val[0] = '\0'; CFG_get_str(CFG_SYS_WG_WSS_KEY, val); wifi_ui_json(req, val);
        CFG_get_str(CFG_SYS_WG_PSK, val);
        WEB_printf(req, ",\"preshared_key_set\":%d,\"public_key\":", val[0] != '\0');
        wg_ecos_public_key(pub); wifi_ui_json(req, pub);
        wg_ecos_counters(&rx, &tx);
        WEB_printf(req, ",\"state\":\"%s\",\"status\":", st >= 0 && st <= 5 ? names[st] : "error");
        wifi_ui_json(req, wg_ecos_status());
        WEB_printf(req, ",\"handshake_age\":%ld,\"rx_bytes\":%lu,\"tx_bytes\":%lu}", wg_ecos_handshake_age(), rx, tx);
        {
            extern int wifi_ui_open_fds(void);
            WEB_printf(req, ",\"open_fds\":%d", wifi_ui_open_fds());
            {
                extern const char *wg_ecos_wss_error(void);
                WEB_printf(req, ",\"wss_error\":"); wifi_ui_json(req, wg_ecos_wss_error());
            }
        }
    }
    {
        int n;
        WEB_printf(req, ",\"startup\":[");
        for (n = 0; n < CLI_BOOT_LINES; n++) {
            val[0] = '\0';
            CFG_get_str(CLI_boot_ids[n], val);
            WEB_printf(req, "%s{\"command\":", n ? "," : "");
            wifi_ui_json(req, val);
            WEB_printf(req, ",\"result\":");
            wifi_ui_json(req, val[0] ? CLI_boot_result(n) : "");
            WEB_printf(req, "}");
        }
        WEB_printf(req, "]");
    }
    val[0] = '\0'; CFG_get_str(CFG_SYS_MDNS_NAME, val);
    WEB_printf(req, ",\"mdns_name\":"); wifi_ui_json(req, val);
    {
        extern void mdns_status(const char **state, unsigned *queries, unsigned *answers, unsigned *noaddr);
        const char *ms; unsigned q, an, na;
        mdns_status(&ms, &q, &an, &na);
        WEB_printf(req, ",\"mdns\":{\"state\":\"%s\",\"queries\":%u,\"answers\":%u,\"no_address\":%u}", ms, q, an, na);
    }
    net_state(req);
    WEB_printf(req, ",\"firmware\":{\"busy\":%d,\"state\":", ramboot_web_busy());
    wifi_ui_json(req, ramboot_web_state());
    WEB_printf(req, ",\"error\":");
    wifi_ui_json(req, ramboot_web_error());
    WEB_printf(req, "}}");
}

/* Per-SSID lists such as "WPA2PSK;OPEN;OPEN;OPEN": replace item 0, keep the
 * others, pad to 4 items with pad. */
static void wifi_ui_list_first(char *out, const char *cur, const char *first, const char *pad)
{
    const char *p = strchr(cur, ';');
    int items = 1, i;
    strcpy(out, first);
    if (p) {
        strcat(out, p);
        for (; *p; p++) if (*p == ';') items++;
    }
    for (i = items; i < 4; i++) { strcat(out, ";"); strcat(out, pad); }
}

/* "aa:bb:cc:dd:ee:ff" */
static int wifi_ui_mac(const char *s)
{
    int i;
    if (!s || strlen(s) != 17) return 0;
    for (i = 0; i < 17; i++) {
        char c = s[i];
        if (i % 3 == 2) { if (c != ':') return 0; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}

/* Gateway mode: opmode 1, Ethernet is the WAN, Wi-Fi the LAN behind NAT. */
static int wifi_ui_is_gateway(void)
{
    char v[16];
    v[0] = 0; CFG_get_str(CFG_SYS_OPMODE, v);
    return atoi(v) == 1;
}

/* Router (WISP) mode: opmode 2 with apcli0 as WAN. */
static int wifi_ui_is_router(void)
{
    char v[16];
    v[0] = 0; CFG_get_str(CFG_SYS_OPMODE, v);
    if (atoi(v) != 2) return 0;
    v[0] = 0; CFG_get_str(CFG_WLN_ApCliEnable, v);
    return atoi(v) != 0;
}

void CGI_wifi_apply(http_req *req)
{
    struct wifi_change { int id; const char *value; char old[256]; };
    struct wifi_change *changes;
    char *mode, *ssid, *key, *uplink, *upkey, *security, *channel, *end, *save, *dsec;
    char *lanaddr, *landhcp, *bssid;
    char curkey[256], curup[256], curupkey[256], curauth[256];
    char authl[256], encl[256], hidel[256], curl[256];
    char lanip[20], lanmask[20], dstart[20], dend[20];
    int repeater, router, gateway, routed, was_routed, open_ap, ch, count = 0, i;
    static int created;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    if (wifi_ui_busy) { WEB_printf(req,"ERROR: configuration is busy"); return; }
    mode = WEB_query(req,"MODE"); ssid = WEB_query(req,"SSID");
    key = WEB_query(req,"PASSWORD"); uplink = WEB_query(req,"UPLINK_SSID");
    upkey = WEB_query(req,"UPLINK_PASSWORD"); security = WEB_query(req,"UPLINK_SECURITY");
    channel = WEB_query(req,"CHANNEL");
    save = WEB_query(req,"SAVE");
    dsec = WEB_query(req,"DEVICE_SECURITY");
    if (save && strcmp(save,"0") && strcmp(save,"1")) goto invalid;
    if (!mode || (strcmp(mode,"ap") && strcmp(mode,"repeater") && strcmp(mode,"router") && strcmp(mode,"gateway"))) goto invalid;
    repeater = !strcmp(mode,"repeater");
    router = !strcmp(mode,"router");
    gateway = !strcmp(mode,"gateway");
    routed = router || gateway;
    was_routed = wifi_ui_is_router() || wifi_ui_is_gateway();
    lanaddr = WEB_query(req,"LAN_ADDRESS"); landhcp = WEB_query(req,"LAN_DHCP"); bssid = WEB_query(req,"UPLINK_BSSID");
    if (routed) {
        extern int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask);
        unsigned long lip, lmask, base;
        struct in_addr a;
        if (!lanaddr || !*lanaddr) lanaddr = gateway ? "192.168.11.1/24" : "10.0.1.1/24";
        if (net_extra_parse(lanaddr, &lip, &lmask)) { WEB_printf(req,"ERROR: LAN_ADDRESS must be IPv4/prefix (8-30), for example 10.0.1.1/24"); return; }
        if (landhcp && strcmp(landhcp,"0") && strcmp(landhcp,"1")) goto invalid;
        a.s_addr = lip; strcpy(lanip, inet_ntoa(a));
        a.s_addr = lmask; strcpy(lanmask, inet_ntoa(a));
        base = ntohl(lip & lmask);
        a.s_addr = htonl(base + 100); strcpy(dstart, inet_ntoa(a));
        a.s_addr = htonl(base + 199 < ntohl(lip | ~lmask) ? base + 199 : ntohl(lip | ~lmask) - 1); strcpy(dend, inet_ntoa(a));
    }
    if (bssid && *bssid && !wifi_ui_mac(bssid)) { WEB_printf(req,"ERROR: UPLINK_BSSID must be aa:bb:cc:dd:ee:ff or empty"); return; }
    /* DEVICE_SECURITY=wpa2 with an empty PASSWORD keeps the current key.
     * Without DEVICE_SECURITY, an empty PASSWORD makes the network open. */
    if (dsec && !strcmp(dsec,"open")) open_ap = 1;
    else if (dsec && !strcmp(dsec,"wpa2")) {
        open_ap = 0;
        if (!key || !*key) {
            CFG_get_str(CFG_WLN_AuthMode,curauth);
            CFG_get_str(CFG_WLN_WPAPSK1,curkey);
            if (strncmp(curauth,"WPA2PSK",7) || !wifi_ui_key(curkey)) goto invalid;
            key = curkey;
        }
    } else if (dsec) goto invalid;
    else open_ap = !key || !*key;
    if (!wifi_ui_text(ssid,1,32) || (!open_ap && !wifi_ui_key(key)) || !channel) goto invalid;
    ch = strtol(channel,&end,10);
    if (*end || ch < 1 || ch > 13) goto invalid;
    if (repeater || router) {
        if (!wifi_ui_text(uplink,1,32) || !security) goto invalid;
        if (strcmp(security,"open") && strcmp(security,"wpa2") && strcmp(security,"mixed")) goto invalid;
        if (strcmp(security,"open") && (!upkey || !*upkey)) {
            /* Same uplink SSID: keep its stored password. */
            CFG_get_str(CFG_WLN_ApCliSsid,curup);
            CFG_get_str(CFG_WLN_ApCliWPAPSK,curupkey);
            if (!strcmp(curup,uplink)) upkey = curupkey;
        }
        if (strcmp(security,"open") && !wifi_ui_key(upkey)) goto invalid;
    }
    curl[0] = 0; CFG_get_str(CFG_WLN_AuthMode, curl);
    wifi_ui_list_first(authl, curl, open_ap ? "OPEN" : "WPA2PSK", "OPEN");
    curl[0] = 0; CFG_get_str(CFG_WLN_EncrypType, curl);
    wifi_ui_list_first(encl, curl, open_ap ? "NONE" : "AES", "NONE");
    curl[0] = 0; CFG_get_str(CFG_WLN_HideSSID, curl);
    wifi_ui_list_first(hidel, curl, "0", "0");
    changes = calloc(40,sizeof(*changes));
    if (!changes) { WEB_printf(req,"ERROR: insufficient memory"); return; }
#define WIFI_CHANGE(k,v) do { changes[count].id=(k); changes[count++].value=(v); } while(0)
    /* Opmode 3 bridges Ethernet and Wi-Fi; ApCliEnable selects the uplink.
     * Router: opmode 2, apcli0 is the WAN, the LAN gets its own address.
     * Gateway: opmode 1, Ethernet is the WAN (DHCP), Wi-Fi the LAN. */
    WIFI_CHANGE(CFG_SYS_OPMODE,gateway ? "1" : router ? "2" : "3");
    WIFI_CHANGE(CFG_LAN_IP_MODE,routed ? "1" : "0");
    WIFI_CHANGE(CFG_LAN_DHCPD_EN,routed && !(landhcp && !strcmp(landhcp,"0")) ? "1" : "0");
    if (gateway) WIFI_CHANGE(CFG_WAN_IP_MODE,"2");
    if (routed) {
        WIFI_CHANGE(CFG_LAN_IP,lanip);
        WIFI_CHANGE(CFG_LAN_MSK,lanmask);
        WIFI_CHANGE(CFG_LAN_DHCPD_START,dstart);
        WIFI_CHANGE(CFG_LAN_DHCPD_END,dend);
    }
    WIFI_CHANGE(CFG_WLN_EN,"1");
    WIFI_CHANGE(CFG_WLN_SSID1,ssid);
    WIFI_CHANGE(CFG_WLN_AutoSSID,"1");
    /* only SSID1's entries: the extra networks keep theirs */
    WIFI_CHANGE(CFG_WLN_AuthMode,authl);
    WIFI_CHANGE(CFG_WLN_EncrypType,encl);
    WIFI_CHANGE(CFG_WLN_WPAPSK1,open_ap ? "" : key);
    WIFI_CHANGE(CFG_WLN_HideSSID,hidel);
    WIFI_CHANGE(CFG_WLN_WirelessMode,"9");
    WIFI_CHANGE(CFG_WLN_HT_BW,"0");
    WIFI_CHANGE(CFG_WLN_AutoChannelSelect,"0");
    WIFI_CHANGE(CFG_WLN_Channel,channel);
    WIFI_CHANGE(CFG_WLN_ApCliEnable,repeater || router ? "1" : "0");
    WIFI_CHANGE(CFG_WLN_MACRepeaterEn,repeater ? "1" : "0");
    if (repeater || router) {
        WIFI_CHANGE(CFG_WLN_ApCliSsid,uplink);
        WIFI_CHANGE(CFG_WLN_ApCliBssid,bssid ? bssid : "");
        WIFI_CHANGE(CFG_WLN_ApCliAuthMode,!strcmp(security,"open") ? "OPEN" :
                    (!strcmp(security,"mixed") ? "WPAPSKWPA2PSK" : "WPA2PSK"));
        WIFI_CHANGE(CFG_WLN_ApCliEncrypType,!strcmp(security,"open") ? "NONE" :
                    (!strcmp(security,"mixed") ? "TKIPAES" : "AES"));
        WIFI_CHANGE(CFG_WLN_ApCliWPAPSK,!strcmp(security,"open") ? "" : upkey);
    }
#undef WIFI_CHANGE
    for (i=0; i<count; i++) CFG_get_str(changes[i].id,changes[i].old);
    for (i=0; i<count; i++) {
        if (CFG_set_str(changes[i].id,(char *)changes[i].value) < 0) {
            int j;
            for (j=0; j<=i; j++) CFG_set_str(changes[j].id,changes[j].old);
            CFG_commit(CFG_NO_EVENT);
            free(changes); WEB_printf(req,"ERROR: settings could not be applied"); return;
        }
    }
    free(changes);
    /* Suppress automatic monitor events: this worker applies without reboot. */
    CFG_commit(CFG_NO_EVENT);
    if (routed || was_routed) {
        /* the LAN address and the WAN change only at boot: save and restart */
        if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
        WEB_printf(req,"OK");
        mon_snd_cmd(MON_CMD_REBOOT);
        return;
    }
    /* Settings are saved unless SAVE=0 (kept for older clients). */
    wifi_ui_save_pending=!save || !strcmp(save,"1");
    wifi_ui_saved=0;
    wifi_ui_revision++;
    wifi_ui_error = 0;
    wifi_ui_stage = "queued";
    wifi_ui_busy = 1;
    if (!created) {
        cyg_semaphore_init(&wifi_ui_wake,0);
        cyg_thread_create(12,wifi_ui_worker,0,"wifi apply",wifi_ui_stack,
                          sizeof(wifi_ui_stack),&wifi_ui_handle,&wifi_ui_thread);
        created = 1;
        cyg_thread_resume(wifi_ui_handle);
    }
    cyg_semaphore_post(&wifi_ui_wake);
    WEB_printf(req,"OK");
    return;
invalid:
    WEB_printf(req,"ERROR: check mode, SSIDs, channel and passwords (empty for an open network, or 8-63 ASCII characters)");
}

static int wifi_ui_restart(void)
{
    extern int CFG_parse_wlan(struct cfgobj_list_t *cfg_lp);
    extern struct cfgobj_list_t cfg_list;
    extern int Wireless_down(void);
    extern int Wireless_start(void);
    int rc = 0;
#if (MODULE_DHCPS == 1)
    extern void DHCPD_down(void);
    /* The factory profile starts a DHCP server. Updating its config alone
     * leaves that daemon serving the old subnet until the next cold boot. */
    wifi_ui_stage = "stopping_dhcp_server";
    DHCPD_down();
#endif
#ifdef CONFIG_BRIDGE
    extern int BRG_start(int cmd);
    wifi_ui_stage = "stopping_bridge";
    BRG_start(0);
#endif
    /* Keep Ethernet, its DHCP lease and management sockets alive. */
    wifi_ui_stage = "stopping_wifi";
    netif_down("apcli0"); /* Also stop the OLD uplink when selecting AP. */
    Wireless_down();
    wifi_ui_stage = "parsing_config";
    if (CFG_parse_wlan(&cfg_list) < 0) rc = -1;
    interface_config(); /* Rebuild bridge members; does not reset Ethernet. */
    wifi_ui_stage = "starting_wifi";
    if (Wireless_start() < 0) rc = -2;
#ifdef CONFIG_BRIDGE
    wifi_ui_stage = "starting_bridge";
    BRG_start(1);
#endif
    return rc;
}

int CGI_do_cmd(http_req *req)
{
	int i;
	char cmdi[8];
	char *cmdv, *val;
	int id;
	int rc=0;
	char * cmd;
	int update_cnt =0;
	int forceToReboot = 0;

#if	(defined(CONFIG_HTTPD_MAX_USERS)&&(CONFIG_HTTPD_MAX_USERS>1))
	#ifdef	CONFIG_HTTPD_ADMIN_NAME
	// check user privilege 
	if(strcmp(req->auth_username, CONFIG_HTTPD_ADMIN_NAME))
	{
		rc=CGI_RC_PRIVILEGE_ERR;
		goto bad;
	}
#else
	char admin[256];
	CFG_get(CFG_SYS_USERS, admin);
	if (strcmp(req->auth_username,admin))
	{
		rc=CGI_RC_PRIVILEGE_ERR;
		goto bad;
	}
	#endif
#endif

	cmd=WEB_query(req,"CMD");
	if (!cmd)
		goto bad;
	if (cmd)
	{
		for (i=0; i< (sizeof(ps_cgi_cmds)/sizeof(cgi_cmd)) ; i++)
		{
			if (!strcmp(ps_cgi_cmds[i].cmd, cmd))
			{
				if (ps_cgi_cmds[i].func)
				{
					rc=(ps_cgi_cmds[i].func)(req);
					if (rc<0)	break;
				}

			}
		}

        	if( !(strcmp(cmd, "WIRELESS_SECURITY") && strcmp(cmd, "WIRELESS_SIMPLE_CONFIG_DEVICE") && strcmp(cmd, "ACL")))
	        	goto ReadyToOut;
	}

	if (rc<0)
		goto bad;
	
	for (i=0;i<50;i++)
	{
		sprintf(cmdi,"SET%d",i);
		cmdv=WEB_query(req,cmdi);
		if (cmdv==0)
			break;

		val=strchr(cmdv,'=');
		if (val == NULL ||( (unsigned int)val <= (unsigned int)cmdv))
		{
			rc=CGI_RC_CFG_ERR;
			break;
		}
		*val=0;
		val++;
		id=atoi(cmdv);
		if (id!=0)
		{

			if((CFG_ID_TYPE(id) == CFG_TYPE_STR)  
				&& (id != CFG_POE_USER)
				&& (id != CFG_POE_PASS))
			{
				/* we don't want to see '\n' and '\r'*/
				char *c=0;
				if((c = strpbrk(val, "\n\r")))
					*c = '\0';
			}
			diag_printf("call CFG set %s=[%s]\n", CFG_id2str(id), val);

			if (!strcmp(CFG_id2str(id), "WLN_BssidNum"))
			{
			;//	forceToReboot = 1;
			}


			
			rc=CFG_set_str(id,val);
			if (rc>=0) rc=CGI_RC_CFG_OK;
		}
	}
	
	/*change by seen*/
	//if (!strcmp(cmd, "OPMODE"))
	{
		char line[100], *p;
		int opmode_value;
		CFG_get_str(CFG_SYS_OPMODE, line);
		opmode_value = strtol(line, &p, 10);	

		if (opmode_value == 3) {
			CFG_set_str(CFG_WLN_MACRepeaterEn, "1");
			CFG_set_str(CFG_WLN_ApCliEnable, "1");
		} else if (opmode_value == 2) {
			CFG_set_str(CFG_WLN_ApCliEnable, "1");		
			CFG_set_str(CFG_WLN_MACRepeaterEn, "0");
		} else {
			CFG_set_str(CFG_WLN_MACRepeaterEn, "0");
		}
	}

ReadyToOut:	
	if (rc==CGI_RC_CFG_OK)/*change by seen*/
		if(!(strcmp(cmd, "WIRELESS_SECURITY"))){
			CFG_commit(CFG_DELAY_EVENT);//add by seen
		}else{
			update_cnt = CFG_commit(CFG_DELAY_EVENT);//old
		}
	else
		if (rc<0)
			goto bad;

	if (cmd)
	{
		for (i=0; i< (sizeof(as_cgi_cmds)/sizeof(cgi_cmd)) ; i++)
		{
			if (!strcmp(as_cgi_cmds[i].cmd, cmd))
			{
				if (as_cgi_cmds[i].func)
				{
					rc = (as_cgi_cmds[i].func)(req);
					if (rc<0)
						break;
				}

			}
		}
	}
        /* change the settings without rebooting the whole system */
	if (update_cnt && (forceToReboot == 0) && strcmp(cmd, "LAN") && strcmp(cmd, "DHCP") && strcmp(cmd, "QOS") && 
		strcmp(cmd, "WIRELESS_SIMPLE_CONFIG_DEVICE") && strcmp(cmd, "OPMODE"))
	{
		extern int CFG_parse_wlan(struct cfgobj_list_t *cfg_lp);
		extern struct cfgobj_list_t cfg_list;
#ifdef CONFIG_BRIDGE
			extern int BRG_start(int cmd);
			extern char bridge_cfg[128];
#endif /* CONFIG_BRIDGE */
#ifdef	CONFIG_UPNP
	extern int ssdp_Delete_MulticastIP(void);
	                ssdp_Delete_MulticastIP();
#endif	// CONFIG_UPNP //



#ifdef CONFIG_BRIDGE
			BRG_start(0);
#endif /* CONFIG_BRIDGE */
#ifdef CONFIG_WIRELESS
		extern int CmdIwpriv(int argc, char *argv[]);

		{	char *string[]={
			"ra0",
			"set",
			"DisConnectAllSta=1"
			};
			CmdIwpriv(3,string);
			cyg_thread_delay(10);
		}


			WLAN_start(0);
#endif 
			LAN_start(0);

			/* reload the cfgobj list and parse WIFI configuration into the array which WIFI driver uses. */
			CFG_parse_wlan(&cfg_list);

#ifdef CONFIG_BRIDGE                
			memset(&bridge_cfg[0], 0 , 128);
#endif /* CONFIG_BRIDGE */		
			interface_config();
			LAN_start(1);
#ifdef CONFIG_WIRELESS
			WLAN_start(1);
#endif /* CONFIG_WIRELESS */
#ifdef CONFIG_BRIDGE
			BRG_start(1);
#endif /* CONFIG_BRIDGE */

#ifdef	CONFIG_UPNP
	extern int ssdp_Update_MulticastIP(void);
	                ssdp_Update_MulticastIP();
#endif	// CONFIG_UPNP //

#ifdef RALINK_1X_SUPPORT		
			Dot1x_Reboot();
#endif //RALINK_1X_SUPPORT
	}
#if CONFIG_QOS
	else if (update_cnt && ( !strcmp(cmd, "QOS")))
	{	
		tfq_load_config();
	}
#endif
	else if ((update_cnt && ((forceToReboot == 1) || !strcmp(cmd, "LAN") || !strcmp(cmd, "DHCP") || 
		!strcmp(cmd, "OPMODE")))|| !strcmp(cmd, "SYS_UPG"))
	{
		/* need to reboot only while changing the number of BSSID or the LAN configuration. */ 
		mon_snd_cmd(MON_CMD_REBOOT);
		rc = CGI_RC_REBOOT;

	}

	if ((update_cnt == 0) && !strcmp(cmd, "WIRELESS_SIMPLE_CONFIG_RESET"))
	{
		diag_printf("Reset OOB!!!\n");
		
		int ret;
		char	wlanbuf[128];
		
		memset(wlanbuf, 0, 128);
		sprintf(wlanbuf, "WscStop=%d", 1);
		ret = system2(wlanbuf);

		memset(wlanbuf, 0, 128);
		sprintf(wlanbuf, "WscConfStatus=%d", 1);
		ret = system2(wlanbuf);
	}
	
bad:
	if (rc < 0)
	{
		diag_printf("cgi result=%d\n", rc);
	}
	
	return rc;
}

void sc_convert(char *instr)
{
	char *p;	
	
    p = instr;
    while(*p)
    {
    	if((*p == '"') || (*p == '\'') || (*p == '\\'))
    	{
    		memmove(p+1, p, strlen(p)+1);
    		*p = '\\';
    		p++; 
    	}
    	p++;
    }
}

void CGI_var_map(http_req *req, char *name, int id)
{
	char val[512] = {0};
	CFG_get_str(id, val);
	sc_convert(val);
	WEB_printf(req, "addCfg('%s',0x%08x,'%s');\n",name,id,val);
}

void CGI_var_map_array(http_req *req, char *name, int id, int num)
{
	char val[512] = {0};
	int i;
	for( i=0; i<num ; i++)
	{
		val[0]='\0';
		CFG_get_str(id+i, val);
		sc_convert(val);
		WEB_printf(req, "addCfg('%s%d',0x%08x,'%s');\n",name,i+1,id+i,val);
	}
}

char * CGI_put_var(http_req *req, char *var)
{
    char *val;
    val=WEB_query(req, var);
    if (val)
        WEB_printf(req, "%s", val );
	return val;
}


// 4
int CGI_do_wan_connect(http_req *req) { 

   char *action ;
   char *argv[1];
	int rc=CGI_RC_CONNECTING;
        
   action = WEB_query(req,"action");
   if (!action) return -1;

   	switch (*action)
	{
#if	(MODULE_WANIF==0)
	case '1': // call release function here
     	DHCPC_release_one(SYS_lan_if);
		rc=8;
     	break ;
	case '2': // call renew function here
    	DHCPC_renew(SYS_lan_if);
     	break ;
#else
#if (MODULE_DHCPC == 1)	
     case '1': // call release function here
     	DHCPC_release_one(SYS_wan_if);
		rc=8;
     	break ;
     case '2': // call renew function here
     	DHCPC_renew(SYS_wan_if);
     	break ;
#endif
#if (MODULE_PPPOE == 1)	
     case '3': // call connection function here
     	argv[0] = "up";
     	pppoe_cmd(1, argv);
    	 break ;
     case '4': // call disconnected function here
     	argv[0] = "down";
     	pppoe_cmd(1, argv);
		rc=8;
    	 break ;
#endif
#if (MODULE_PPTP == 1)	
     case '5': // call pptp connection function here
     	argv[0] = "up";
     	pptp_cmd(1, argv);
        break;
        
     case '6': // call disconnected function here
     	argv[0] = "down";
     	pptp_cmd(1, argv);
		rc=8;
        break;    
#endif
#if (MODULE_L2TP == 1)	 
     case '7': // call pptp connection function here
     	argv[0] = "up";
     	l2tp_cmd(1, argv);
        break;
      
     case '8': // call disconnected function here
     	argv[0] = "down";
     	l2tp_cmd(1, argv);
		rc=8;
        break;   
#endif    	 
#endif
   }                                        
    return rc;
} 

void CGI_reset_default(void)
{
	diag_printf("CGI_reset_default----->\n");
	
	CFG_reset_default();
	
	mon_snd_cmd(MON_CMD_REBOOT);
}
//add by rong
int IsHexChar(char ch)
{
if((ch>='0' && ch<='9') || (ch>='a' && ch<='f') ||(ch>='A' && ch<='F'))
return 1;
else
return 0;
}
unsigned char CharToValue(char c)
{
if(c>='0' && c<='9')
{
return c-'0';
}
if(c>='A' && c<='F')
{
return c-'A'+10;
}
if(c>='a' && c<='f')
{
return c-'a'+10;
}
}
unsigned char TwoCharToByte(char h,char l)
{
return (unsigned char)(CharToValue(h)*16 + CharToValue(l));
}
//add by seen
void CGI_do_update_mac(http_req *req)
{
	char *mac_addr,mac4[7],mac6[7],mac8[7];
	char mac2E[8],mac30[8],mac32[8];
	unsigned char mac_adrr1;
	int i = 0,j=0;
	if ((mac_addr = WEB_query(req,"UMAC"))==0)
		return -1;
	/*解析mac*/
	diag_printf("[MAC]%s\n",mac_addr);
	for(i=0,j=0;i<17;i++){
		if((i+1)%3 == 0){
			j += 1;
			continue;
		}

		if(i < 5){
			(j==1)?(mac2E[i-j-2+3] = mac_addr[i]):(mac2E[i-j+2+3] = mac_addr[i]);
		}else if(i < 11){
			(j==3)?(mac30[i-j-4-2+3] = mac_addr[i]):(mac30[i-j-4+2+3] = mac_addr[i]);
		}else if(i < 17){
			(j==5)?(mac32[i-j-8-2+3] = mac_addr[i]):(mac32[i-j-8+2+3] = mac_addr[i]);
		}
	}
	for(i=0,j=0;i<17;i++){
		if((i+1)%3 == 0){
			j += 1;
			continue;
		}

		if(i < 5){
			(j==1)?(mac4[i-j-2+2] = mac_addr[i]):(mac4[i-j+2+2] = mac_addr[i]);
		}else if(i < 11){
			(j==3)?(mac6[i-j-4-2+2] = mac_addr[i]):(mac6[i-j-4+2+2] = mac_addr[i]);
		}else if(i < 17){
			(j==5)?(mac8[i-j-8-2+2] = mac_addr[i]):(mac8[i-j-8+2+2] = mac_addr[i]);
		}
	}
	mac4[0] = '4';
	mac4[1] = '=';
	mac4[6] = '\0';

	mac6[0] = '6';
	mac6[1] = '=';
	mac6[6] = '\0';

	mac8[0] = '8';
	mac8[1] = '=';
	mac8[6] = '\0';
	diag_printf("Mac4=%s,Mac6=%s,Mac8=%s\n",mac4,mac6,mac8);
//add by rong
	diag_printf("%c\n",mac8[2]);
	diag_printf("%c\n",mac8[3]);
	mac_adrr1=TwoCharToByte(mac8[2],mac8[3]);
	
	mac_adrr1=mac_adrr1+1;
	diag_printf("%d\n",mac_adrr1);
	int aa=mac_adrr1/16;
	int bb=mac_adrr1%16;
	if(aa>=0&&aa<=9){
		aa=aa+0x30;
		
		}
	if(aa>=10&&aa<=15){
		aa=aa-10+'A';
		
		}
	if(bb>=0&&bb<=9){
		bb=bb+0x30;
		
		}
	if(bb>=10&&bb<=15){
		bb=bb-10+'A';
		
		}
	mac32[3]=aa;
	mac32[4]=bb;
	diag_printf("%s",mac32);

	mac2E[0] = '2';
	mac2E[1] = 'E';
	mac2E[2] = '=';
	mac2E[7] = '\0';

	mac30[0] = '3';
	mac30[1] = '0';
	mac30[2] = '=';
	mac30[7] = '\0';

	mac32[0] = '3';
	mac32[1] = '2';
	mac32[2] = '=';
	mac32[7] = '\0';
	diag_printf("Mac2E=%s,Mac30=%s,Mac32=%s\n",mac2E,mac30,mac32);
//add by rong

	extern int CmdIwpriv(int argc, char *argv[]);
	{	
		char *string4[]={
			"ra0",
			"e2p",
			mac4
		};
		char *string6[]={
			"ra0",
			"e2p",
			mac6
		};
		char *string8[]={
			"ra0",
			"e2p",
			mac8
		};

		CmdIwpriv(3,string4);
		cyg_thread_delay(3);
		CmdIwpriv(3,string6);
		cyg_thread_delay(3);
		CmdIwpriv(3,string8);
		cyg_thread_delay(5);
	}
	extern int CmdIwpriv(int argc, char *argv[]);
	{	
		char *string2E[]={
			"ra0",
			"e2p",
			mac2E
		};
		char *string30[]={
			"ra0",
			"e2p",
			mac30
		};
		char *string32[]={
			"ra0",
			"e2p",
			mac32
		};

		CmdIwpriv(3,string2E);
		cyg_thread_delay(3);
		CmdIwpriv(3,string30);
		cyg_thread_delay(3);
		CmdIwpriv(3,string32);
		cyg_thread_delay(5);
	}
	diag_printf("[UPDATE MAC]Sucessful...\n");
	diag_printf("[UPDATE MAC]reboot...\n");
	mon_snd_cmd(MON_CMD_REBOOT);
}
//end add
// 8
int CGI_do_sys_config(http_req *req)
{
   char *CCMD, *file,*ping;
   int len,rc, dst;
   int rtt, i;	
   int loop = 5;
   if ((CCMD = WEB_query(req,"CCMD"))==0)
        return -1;

	switch (CCMD[0])
	{
	case '3':
		file = WEB_query(req, "files");
		if( !file )
			return CFG_ERANGE;
		
		file = WEB_upload_file(req, "files", &len);

		//rc=CFG_put_file(0, file, len) ;
        rc=http_put_file(0, req->content, file, len);
		if (rc)
			return CGI_RC_FILE_INVALID;
		
		mon_snd_cmd(MON_CMD_REBOOT);
		return CGI_RC_FACTORY_DEFAULT;
			
	case '1':
		//diag_printf("doing Restore Factory Default\n");
		CFG_reset_default();
		mon_snd_cmd(MON_CMD_REBOOT);
		return CGI_RC_FACTORY_DEFAULT;
		
	case '0':
		//diag_printf("doing Restart System\n");
		/*add by seen*/
		//delay for getting more time jump to count.html
		cyg_thread_delay(10);
		/*end add*/
		mon_snd_cmd(MON_CMD_REBOOT);
		return CGI_RC_REBOOT;
			
	case '4':
	{
		int  ping_len=0;
		ping = WEB_query(req,"PING");
		diag_printf("ping %s\n",ping);
		memset(PING_Result,0,sizeof(PING_Result));
		if ((ping!=NULL)&&((dst = nstr2ip(ping)) != 0))
		{
			for(i=1; i<=loop; i++)
			{
				if((rtt = net_ping_test(dst, i, 300)) < 0)
					{
					ping_len=strlen(PING_Result);
					sprintf(&PING_Result[ping_len]," %d: timeout<BR>", i);
					}
				else if (strlen(SavePingResult) > 0)
					{
					ping_len=strlen(PING_Result);
					sprintf(&PING_Result[ping_len], "%d: %s<BR>",  i, SavePingResult);
					}
		
				sprintf(SavePingResult,"");
			}

			return CGI_RC_PING_OK;
		} else {
			sprintf(PING_Result,"PING %s Failed<BR>",ping);
			return CGI_RC_PING_TIMEOUT;
		}
	}
		
	case '5':
		netif_clear_cnt(WAN_NAME);
		netif_clear_cnt(LAN_NAME);
		return 0;
		
	default:
		break;
	}
	
	return 0;
}

int CGI_do_sys_chk_pass(http_req *req) {
	char *CPW;
	char cpw[256];
   	if ((CPW = WEB_query(req,"CPW"))==0)
        return 0; // no password update
	// if same , ok
	CFG_get(CFG_SYS_ADMPASS, cpw);
	if (!strcmp(CPW,cpw)) return 0;

    return -1;
}

// 9
#if		MODULE_SYSLOG
int CGI_do_sys_log(http_req *req)
{
	clear_system_log();
	return 0;
}
int CGI_do_secure_log(http_req *req)
{
	clear_seurity_log();
	return 0;
}
int CGI_do_sys_log_mail(http_req *req)
{
	event_send_mail();
	return CGI_RC_SNDMAIL;
}
#endif
// 17
#if		MODULE_DHCPS
int CGI_do_lan_dhcp_clients(http_req *req) 
{ 
	char dhcpc_lname[8], *dhcpc_lvar;
	int i = 1;
	
	do 
	{
		sprintf(dhcpc_lname, "list%d", i);
		dhcpc_lvar = WEB_query(req, dhcpc_lname);
		
		DHCPD_leases_set(dhcpc_lvar);
	}
	while(i++ <256);
	
    return 0;                        
}
#endif

// 27
int CGI_do_rt_add(http_req *req) 
{ 
	int i=0, rc = 0;
	char *cmd,*entstr;
	char rtent[100];
	
	cmd = WEB_getvar(req,"cmd","");    
	entstr= WEB_getvar(req,"str","");    
       
    if (atoi(cmd) == 1) // delete
    {
		while (CFG_get(CFG_RT_ENTRY+i+1, rtent) != -1)
		{
			if(!strcmp(entstr, rtent))
			{
				CFG_del(CFG_RT_ENTRY+i+1);
				rc = RT_del_staticrt(entstr);
			}
			i++;
		}  
	}
	else // add
	{
		while (CFG_get(CFG_RT_ENTRY+i+1, rtent) != -1)
			i++;
		
		rc = RT_add_staticrt(entstr);
		if (rc != -1)
			CFG_set(CFG_RT_ENTRY+i+1, entstr);
	}                                           

	// Force to save configuration   
	if (rc == 0)
		rc = CGI_RC_CFG_OK;
                                                   
    return rc;           
}

int system2(char *str)
{
	struct iwreq iwr;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) str;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;
		
		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
	       }
	}

	if (found == 1)	
	{
#ifdef CONFIG_AP_SUPPORT		
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_SET, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_SET has error.\n");
		}
#endif
#ifdef CONFIG_STA_SUPPORT		
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_SET, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_SET has error.\n");
		}
#endif

	}	
	else
	{
		diag_printf("Can't find ra0.\n");
		return -1;
	}

	return 0;
#else
	diag_printf("Wireless IF does not init.\n");
        return -1;
#endif
}

int CGI_do_wireless_simple_config_device(http_req *req) 
{
	int i, ret, id, id2, rc = 0;
	int WscPinCode, WscMode, WscConfMode, WscConfStatus;
	char cmdi[8], cmdi2[8];
	char *cmdv, *val, *cmdv2, *val2;
	char	wlanbuf[128];
	char WscPinCodeTemp[255]; 
	char WscModeTemp[10];
	char WscConfModeTemp[10];
	char WscConfStatusTemp[10];

	WscPinCodeTemp[0]='\0';
	WscModeTemp[0]='\0';
	WscConfModeTemp[0] = '\0';
	WscConfStatusTemp[0] = '\0';
	
	CFG_get_str(CFG_WLN_WscPinCode, WscPinCodeTemp);
	CFG_get_str(CFG_WLN_WscModeOption, WscModeTemp);
	CFG_get_str(CFG_WLN_WscConfMode, WscConfModeTemp);
	CFG_get_str(CFG_WLN_WscConfStatus, WscConfStatusTemp);
	
	WscPinCode = atoi(&WscPinCodeTemp[0]);
	WscMode = atoi(&WscModeTemp[0]);
	WscConfMode = atoi(&WscConfModeTemp[0]);
	WscConfStatus = atoi(&WscConfStatusTemp[0]);

	for (i = 0; i < 10; i++)
	{
		sprintf(cmdi2,"SET%d",i);
		cmdv2 = WEB_query(req,cmdi2);
		if (cmdv2 == 0)
			continue;
		
		val2 = strchr(cmdv2,'=');
		
		if ((unsigned int)val2 <= (unsigned int)cmdv2)
		{
			rc = CGI_RC_CFG_ERR;
			continue;
		}
		
		val2++;
		id2 = atoi(cmdv2);

		if (id2 == 0x4720100) //if update WscPinCode
			WscPinCode = atoi(val2);
		else if(id2 == 0x4700100) // if update WscModeOption
			WscMode = atoi(val2);
	}

	CFG_set(CFG_WLN_WscPinCode, &WscPinCode);
	CFG_set(CFG_WLN_WscModeOption, &WscMode);

	diag_printf("WscPinCode=%d\n", WscPinCode);
	diag_printf("WscMode=%d\n", WscMode);
	diag_printf("WscConfMode=%d\n", WscConfMode);
	diag_printf("WscConfStatus=%d\n", WscConfStatus);

	memset(wlanbuf, 0, 128);
	sprintf(wlanbuf, "WscGetConf=0");
	ret = system2(wlanbuf);

	memset(wlanbuf, 0, 128);
	sprintf(wlanbuf, "WscConfMode=%d", WscConfMode);
	ret = system2(wlanbuf);

	/* snowpin recommands that below is unnecessary. */
	memset(wlanbuf, 0, 128);
	sprintf(wlanbuf, "WscConfStatus=%d", WscConfStatus);
	ret = system2(wlanbuf);
	
	memset(wlanbuf, 0, 128);
	sprintf(wlanbuf, "WscMode=%d", WscMode);
	ret = system2(wlanbuf);

	if(WscMode == 1)
	{
		memset(wlanbuf, 0, 128);
		sprintf(wlanbuf, "WscPinCode=%d", WscPinCode);
		ret = system2(wlanbuf);	
	}

	memset(wlanbuf, 0, 128);
	sprintf(wlanbuf, "WscGetConf=1");
	ret = system2(wlanbuf);
	
	rc = CGI_RC_CFG_OK;

	return rc;
}

int CGI_do_wireless_security(http_req *req) 
{
	int i, id, id2, rc = 0;
	int ssid_index_num = 0;
	char cmdi[8], cmdi2[8];
	char SSIDIndexTemp[255]; 
	char *cmdv, *val, *cmdv2, *val2;

	SSIDIndexTemp[0]='\0';
	
	CFG_get_str(CFG_WLN_SSIDIndex, SSIDIndexTemp);
	
	ssid_index_num = atoi(&SSIDIndexTemp[0]);

	for (i = 0; i < 50; i++)
	{
		sprintf(cmdi2,"SET%d",i);

		cmdv2 = WEB_query(req,cmdi2);

		if (cmdv2 == 0)
			continue;
		
		val2 = strchr(cmdv2,'=');
		
		if ((unsigned int)val2 <= (unsigned int)cmdv2)
		{
			rc = CGI_RC_CFG_ERR;
			continue;
		}
		
		val2++;
		id2 = atoi(cmdv2);

		if (id2 == 0x4E90100) // search for SSIDIndex
		{
			ssid_index_num = atoi(val2);
			break;
		}
	}
	
	for (i = 0; i < 50; i++)
	{
		sprintf(cmdi,"SET%d",i);
		
		cmdv=WEB_query(req,cmdi);
		
		if (cmdv == 0)
			break;
		
		val = strchr(cmdv,'=');
		
		if (( (unsigned int)val <= (unsigned int)cmdv)||val == NULL)
		{
			rc=CGI_RC_CFG_ERR;
			break;
		}
		
		*val = 0;
		val++;
		id = atoi(cmdv);
		
		if (id != 0)
		{
			if((CFG_ID_TYPE(id) == CFG_TYPE_STR) && (id != CFG_POE_USER) && (id != CFG_POE_PASS))
			{
				/* we don't want to see '\n' and '\r'*/
				char *c = 0;
				if((c = strpbrk(val, "\n\r")))
					*c = '\0';
			}

			char * var = CFG_id2str(id);
   			int len = strlen(var);
			int lastByte;

			memmove(&lastByte, var+len-1, 1);

    			if (len == 0)
        			break;
	
			if (!isdigit(var[len-1]) ) 
			{
				/* Only when SSID index == 0, WscNewKey, WscAuthType,WscEncrypType, and WscConfigured can be modified */
				if(!((ssid_index_num != 0) && (id == 0x4920200 || id == 0x4900100 || id == 0x4910100 || id == 0x4710100)))
					rc = CFG_set_str(id,val);
			}
			else 
			{
				/* AccessControlList0, AccessControlList1, AccessControlList2, AccessControlList3, AccessPolicy0, AccessPolicy1,
				    AccessPolicy2, and AccessPolicy3 are the special cases since the index is counted from 0 not from 1 */			  
				if(id == 0x4A60200 || id == 0x4A70200 || id == 0x4A80200 || id == 0x4A90200 ||
					id == 0x46A0100 || id == 0x46B0100 || id == 0x46C0100 || id == 0x46D0100)
				{
					if(atoi(&lastByte) == ssid_index_num)
						rc = CFG_set_str(id,val);
				}
				else if(atoi(&lastByte) == (ssid_index_num + 1))
					rc = CFG_set_str(id,val);
			}
			
			if (rc >= 0) 
				rc = CGI_RC_CFG_OK;		
		}
	}

	return rc; 
}

void CGI_get_cfg(http_req *req, int tag) 
{ 
	char val[255];  

	val[0]='\0';
	CFG_get_str(tag, val);
	
	if (CFG_ID_TYPE(tag) == CFG_TYPE_STR)
	{	
		char seperators[] = "\"";
		char *start = &val[0];
		char * end = NULL;
		char temp[255];
		char temp2[255];
		int lencnt = 0;

		memset(temp, 0x0, 255);
#if 1
		int i = 0;

		while (val[i] != 0)
		{
			if (val[i] == '\"')
			{
				strcpy(temp2, temp);
				sprintf(temp, "%s%s", temp2, "&quot;");
			}
			else if (val[i] == '\\')
			{
				strcpy(temp2, temp);
				sprintf(temp, "%s%s", temp2, "\\\\");
			}			
			else
			{
				strcpy(temp2, temp);
				sprintf(temp, "%s%c", temp2, val[i]);
			}
			i++;
		}

#else
		while ((end = strpbrk(start , seperators)) != NULL)
		{ 
			if ((end != NULL) && (*end == '\"'))
			{
				diag_printf("%s  %d\n", end, end-start);
				if (end != start)
				{
					strncpy(&temp[lencnt], start, end-start);
					lencnt += (end - start);
				}
				strcat(&temp[lencnt], "&quot;");
				lencnt += strlen("&quot;");
			} 
			start = end + 1;
		}
		
		if ((start - &val[0]) < strlen(val))
			strncpy(&temp[lencnt], start, strlen(start)+1);	
#endif
		
		WEB_printf( req, "%s", temp);
	}
	else	
		WEB_printf( req, "%s", val);
}

#if		MODULE_WANIF
int get_wan_state_value(http_req *req, struct ip_set *ip_point, int term)
{
  struct ip_set *wan_ipset = ip_point;
  int type, dns;
  int time_diff; 
  char strbuf[50];
  char *buffer = 0;

  CFG_get(CFG_WAN_IP_MODE, &type);
  switch(term)
	{	
	case 1:
		switch(wan_ipset->up)
		{
		case DISCONNECTED:
			buffer = "0";
			break;
		case CONNECTED:
			buffer = "1";
			break;
		case CONNECTING:
			buffer = "2";
			break;
		}
		break;
		
	case 2:
		buffer = NSTR(wan_ipset->ip);
		break;
		
	case 3:
		buffer = NSTR(wan_ipset->netmask);
		break
		;
	case 4:
		buffer = NSTR(wan_ipset->gw_ip);
		break;
		
	case 5:
		dns = SYS_dns_1;
		buffer = NSTR(dns);
		break;
		
	case 6:
		dns = SYS_dns_2;
		buffer = NSTR(dns);
		break;
		
	case 7:
		buffer = ESTR(SYS_wan_mac);
		break;
		
	case 8:		                		
		buffer = wan_ipset->domain;
		break;
		
	case 9:
		if (wan_ipset->conn_time)
			time_diff = time(0) - wan_ipset->conn_time;
		else
			time_diff = 0;
			
		sprintf(strbuf, "%d", time_diff);
		buffer=strbuf;
		break;
		
	case 10:
		/* only DHCP mode */
		if (type == 2)
			time_diff = DHCPC_remaining_time(wan_ipset->ifname);
		else
			time_diff = 0;
		
		sprintf(strbuf, "%d", time_diff);
		buffer=strbuf;
		break;
	}  

	if (buffer != NULL)
	  WEB_printf( req, "%s", buffer);
  return 0;
}

void CGI_get_wan_state(http_req *req, int term)
{
  int ipmode;
  CFG_get(CFG_WAN_IP_MODE, &ipmode);
  
  if (opmode == 3)
  {
  	if (term == 1)
  		WEB_printf( req, "0");
  	else
  		WEB_printf( req, "");
  	return;
  }

  #ifdef CONFIG_PPTP_PPPOE
  extern struct ip_set ppp_ip_set[CONFIG_PPP_NUM_SESSIONS];
  int pptp_wanif;
  if(ipmode == PPTPMODE){
    CFG_get(CFG_PTP_WANIF, &pptp_wanif);
    if(pptp_wanif == 2)
	  ipmode = 9;//pppoe mode for pptp vpn
  }
  #endif

  #ifdef CONFIG_L2TP_OVER_PPPOE
  extern struct ip_set l2tp_wan_ip_set[CONFIG_PPP_NUM_SESSIONS];
  int l2tp_wanif;
  if(ipmode == L2TPMODE){
    CFG_get(CFG_L2T_WANIF, &l2tp_wanif);
    if(l2tp_wanif == 2)
	  ipmode = 10;//pppoe mode for l2tp
  }
  #endif

  switch(ipmode){
  	#ifdef CONFIG_PPTP_PPPOE
  	case 9:
	  get_wan_state_value(req, &ppp_ip_set[0], term);
	  break;
    #endif

    #ifdef CONFIG_L2TP_OVER_PPPOE
	case 10:
	  get_wan_state_value(req, &l2tp_wan_ip_set[0], term);
	  break;
    #endif

	default:
      get_wan_state_value(req, &primary_wan_ip_set[0], term);
	  break;
  }
}
#endif	//MODULE_WANIF

void CGI_get_time(http_req *req)
{
	WEB_printf( req, "%d", GMTtime(0));
}

void CGI_get_uptime(http_req *req)
{
	WEB_printf( req, "%d", time(0));
}

void CGI_get_ntpinfo(http_req *req)
{
	int te,now;
	struct tm TM;
	
	te = get_ntp_type();
	now = ntp_getlocaltime(0);
	gmtime_r(&now,&TM);
	WEB_printf( req, "\"%d\",\"0\",\"%d/%d/%d\",\"%d:%d:%d\",\"\",\"\",\"\",\"\"",te,
				TM.tm_mon+1,TM.tm_mday,TM.tm_year+1900,TM.tm_hour,TM.tm_min,TM.tm_sec);
}


static void _mask(struct sockaddr *sa, char *buf, int _len)
{
    unsigned char *cp = ((char *)sa) + 4;
    int len = sa->sa_len - 4;
    int tot = 0;

    while (len-- > 0) {
        if (tot) *buf++ = '.';
        buf += diag_sprintf(buf, "%d", *cp++);
        tot++;
    }

    while (tot < 4) {
        if (tot) *buf++ = '.';
        buf += diag_sprintf(buf, "%d", 0);
        tot++;
    }
}

// routing table entry, format: d.d.d.d,n.n.n.n,g.g.g.g,metric,if
// routing table entry number
static int rte_num;
static int CGI_routing_entry(struct radix_node *rn, void *vw)
{
    struct rtentry *rt = (struct rtentry *)rn;
    struct sockaddr *dst, *gate, *netmask, *genmask;
    char addr[32]={0}, addr1[32]={0}, addr2[32]={0};
    http_req *req = (http_req *)vw;

    dst = rt_key(rt);
    gate = rt->rt_gateway;
    netmask = rt_mask(rt);
    genmask = rt->rt_genmask;
    if ((rt->rt_flags & (RTF_UP | RTF_LLINFO)) == RTF_UP) 
	{
        _inet_ntop(dst, addr, sizeof(addr));

        if (netmask != NULL) {
            _mask(netmask, addr2, sizeof(addr2));
        } else {
        	if(rt->rt_flags & RTF_HOST) 
        		sprintf(addr2, "255.255.255.255");
        	else
            	sprintf(addr2, " ");
        }
       
        if (gate != NULL && gate->sa_family == AF_INET) {
            _inet_ntop(gate, addr1, sizeof(addr1));
        } else if(gate != NULL && gate->sa_family == AF_LINK) {
        	_inet_ntop((struct sockaddr *)rt_key(rt), addr1, sizeof(addr1));
        } else {
            sprintf(addr1,"unknown");
        }
		if (rte_num++!=0)
			WEB_printf(req,",");
        WEB_printf(req, "\n'%s,%s,%s,%d,", addr,addr2,addr1,rt->rt_rmx.rmx_hopcount);
        if_indextoname(rt->rt_ifp->if_index, addr);
        WEB_printf(req, "%s'", addr);
    }
    return 0;
}

void CGI_show_routing_table(http_req *req)
{
	struct radix_node_head *rnh;
	int i;

	rte_num=0;
	for (i = 1; i <= AF_MAX; i++) {
        if ((rnh = rt_tables[i]) != NULL) {
           rnh->rnh_walktree(rnh, CGI_routing_entry, req);
        }
    }
}

#if		MODULE_DHCPS
static void dhcpd_entry(char *buf, int id, void *arg1)
{
	http_req *req = (http_req *)arg1;
	
	//if (id>1)
		//WEB_printf(req, ",");
		
	WEB_printf(req, "%s", buf);
}

inline void CGI_show_dhcpd_clist(http_req *req)
{
	DHCPD_dumplease(dhcpd_entry, 0x3, req);
}

inline void CGI_show_dhcpd_dyn_clist(http_req *req)
{
	DHCPD_dumplease(dhcpd_entry, 0x1, req);
}

void CGI_show_dhcpd_leases_num(http_req *req)
{
	int num=0;
	num = DHCPD_dumplease(NULL, 0x3);
	WEB_printf(req, "%d", num);
}
#endif	//MODULE_DHCPS

#if		MODULE_UPNP
void CGI_show_upnp_pmap(http_req *req)
{
	int i=0;
	int maxNum=portmap_num() ;
	char entry[100];
	
	for( i=0; i<maxNum ; i++) {	
	   	getUpnpPmapEntry(i,entry) ;	
		if (i)
			WEB_printf(req, ",");
	   WEB_printf(req, "\n'%s'", entry);
	}
}
#endif

#if		MODULE_SYSLOG
void CGI_print_log(http_req *req, int type)
{ 
    char time_info[32];
    UINT32	ev_dateTime;
	int	diff = ntp_time() - time(0);
	
    EventLogEntry *ev;
	char *p;
	//int i, index, count;
	
	//index = 1;
	//count = 65535;

	memset(time_info,0,sizeof(time_info));
	syslog_mutex_lock();
	//p = FindEvent(type);
	//for (i=1; (p != 0) && (i < index); i++, p = NextEvent(p, type));
	//for (i=0; (p != 0) && (i < count); i++, p = NextEvent(p, type))
	for (p=FindEvent(type); p != 0; p=NextEvent(p, type))
	{
		ev = (EventLogEntry *)p;
		//if ((ev->class & LOG_CLASS_MASK) == LOG_USER)
		//{
	    	ev_dateTime = gmt_translate2localtime(diff + ev->unix_dateTime);
			ctime_r(&ev_dateTime, time_info);
			time_info[strlen(time_info)-1] = 0;  // Strip \n
			WEB_printf (req, "[%s]:%s %s \n",
						time_info, 
						EventModule(ev), 
						ev->text);
		//}
	}
	syslog_mutex_unlock();
}

void CGI_print_log_list(http_req *req, int type)
{ 
    char time_info[32] = {0};
	UINT32	ev_dateTime;
	unsigned long curr_time = time(0);
	int	diff = ntp_time() - curr_time;
	
    EventLogEntry *ev;
	char *p;
	//int i, index, count,tt;
	int i;
	int tt;
	
	//index = 1;
	//count = 65535;
	
	tt = Is_ntp_ever_sync();
	
	syslog_mutex_lock();
	//p = FindEvent(type);
	//for (i=1; (p != 0) && (i < index); i++, p = NextEvent(p, type));
	for (i=0, p=FindEvent(type); p != 0; i++, p=NextEvent(p, type))
	{
		ev = (EventLogEntry *)p;
		//p = NextEvent(p, type);
		//if ((ev->class & LOG_CLASS_MASK) == LOG_USER)
		//{
			ev_dateTime = gmt_translate2localtime(diff + ev->unix_dateTime);
			ctime_r(&ev_dateTime, time_info);
			time_info[strlen(time_info)-1] = 0;  // Strip \n
			WEB_printf (req, "%s\n'%d','%d','%d','%d','%s','%s %s'",
						i ? "," : "",
						i+1,
						tt, 
						(curr_time - ev->unix_dateTime), 
						ev_dateTime, 
						time_info, 
						EventModule(ev), 
						ev->text);
		//}
	}
	syslog_mutex_unlock();
}
#endif

char * CGI_get_client_mac(http_req *req)
{
	static char macstr[20];
	struct sockaddr_in addr;
	socklen_t len;
	len = sizeof(addr);
	char mac[6];
	
	if(getpeername(req->conn_fd, (struct sockaddr*)&addr,  &len) < 0)
		return 0;
	
	netarp_get_one(addr.sin_addr.s_addr, mac);
	sprintf( macstr, "%s", ether_ntoa(mac));
	return macstr;
}

int CGI_upgrade(http_req *req)
{  
	/*  
	char *file;
	int len,rc;
	
	file = WEB_upload_file(req, "files", &len);
	
   	//rc = CFG_put_file(1, file, len) ;
    rc = http_put_file(1, req->content, file, len);
	
	upgrade_mem = req->content;
	req->content = 0;
	CGI_upgrade_free();
	if (rc)
		return CGI_RC_FILE_INVALID;
	
#ifdef	CONFIG_ZWEB
	zweb_location = 0;
#endif*/
	return CGI_RC_UPGRADE;
}

int CGI_upgrade_upload(http_req *req)
{
	int len;
	
	upgrade_file = WEB_upload_file(req, "files", &len);
	if (!upgrade_file) 
		return -1;
	
	if (upgrade_mem) 
		return -1; // if previous request are not finished, skip
	
	upgrade_time_stamp=time(0);
	upgrade_file_len = len;
	upgrade_mem = req->content;
	req->content = 0;
	
	timeout(&CGI_upgrade_free, upgrade_time_stamp, 300);
	return 0;
}

int CGI_upgrade_save(http_req *req)
{ 
	int rc;
	
	if (!upgrade_mem) 
		return CGI_RC_FILE_INVALID; // avoid incorrect cgi call
	
	untimeout(&CGI_upgrade_free,upgrade_time_stamp);
	//rc = CFG_put_file(1, upgrade_file, upgrade_file_len);
    rc = http_put_file(1, upgrade_mem, upgrade_file, upgrade_file_len);
	
	CGI_upgrade_free();
	if (rc)
		return CGI_RC_FILE_INVALID;
	
#ifdef	CONFIG_ZWEB
	zweb_location = 0;
#endif
	return CGI_RC_UPGRADE;
}

void CGI_upgrade_free(void)
{
	if (upgrade_mem)
	{
		diag_printf("CGI_upgrade_free() be called!!!\n");
		
        CGI_free_content(upgrade_mem);
        upgrade_mem = 0;
	}
}

#ifdef CONFIG_NTP
int CGI_do_ntp_config(http_req *req)
{
	char *cmd;
	int  c_time;
	
	if ((cmd=WEB_query(req,"TIMES"))==0)
		return 0;
	
	c_time = atol(cmd);
	if(c_time)
		non_ntp_update(c_time);
	
	return CGI_RC_CFG_OK;
}
#endif



char *cgiFunc(webpage_entry* fileptr, http_req *req)
{
	int result = 0;
	char * cmd;

	cmd=WEB_query(req,"CMD");
	if (cmd) {
		result = CGI_do_cmd(req);
		if ((result == CGI_RC_REBOOT) || (result == CGI_RC_UPGRADE))
			return "count.html";
		else if (result > 0)
			return 0;// WEB_query(req,"GO");
	}

	return 0;
}

int	cgiFileMiss(http_req *req)
{
	if (!strncmp(req->file, CMD_PAGE, 3))
	{
		extern time_t time_pages_created;
		
		add_headers( req, HTTP_REQUEST_OK, "Ok", (char*) 0, "text/html; charset=", -1, time_pages_created, 1);
		send_response(req);
		WEB_printf(req, "%s", RESTART_MSG_PAGE);
		
		CGI_do_cmd(req);
		return 0;
	}
	
	return -1;
}


typedef struct nat_sessinfo_s {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint16_t prot;
	uint8_t s_tcpstate;
	uint8_t d_tcpstate;
	uint32_t age;
} nat_sessinfo_t;

typedef struct nat_brif_s {
	uint32_t sip;
	uint16_t tcpnum;
	uint16_t udpnum;
} nat_brif_t;

#define MAX_NATBRIF_NUM		512
int CGI_get_nat_session_brief(http_req *req)
{
	nat_sessinfo_t *pnatinfo;
	int buflen, sess_num;
	extern int nat_table_max;
	int sidx, bridx, brifnum;
	nat_brif_t *pbrif;

	buflen = sizeof(nat_sessinfo_t)*nat_table_max +
		 MAX_NATBRIF_NUM*sizeof(nat_brif_t);
	if ((pnatinfo=malloc(buflen)) == NULL) {
		return -1;
	}
	memset(pnatinfo,0,buflen);
	/*  Get NAT session info  */
	if ((sess_num = ipnat_session_list(pnatinfo, buflen)) <= 0)
		goto brif_exit;
	sess_num /= sizeof(nat_sessinfo_t);
	pbrif = (nat_brif_t *) &pnatinfo[nat_table_max];

	/*  Prepare NAT session brief */
	for (sidx=0, brifnum=0; sidx<sess_num; sidx++) {
		for (bridx=0; bridx<brifnum; bridx++) {
			if (pnatinfo[sidx].sip == pbrif[bridx].sip) {
				if (pnatinfo[sidx].prot == 6) {
					/*  TCP  */
					pbrif[bridx].tcpnum ++;
				} else if (pnatinfo[sidx].prot == 17) {
					/*  UDP  */
					pbrif[bridx].udpnum ++;
				}
				break;
			}
		}
		if (bridx == brifnum) {
			pbrif[bridx].sip = pnatinfo[sidx].sip;
			pbrif[bridx].tcpnum = pbrif[bridx].udpnum = 0;
			brifnum ++;
			if (pnatinfo[sidx].prot == 6)
				pbrif[bridx].tcpnum = 1;
			else if (pnatinfo[sidx].prot == 17)
				pbrif[bridx].udpnum = 1;
		}
	}

	/*  Output brief  */
	for (bridx=0; bridx<brifnum; bridx++) {
		if (bridx>0)
			WEB_printf(req, ",");
		WEB_printf(req, "\n'%s;%d;%d'", NSTR(pbrif[bridx].sip), 
				pbrif[bridx].tcpnum, pbrif[bridx].udpnum);
	}

brif_exit:
	free(pnatinfo);
	return 0;
}

CGI_get_nat_session_list(http_req *req)
{
	nat_sessinfo_t *pnatinfo;
	int buflen, sess_num;
	extern int nat_table_max;
	uint32_t client_ip;
	char *pval, *protnamelist[]={"TCP","UDP"}, *protname=NULL;
	int i, cnt;
	struct in_addr claddr;

	if ((pval = WEB_query(req, "client")) == NULL)
		return -1;
	if (inet_aton(pval, &claddr) == 0)
		return -1;
	client_ip = ntohl(claddr.s_addr);

	buflen = sizeof(nat_sessinfo_t)*nat_table_max;
	if ((pnatinfo=malloc(buflen)) == NULL) {
		return -1;
	}
	/*  Get NAT session info  */
	if ((sess_num = ipnat_session_list(pnatinfo, buflen)) <= 0)
		goto sess_exit;
	sess_num /= sizeof(nat_sessinfo_t);

	for (i=0, cnt=0; i<sess_num; i++) {
		if (pnatinfo[i].sip == client_ip) {
			if (pnatinfo[i].prot==6)
				protname = protnamelist[0];
			else if (pnatinfo[i].prot==17)
				protname = protnamelist[1];
			else
				continue;
			if (cnt >0)
				WEB_printf(req, ",");
			WEB_printf(req, "\n'%s;%s;%d;%s;%d;%d'",
					protname, pval, pnatinfo[i].sport, 
					NSTR(pnatinfo[i].dip),
					pnatinfo[i].dport, pnatinfo[i].age);
			cnt++;
		}
	}
	
sess_exit:
	free(pnatinfo);
	return 0;
}

extern int Oray_DDNS_Webshow(int x, unsigned char *buf, int *status);
void CGI_get_ddns_oray_list(http_req *req, char *name)
{
	int x = 0;
	int status = 0;
	unsigned char buf[50], buf_temp[2];
	char val[200];

	//char *name = "Oray_DDNS_LIST";

	do
	{
		Oray_DDNS_Webshow(x, buf, &status);
		if (status > 0)
		{
			memset(val,0,sizeof(val));
			sprintf(buf_temp, "%d", status);
			strcat(val, buf_temp);
			strcat(val, ",");
			strcat(val, buf);
			WEB_printf(req, "<input name='%s%d' value='%s' type='hidden'>", name, x, val);
		}
		x++;
	}while(status > 0);
}

#ifdef CONFIG_DUALWAN
void CGI_get_dwan(http_req *req)
{
	char *buf;
	
	buf=inet_ntoa(*(struct in_addr *)&primary_wan_ip_set[1].ip);
	WEB_printf( req, "%s", buf);
}
#endif

int OidQueryInformation(unsigned short OidQueryCode, char *DeviceName, void *ptr, unsigned long PtrLength)
{
    struct iwreq wrq;

    //strcpy(wrq.ifr_ifrn.ifrn_name, DeviceName);
    wrq.u.data.length = PtrLength;
    wrq.u.data.pointer = (caddr_t) ptr;
    wrq.u.data.flags = OidQueryCode;

	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;
		
		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
	       }
	}

	if (found == 1)	
#ifdef CONFIG_AP_SUPPORT		
		return(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&wrq));
#endif
#ifdef CONFIG_STA_SUPPORT		
		return(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&wrq));
#endif
	else
		return -1;
#else
	diag_printf("Wireless IF does not init.\n");
	return -1;
#endif   
}

int  parse_config_file(void)
{
	char	tmp_buffer[260];
	char val[255];     
	val[0] = '\0';
	char	*tok = NULL;
	int		i, new_driver, s, idx, wake_up_dot1x = 0;
	int		bssid_num;
	int		start_uam = 0;
	unsigned char version_number[8] = {0};
	int		wake_up_wapid = 0;

	new_driver = 0;

	if ( OidQueryInformation(RT_OID_QUERY_DRIVER_VERSION, "ra0", &version_number, sizeof(unsigned char)*8) < 0 )
	{
		if ( OidQueryInformation(RT_OID_VERSION_INFO,"ra0", &version_number, sizeof(unsigned char)*8) < 0 )
		{
			new_driver = 0;
		}
	}

	version_number[7] = '\0';

	if (version_number[0] >= '1')
	{
		if (version_number[2] == '5')
		{
			new_driver = 1;
			CFG_set(CFG_WLN_NewVersion, "1");
		}
		else if (version_number[2] >= '6')
		{
			new_driver = 2;
			CFG_set(CFG_WLN_NewVersion, "2");
		}
		else
		{
			new_driver = 0;
			CFG_set(CFG_WLN_NewVersion, "0");
		}
	}
	else
	{
		new_driver = 0;
		CFG_set(CFG_WLN_NewVersion, "0");
	}

	new_driver = 2;
	CFG_set(CFG_WLN_NewVersion, "2");

	g_new_version = new_driver;

	CFG_get_str(CFG_WLN_BssidNum, val);
	
	if (strcmp(val, "") == 0)
	{
		idx = 1;
		bssid_num = 1;
	}
	else
	{
		idx = atoi(val);
		bssid_num = atoi(val);
		if (idx >4)idx =4; //eCos just support 4 mbss
		if(bssid_num >4)bssid_num =4;
	}

	/* SSID */
	if (new_driver == 0)
	{
   		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_SSID, val);

		if (strcmp(val, "") == 0)
			strcpy(tmp_buffer, "Ralink11nInitAP");
		else
			strncpy(tmp_buffer, val, strlen(val));
   		if (strlen(tmp_buffer) < sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) -1] = '\0';
		else
			tmp_buffer[sizeof(tmp_buffer) -1]='\0';
		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			mBSSID[i].enable = 1;
			sprintf(mBSSID[i].SSID, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < bssid_num; i++)
		{
			switch(i)
			{
				memset(val, 0 ,255);
				
				case 0:
					CFG_get_str(CFG_WLN_SSID1, val);
					break;
				case 1:
					CFG_get_str(CFG_WLN_SSID2, val);
					break;
				case 2:
					CFG_get_str(CFG_WLN_SSID3, val);
					break;
				case 3:
					CFG_get_str(CFG_WLN_SSID4, val);
					break;
				default:
					break;
			}
			mBSSID[i].enable = 1;
			if (strcmp(val, "") == 0)
				sprintf(mBSSID[i].SSID, "%s%d", "Ralink-eCosAP", i+1);
			else
				sprintf(mBSSID[i].SSID, "%s", val);
		}
	}

	/* HideSSID */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_HideSSID, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
	{
		strncpy(tmp_buffer, val, strlen(val));
		if(strlen(val) > sizeof(tmp_buffer))
			tmp_buffer[sizeof(tmp_buffer) -1] = '\0';
		else
			tmp_buffer[strlen(val)] = '\0';
	}	
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer)] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
	
	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
		mBSSID[i].HideSSID = atoi(tok);
	}

	/* TxRate */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_TxRate, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
		mBSSID[i].TxRate = atoi(tok);
	}

	/* SecurityMode */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_SecurityMode, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
		{
			mBSSID[i].SecurityMode = atoi(tok);
			if (mBSSID[i].SecurityMode == 4)
				start_uam = 1;
		}
	}

	/* AuthMode */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_AuthMode, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "OPEN");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
		{
			sprintf(mBSSID[i].AuthMode, "%s", tok);
			if ((strcmp(tok, "WPA") == 0) || (strcmp(tok, "WPA2") == 0) || (strcmp(tok, "WPA1WPA2") == 0))
				wake_up_dot1x = 1;
				else if ((strcmp(tok, "WAIPSK") == 0) || (strcmp(tok, "WAICERT") == 0))
					wake_up_wapid = 1;
		}
	}

	/* EncrypType */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_EncrypType, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "NONE");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			sprintf(mBSSID[i].EncrypType, "%s", tok);
	}

	/* WPAPSK */
	if (new_driver == 0)
	{
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_WPAPSK, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].WPAPSK, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			
			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mBSSID[i].WPAPSK, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,sizeof(val));
					
					case 0:
						CFG_get_str(CFG_WLN_WPAPSK1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_WPAPSK2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_WPAPSK3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_WPAPSK4, val);
						break;
					default:
						break;
				}
				if (strcmp(val, "") == 0)
					strcpy(mBSSID[i].WPAPSK, "");
				else
					sprintf(mBSSID[i].WPAPSK, "%s", val);
			}
		}
	}

	/* DefaultKeyID */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_DefaultKeyID, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "1");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].DefaultKeyID = atoi(tok);
	}

	/* Key1Type */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_Key1Type, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].Key1Type = atoi(tok);
	}

	/* Key1Str */
	if (new_driver == 0)
	{
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_Key1Str, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].Key1Str, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			
			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mBSSID[i].Key1Str, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,255);
					
					case 0:
						CFG_get_str(CFG_WLN_Key1Str1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_Key1Str2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_Key1Str3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_Key1Str4, val);
						break;
					default:
						break;
				}
				if (strcmp(val, "") == 0)
					strcpy(mBSSID[i].Key1Str, "");
				else
					sprintf(mBSSID[i].Key1Str, "%s", val);
			}
		}
	}

	/* Key2Type */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_Key2Type, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].Key2Type = atoi(tok);
	}

	/* Key2Str */
	if (new_driver == 0)
	{
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_Key2Str, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].Key2Str, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			
			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mBSSID[i].Key2Str, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,255);
					
					case 0:
						CFG_get_str(CFG_WLN_Key2Str1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_Key2Str2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_Key2Str3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_Key2Str4, val);
						break;
					default:
						break;
				}

				if (strcmp(val, "") == 0)
					sprintf(mBSSID[i].Key2Str, "%s", "");
				else
					sprintf(mBSSID[i].Key2Str, "%s", val);
			}
		}
	}

	/* Key3Type */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_Key3Type, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].Key3Type = atoi(tok);
	}

	/* Key3Str */
	if (new_driver == 0)
	{
		bzero(tmp_buffer, sizeof(char)*260);
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_Key3Str, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].Key3Str, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			
			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mBSSID[i].Key3Str, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,255);
					
					case 0:
						CFG_get_str(CFG_WLN_Key3Str1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_Key3Str2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_Key3Str3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_Key3Str4, val);
						break;
					default:
						break;
				}

				if (strcmp(val, "") == 0)
					sprintf(mBSSID[i].Key3Str, "%s", "");
				else
					sprintf(mBSSID[i].Key3Str, "%s", val);
			}
		}
	}

	/* Key4Type */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_Key4Type, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].Key4Type = atoi(tok);
	}

	/* Key4Str */
	if (new_driver == 0)
	{
		bzero(tmp_buffer, sizeof(char)*260);
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_Key4Str, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].Key4Str, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			
			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mBSSID[i].Key4Str, "%s", tok);
		}
	}
	else
	{
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,255);
					
					case 0:
						CFG_get_str(CFG_WLN_Key4Str1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_Key4Str2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_Key4Str3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_Key4Str4, val);
						break;
					default:
						break;
				}

				if (strcmp(val, "") == 0)
					sprintf(mBSSID[i].Key4Str, "%s", "");
				else
					sprintf(mBSSID[i].Key4Str, "%s", val);
			}
		}
	}

	/* WapiPskType */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_WapiPskType, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].WapiKeyType = atoi(tok);
	}

	/* Wapi Psk key */
	for (i = 0; i < idx; i++)
	{
		if (i < bssid_num)
		{
			switch(i)
			{
				memset(val, 0 ,255);
				
				case 0:
					CFG_get_str(CFG_WLN_WapiPsk1, val);
					break;
				case 1:
					CFG_get_str(CFG_WLN_WapiPsk2, val);
					break;
				case 2:
					CFG_get_str(CFG_WLN_WapiPsk3, val);
					break;
				case 3:
					CFG_get_str(CFG_WLN_WapiPsk4, val);
					break;
				default:
					break;
			}
			if (strcmp(val, "") == 0)
				strcpy(mBSSID[i].WapiKey, "");
			else
				sprintf(mBSSID[i].WapiKey, "%s", val);
		}
	}

	/* IEEE8021X */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_IEEE8021X, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
		{
			mBSSID[i].IEEE8021X = atoi(tok);
			if (atoi(tok) == 1)
				wake_up_dot1x = 1;
		}
	}

	/* PreAuth */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_PreAuth, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].PreAuth = atoi(tok);
	}

	/* PMKCachePeriod */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_PMKCachePeriod, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "10");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].PMKCachePeriod = atoi(tok);
	}

	/* RekeyMethod */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_RekeyMethod, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "DISABLE");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			sprintf(mBSSID[i].RekeyMethod, "%s", tok);
	}

	/* RekeyInterval */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_RekeyInterval, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "3600");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		if (i < bssid_num)
			mBSSID[i].RekeyInterval = atoi(tok);
	}

	/* Vlan Name */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_VLANName, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "ralink-vlan0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		sprintf(mBSSID[i].VlanName, "%s", tok);
	}

	/* Vlan ID */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_VLANID, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		mBSSID[i].VlanId = atoi(tok);
	}

	/* Vlan Priority */
	bzero(tmp_buffer, sizeof(tmp_buffer));
	memset(val, 0 ,sizeof(val));
	CFG_get_str(CFG_WLN_VLANPriority, val);

	if (strcmp(val, "") == 0)
		strcpy(tmp_buffer, "0");
	else
		strncpy(tmp_buffer, val, strlen(val));
	
	if (strlen(tmp_buffer) < sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) -1] = '\0';
	else
		tmp_buffer[sizeof(tmp_buffer) -1]='\0';
	

	for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
	{
		mBSSID[i].VlanPriority = atoi(tok);
	}

	if (new_driver == 2)
	{
		/* Radius Server */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_RADIUS_Server, val);

		if (strcmp(val, "") == 0)
		{
			sprintf(mBSSID[0].radius_server, "%s", "");
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
			{
				if (i < bssid_num)
					sprintf(mBSSID[i].radius_server, "%s", tok);
			}
		}

		/* Radius Port */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_RADIUS_Port, val);

		if (strcmp(val, "") == 0)
		{
			mBSSID[0].radius_port = 1812;
		}
		else
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
			{
				if (i < bssid_num)
					mBSSID[i].radius_port = atoi(tok);
			}
		}

		/* Radius Secret */
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					memset(val, 0 ,255);
					
					case 0:
						CFG_get_str(CFG_WLN_RADIUS_Key1, val);
						break;
					case 1:
						CFG_get_str(CFG_WLN_RADIUS_Key2, val);
						break;
					case 2:
						CFG_get_str(CFG_WLN_RADIUS_Key3, val);
						break;
					case 3:
						CFG_get_str(CFG_WLN_RADIUS_Key4, val);
						break;
					default:
						break;
				}

				if (strcmp(val, "") == 0)
					sprintf(mBSSID[i].radius_secret, "%s", "");
				else
					sprintf(mBSSID[i].radius_secret, "%s", val);
			}
		}
#if 0 
		bzero(mFT, sizeof(ft_tbl_s)*4);
		/* FtSupport */
		bzero(tmp_buffer, sizeof(char)*260);
		wordlist = nvram_get("FtSupport");
		if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
			strcpy(tmp_buffer, "0");
		else
			strncpy(tmp_buffer, wordlist, strlen(wordlist));

		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			if (i < bssid_num)
			mFT[i].FtSupport = atoi(tok);
		}

		/* FtRic */
		bzero(tmp_buffer, sizeof(char)*260);
		wordlist = nvram_get("FtRic");
		if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
			strcpy(tmp_buffer, "0");
		else
			strncpy(tmp_buffer, wordlist, strlen(wordlist));

		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			if (i < bssid_num)
				mFT[i].FtRic = atoi(tok);
		}

		/* FtOtd */
		bzero(tmp_buffer, sizeof(char)*260);
		wordlist = nvram_get("FtOtd");
		if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
			strcpy(tmp_buffer, "0");
		else
			strncpy(tmp_buffer, wordlist, strlen(wordlist));
	
		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			if (i < bssid_num)
				mFT[i].FtOtd = atoi(tok);
		}

		/* FtMdId */
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					case 0:
						wordlist = nvram_get("FtMdId1");
						break;
					case 1:
						wordlist = nvram_get("FtMdId2");
						break;
					case 2:
						wordlist = nvram_get("FtMdId3");
						break;
					case 3:
						wordlist = nvram_get("FtMdId4");
						break;
					default:
						break;
				}
				if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
					strcpy(mFT[i].FtMdId, "");
				else
					sprintf(mFT[i].FtMdId, "%s", wordlist);
				fprintf(stderr, "FtMdId%d = %s\n", i, wordlist);
			}
		}

		/* FtR0khId */
		for (i = 0; i < idx; i++)
		{
			if (i < bssid_num)
			{
				switch(i)
				{
					case 0:
						wordlist = nvram_get("FtR0khId1");
						break;
					case 1:
						wordlist = nvram_get("FtR0khId2");
						break;
					case 2:
						wordlist = nvram_get("FtR0khId3");
						break;
					case 3:
						wordlist = nvram_get("FtR0khId4");
						break;
					default:
						break;
				}
				if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
					strcpy(mFT[i].FtR0khId, "");
				else
					sprintf(mFT[i].FtR0khId, "%s", wordlist);
			}
		}
	
		/* FtKeyLifeTime */
		bzero(tmp_buffer, sizeof(char)*260);
		wordlist = nvram_get("FtKeyLifeTime");
		if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
			strcpy(tmp_buffer, "3600");
		else
			strncpy(tmp_buffer, wordlist, strlen(wordlist));
	
		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			if (i < bssid_num)
				mFT[i].FtKeyLifeTime = atoi(tok);
		}
	
		/* FtReassociateDealine */
		bzero(tmp_buffer, sizeof(char)*260);
		wordlist = nvram_get("FtReassociateDealine");
		if ((wordlist == NULL) || (strcmp(wordlist, "") == 0))
			strcpy(tmp_buffer, "100");
		else
			strncpy(tmp_buffer, wordlist, strlen(wordlist));
	
		for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
		{
			if (i < bssid_num)
				mFT[i].FtReassociateDealine = atoi(tok);
		}
#endif
		bzero(mWDS, sizeof(wds_tbl_s)*4);

		/* WDS Peer Link MAC Address */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_WdsList, val);

		idx = 0;
		if (!(strcmp(val, "") == 0))
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
			{
				sprintf(mWDS[i].PeerMac, "%s", tok);
				mWDS[i].enable = 1;
				idx++;
			}
		}

		/* WDS Peer Link Phy Mode */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_WdsPhyMode, val);

		if (!(strcmp(val, "") == 0))
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mWDS[i].PhyMode, "%s", tok);
		}

		/* WDS Peer Link EncrypType */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_WdsEncrypType, val);

		if (!(strcmp(val, "") == 0))
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				sprintf(mWDS[i].EncrypType, "%s", tok);
		}

		/* WDS Peer Link Default KeyID */
		bzero(tmp_buffer, sizeof(tmp_buffer));
		memset(val, 0 ,sizeof(val));
		CFG_get_str(CFG_WLN_WdsDefaultKeyID, val);

		if (!(strcmp(val, "") == 0))
		{
			strncpy(tmp_buffer, val, strlen(val));
			
			if (strlen(tmp_buffer) < sizeof(tmp_buffer))
				tmp_buffer[strlen(tmp_buffer) -1] = '\0';
			else
				tmp_buffer[sizeof(tmp_buffer) -1]='\0';
			

			for (i = 0, tok = strtok(tmp_buffer,";"); tok; tok = strtok(NULL,";"), i++)
				mWDS[i].DefaultKeyID = atoi(tok);
		}

		/* WDS Peer Link Encryption Key */
		for (i = 0; i < idx; i++)
		{
			switch(i)
			{
				memset(val, 0 ,255);
				
				case 0:
					CFG_get_str(CFG_WLN_Wds1Key, val);
					break;
				case 1:
					CFG_get_str(CFG_WLN_Wds2Key, val);
					break;
				case 2:
					CFG_get_str(CFG_WLN_Wds3Key, val);
					break;
				case 3:
					CFG_get_str(CFG_WLN_Wds4Key, val);
					break;
				default:
					break;
			}

			if (strcmp(val, "") == 0)
				sprintf(mWDS[i].Key, "%s", "");
			else
				sprintf(mWDS[i].Key, "%s", val);
		}
	}

	if ((wake_up_dot1x == 1) && (start_uam == 0) && (wake_up_wapid == 0))
		return 2;
	else if ((wake_up_dot1x == 0) && (start_uam == 1) && (wake_up_wapid == 0))
		return 3;
	else if ((wake_up_dot1x == 0) && (start_uam == 0) && (wake_up_wapid == 1))
		return 5;
	else if ((wake_up_dot1x == 1) && (start_uam == 1) && (wake_up_wapid == 0))
		return 4;
	else if ((wake_up_wapid == 1) && (wake_up_dot1x == 1) && (start_uam == 0))
		return 6;
	else
		return 1;
}

void CGI_get_wlan_mac_address(http_req *req)
{
	char if_hw[18] = {0};
	struct ifreq ifr;
	char *ptr;
	int skfd;

	memset(if_hw, 0, 18);

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* hardware address */
	strncpy(ifr.ifr_name, "ra0", IF_NAMESIZE);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("SIOCGIFHWADDR");
		close(skfd);
		return;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	(void) close(skfd);

	WEB_printf( req, "%s", if_hw);

	return;
}
void CGI_get_wlan_mac_address1(http_req *req)
{
	char if_hw[18] = {0};
	struct ifreq ifr;
	char *ptr;
	int skfd;

	memset(if_hw, 0, 18);

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* hardware address */
	strncpy(ifr.ifr_name, "eth1", IF_NAMESIZE);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) 
	{
		perror("SIOCGIFHWADDR");
		close(skfd);
		return;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	(void) close(skfd);
	
	WEB_printf( req, "%s", if_hw);

	return;
}
void CGI_get_wlan_11a_channel_list(http_req *req)
{
	int  idx = 0;	
	char val[255];     
	
	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_CountryCode, val);

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "JP") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 0; idx < 4; idx++)
		{
			if (idx == 0)
				WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", 36 + 4*idx, 5180 + 20*idx, 36 + 4*idx);
			else
				WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", 36 + 4*idx, 5180 + 20*idx, 36 + 4*idx);
		}
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "TW") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 4; idx < 8; idx++)
			WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", 36 + 4*idx, 5180 + 20*idx, 36 + 4*idx);
    }

	if ((val == "") || (strcmp(val, "") == 0))
	{
		for (idx = 16; idx < 27; idx++)
			WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", 36 + 4*idx, 5180 + 20*idx, 36 + 4*idx);
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) || (strcmp(val, "TW") == 0) ||
        (strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 28; idx < 32; idx++)
			WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", 36 + 4*idx + 1, 5180 + 20*idx + 5, 36 + 4*idx + 1);
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) ||
		(strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
		WEB_printf(req, "<option value=165>5825MHz (Channel 165)</option>\n");
	}

	return;
}

void CGI_get_wlan_11b_channel_list(http_req *req)
{
	int  idx = 0;	
	char val[255]; 
	
	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_CountryCode, val);

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) || (strcmp(val, "JP") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "TW") == 0) || (strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 0; idx < 11; idx++)
		{
			if (idx == 5)
				WEB_printf(req, "<option value=%d selected>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
			else
				WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
		}
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "JP") == 0) || (strcmp(val, "TW") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 11; idx < 13; idx++)
			WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "JP") == 0))
	{
		WEB_printf(req, "<option value=14>2484MHz (Channel 14)</option>\n");
	}

	return;
}

void CGI_get_wlan_11g_channel_list(http_req *req)
{
	int  idx = 0;	
	char val[255];    
	
	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_CountryCode, val);

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "US") == 0) || (strcmp(val, "JP") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "TW") == 0) || (strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
		for (idx = 0; idx < 11; idx++)
		{
			if (idx == 5)
				WEB_printf(req, "<option value=%d selected>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
			else
				WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
		}
	}

	if ((val == "") || (strcmp(val, "") == 0) || (strcmp(val, "JP") == 0) || (strcmp(val, "TW") == 0) || (strcmp(val, "FR") == 0) ||
		(strcmp(val, "IE") == 0) || (strcmp(val, "CN") == 0) || (strcmp(val, "HK") == 0))
	{
			for (idx = 11; idx < 13; idx++)
				WEB_printf(req, "<option value=%d>%dMHz (Channel %d)</option>\n", idx + 1, 2412 + 5*idx, idx+1);
	}

	if ((val == "") || (strcmp(val, "") == 0))
	{
		WEB_printf(req, "<option value=14>2484MHz (Channel 14)</option>\n");
	}

	return;
}

void CGI_get_wlan_channel(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_AutoChannelSelect, val);

	if (val == "")
		WEB_printf(req, "%s", "9");
	else
	{
		if (strcmp(val, "1") == 0)
			WEB_printf(req, "%s", "0");
		else
		{
			CFG_get_str(CFG_WLN_Channel, val);
			
			if (val == "")
				WEB_printf(req, "%s", "9");
			else
				WEB_printf(req, "%s", val);
		}
	}

	return;
}

void CGI_get_wlan_wds_default_key(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	int wdsmode = 0;

	CFG_get_str(CFG_WLN_WdsEnable, val);
	
	wdsmode = atoi(val);

	memset(val, 0, 255);

	CFG_get_str(CFG_WLN_WdsDefaultKeyID, val);

	if (g_new_version == 2)
	{
		if ((val == NULL) || (strcmp(val, "") == 0))
			WEB_printf(req, "%s", "");
		else
		{
			if (wdsmode == 4)
			{
				wdsmode = atoi(val);
				WEB_printf(req, "%d", wdsmode);
			}
			else
				WEB_printf(req, "%s", val);
		}
	}
	else
	{
		WEB_printf(req, "%s", val);
	}

	return;
}

void CGI_get_wlan_wds_encryp_key(http_req *req)
{
	char val[255];  
	char tmp_buffer[260];
	int wdsmode = 0;

	val[0] = '\0';
	
	if (g_new_version == 2)
	{
		bzero(tmp_buffer, sizeof(tmp_buffer));

		CFG_get_str(CFG_WLN_WdsEnable, val);
		wdsmode = atoi(val);

		if (wdsmode == 0)
		{
			WEB_printf(req, "%s", "");
			return;
		}
		else if (wdsmode == 4)
		{
			CFG_get_str(CFG_WLN_Wds1Key, val);

			if ((val == "") || (strcmp(val, "") == 0))
				WEB_printf(req, "%s", "");
			else
				WEB_printf(req, "%s", val);

			return;
		}

		CFG_get_str(CFG_WLN_Wds1Key, val);
		if ((val == "") || (strcmp(val, "") == 0))
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", 0);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
		else
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", val);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}

		CFG_get_str(CFG_WLN_Wds2Key, val);
		if ((val == "") || (strcmp(val, "") == 0))
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", 0);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
		else
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", val);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}

		CFG_get_str(CFG_WLN_Wds3Key, val);
		if ((val == "") || (strcmp(val, "") == 0))
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", 0);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
		else
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", val);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}

		CFG_get_str(CFG_WLN_Wds4Key, val);
		if ((val == "") || (strcmp(val, "") == 0))
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", 0);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
		else
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", val);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}

		if (strlen(tmp_buffer) <= sizeof(tmp_buffer) && strlen(tmp_buffer) >0)
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			tmp_buffer[sizeof(tmp_buffer) - 1] = '\0';
		WEB_printf(req, "%s", tmp_buffer);
	}
	else
	{
		CFG_get_str(CFG_WLN_WdsKey, val);
	}

	if (val == "")
	   WEB_printf(req, "%s", "");
	else
	   WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_all_bss_tkip_or_wep(http_req *req)
{
	char val[255];  
	char *tmpp = NULL;

	val[0] = '\0';

	CFG_get_str(CFG_WLN_EncrypType, val);

	if (val == "")
	   	WEB_printf(req, "%s", "0");
	else
	{
		tmpp = strstr(val, "TKIP");
		if (tmpp == NULL)
			tmpp = strstr(val, "WEP");

		if (tmpp == NULL)
			WEB_printf(req, "%s", "0");
		else
			WEB_printf(req, "%s", "1");
	}

	return;
}

/* save_level 0: only change SSID and HideSSID 1: SSID Number change or Security change */
int save_mbss_value_to_flash(int save_level)
{
	int  idx, s, new_driver;
	char tmp_buffer[260];
	unsigned char version_number[8] = {0};

	new_driver = 0;

	if ( OidQueryInformation(RT_OID_QUERY_DRIVER_VERSION, "ra0", &version_number, sizeof(unsigned char)*8) < 0 )
	{
		if ( OidQueryInformation(RT_OID_VERSION_INFO,"ra0", &version_number, sizeof(unsigned char)*8) < 0 )
		{
			new_driver = 0;
		}
	}

	new_driver = 2;
	CFG_set(CFG_WLN_NewVersion, "2");
	
	g_new_version = new_driver;

	/* SSID */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].SSID);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						CFG_set(CFG_WLN_SSID1, mBSSID[idx].SSID);
						break;
					case 1:
						CFG_set(CFG_WLN_SSID2, mBSSID[idx].SSID);
						break;
					case 2:
						CFG_set(CFG_WLN_SSID3, mBSSID[idx].SSID);
						break;
					case 3:
						CFG_set(CFG_WLN_SSID4, mBSSID[idx].SSID);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_SSID, tmp_buffer);
		CFG_set(CFG_WLN_SSID1, "");
		CFG_set(CFG_WLN_SSID2, "");
		CFG_set(CFG_WLN_SSID3, "");
		CFG_set(CFG_WLN_SSID4, "");
	}

	/* TxRate */
/*
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].TxRate);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	nvram_bufset("TxRate", tmp_buffer);
*/

	/* HideSSID */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].HideSSID);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer) >= sizeof(tmp_buffer))
		tmp_buffer[sizeof(tmp_buffer) -1] = '\0';
	else if (strlen(tmp_buffer) > 0)
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	CFG_set(CFG_WLN_HideSSID, tmp_buffer);

	/* VlanName */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].VlanName);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
	{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
	}
	CFG_set(CFG_WLN_VLANName, tmp_buffer);

	/* Vlan ID */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].VlanId);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_VLANID, tmp_buffer);

	/* Vlan Priority */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].VlanPriority);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_VLANPriority, tmp_buffer);
	
	if (save_level == 0)
	{
		CFG_commit(0);
		return 1;
	}

	/* SecurityMode */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].SecurityMode);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_SecurityMode, tmp_buffer);

	/* AuthMode */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].AuthMode);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_AuthMode, tmp_buffer);

	/* EncrypType */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].EncrypType);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_EncrypType, tmp_buffer);

	/* WPAPSK */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				if (strcmp(mBSSID[idx].WPAPSK, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].WPAPSK);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].WPAPSK, "") == 0)
							CFG_set(CFG_WLN_WPAPSK1, "0");
						else
							CFG_set(CFG_WLN_WPAPSK1, mBSSID[idx].WPAPSK);
						break;
					case 1:
						if (strcmp(mBSSID[idx].WPAPSK, "") == 0)
							CFG_set(CFG_WLN_WPAPSK2, "0");
						else
							CFG_set(CFG_WLN_WPAPSK2, mBSSID[idx].WPAPSK);
						break;
					case 2:
						if (strcmp(mBSSID[idx].WPAPSK, "") == 0)
							CFG_set(CFG_WLN_WPAPSK3, "0");
						else
							CFG_set(CFG_WLN_WPAPSK3, mBSSID[idx].WPAPSK);
						break;
					case 3:
						if (strcmp(mBSSID[idx].WPAPSK, "") == 0)
							CFG_set(CFG_WLN_WPAPSK4, "0");
						else
							CFG_set(CFG_WLN_WPAPSK4, mBSSID[idx].WPAPSK);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_WPAPSK, tmp_buffer);
		CFG_set(CFG_WLN_WPAPSK1, "");
		CFG_set(CFG_WLN_WPAPSK2, "");
		CFG_set(CFG_WLN_WPAPSK3, "");
		CFG_set(CFG_WLN_WPAPSK4, "");
	}

	/* DefaultKeyID */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].DefaultKeyID);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_DefaultKeyID, tmp_buffer);

	/* Key1Type */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].Key1Type);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_Key1Type, tmp_buffer);

	/* Key1Str */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				if (strcmp(mBSSID[idx].Key1Str, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].Key1Str);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].Key1Str, "") == 0)
							CFG_set(CFG_WLN_Key1Str1, "0");
						else
							CFG_set(CFG_WLN_Key1Str1, mBSSID[idx].Key1Str);
						break;
					case 1:
						if (strcmp(mBSSID[idx].Key1Str, "") == 0)
							CFG_set(CFG_WLN_Key1Str2, "0");
						else
							CFG_set(CFG_WLN_Key1Str2, mBSSID[idx].Key1Str);
						break;
					case 2:
						if (strcmp(mBSSID[idx].Key1Str, "") == 0)
							CFG_set(CFG_WLN_Key1Str3, "0");
						else
							CFG_set(CFG_WLN_Key1Str3, mBSSID[idx].Key1Str);
						break;
					case 3:
						if (strcmp(mBSSID[idx].Key1Str, "") == 0)
							CFG_set(CFG_WLN_Key1Str4, "0");
						else
							CFG_set(CFG_WLN_Key1Str4, mBSSID[idx].Key1Str);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_Key1Str, tmp_buffer);
		CFG_set(CFG_WLN_Key1Str1, "");
		CFG_set(CFG_WLN_Key1Str2, "");
		CFG_set(CFG_WLN_Key1Str3, "");
		CFG_set(CFG_WLN_Key1Str4, "");
	}

	/* Key2Type */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].Key2Type);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_Key2Type, tmp_buffer);

	/* Key2Str */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				if (strcmp(mBSSID[idx].Key2Str, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].Key2Str);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].Key2Str, "") == 0)
							CFG_set(CFG_WLN_Key2Str1, "0");
						else
							CFG_set(CFG_WLN_Key2Str1, mBSSID[idx].Key2Str);
						break;
					case 1:
						if (strcmp(mBSSID[idx].Key2Str, "") == 0)
							CFG_set(CFG_WLN_Key2Str2, "0");
						else
							CFG_set(CFG_WLN_Key2Str2, mBSSID[idx].Key2Str);
						break;
					case 2:
						if (strcmp(mBSSID[idx].Key2Str, "") == 0)
							CFG_set(CFG_WLN_Key2Str3, "0");
						else
							CFG_set(CFG_WLN_Key2Str3, mBSSID[idx].Key2Str);
						break;
					case 3:
						if (strcmp(mBSSID[idx].Key2Str, "") == 0)
							CFG_set(CFG_WLN_Key2Str4, "0");
						else
							CFG_set(CFG_WLN_Key2Str4, mBSSID[idx].Key2Str);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_Key2Str, tmp_buffer);
		CFG_set(CFG_WLN_Key2Str1, "");
		CFG_set(CFG_WLN_Key2Str2, "");
		CFG_set(CFG_WLN_Key2Str3, "");
		CFG_set(CFG_WLN_Key2Str4, "");
	}

	/* Key3Type */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].Key3Type);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_Key3Type, tmp_buffer);

	/* Key3Str */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				if (strcmp(mBSSID[idx].Key3Str, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].Key3Str);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].Key3Str, "") == 0)
							CFG_set(CFG_WLN_Key3Str1, "0");
						else
							CFG_set(CFG_WLN_Key3Str1, mBSSID[idx].Key3Str);
						break;
					case 1:
						if (strcmp(mBSSID[idx].Key3Str, "") == 0)
							CFG_set(CFG_WLN_Key3Str2, "0");
						else
							CFG_set(CFG_WLN_Key3Str2, mBSSID[idx].Key3Str);
						break;
					case 2:
						if (strcmp(mBSSID[idx].Key3Str, "") == 0)
							CFG_set(CFG_WLN_Key3Str3, "0");
						else
							CFG_set(CFG_WLN_Key3Str3, mBSSID[idx].Key3Str);
						break;
					case 3:
						if (strcmp(mBSSID[idx].Key3Str, "") == 0)
							CFG_set(CFG_WLN_Key3Str4, "0");
						else
							CFG_set(CFG_WLN_Key3Str4, mBSSID[idx].Key3Str);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
		{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
		CFG_set(CFG_WLN_Key3Str, tmp_buffer);
		CFG_set(CFG_WLN_Key3Str1, "");
		CFG_set(CFG_WLN_Key3Str2, "");
		CFG_set(CFG_WLN_Key3Str3, "");
		CFG_set(CFG_WLN_Key3Str4, "");
	}

	/* Key4Type */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].Key4Type);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_Key4Type, tmp_buffer);

	/* Key4Str */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (new_driver == 0)
			{
				if (strcmp(mBSSID[idx].Key4Str, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].Key4Str);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
			else
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].Key4Str, "") == 0)
							CFG_set(CFG_WLN_Key4Str1, "0");
						else
							CFG_set(CFG_WLN_Key4Str1, mBSSID[idx].Key4Str);
						break;
					case 1:
						if (strcmp(mBSSID[idx].Key4Str, "") == 0)
							CFG_set(CFG_WLN_Key4Str2, "0");
						else
							CFG_set(CFG_WLN_Key4Str2, mBSSID[idx].Key4Str);
						break;
					case 2:
						if (strcmp(mBSSID[idx].Key4Str, "") == 0)
							CFG_set(CFG_WLN_Key4Str3, "0");
						else
							CFG_set(CFG_WLN_Key4Str3, mBSSID[idx].Key4Str);
						break;
					case 3:
						if (strcmp(mBSSID[idx].Key4Str, "") == 0)
							CFG_set(CFG_WLN_Key4Str4, "0");
						else
							CFG_set(CFG_WLN_Key4Str4, mBSSID[idx].Key4Str);
						break;
					default:
						break;
				}
			}
		}
	}

	if (new_driver == 0)
	{
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_Key4Str, tmp_buffer);
		CFG_set(CFG_WLN_Key4Str1, "");
		CFG_set(CFG_WLN_Key4Str2, "");
		CFG_set(CFG_WLN_Key4Str3, "");
		CFG_set(CFG_WLN_Key4Str4, "");
	}

	/* WAPI Key Type */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].WapiKeyType);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_WapiPskType, tmp_buffer);

	/* WAPI Key */
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			switch(idx)
			{
				case 0:
					if (strcmp(mBSSID[idx].WapiKey, "") == 0)
						CFG_set(CFG_WLN_WapiPsk1, "0");
					else
						CFG_set(CFG_WLN_WapiPsk1, mBSSID[idx].WapiKey);
					break;
				case 1:
					if (strcmp(mBSSID[idx].WapiKey, "") == 0)
						CFG_set(CFG_WLN_WapiPsk2, "0");
					else
						CFG_set(CFG_WLN_WapiPsk2, mBSSID[idx].WapiKey);
					break;
				case 2:
					if (strcmp(mBSSID[idx].WapiKey, "") == 0)
						CFG_set(CFG_WLN_WapiPsk3, "0");
					else
						CFG_set(CFG_WLN_WapiPsk3, mBSSID[idx].WapiKey);
					break;
				case 3:
					if (strcmp(mBSSID[idx].WapiKey, "") == 0)
						CFG_set(CFG_WLN_WapiPsk4, "0");
					else
						CFG_set(CFG_WLN_WapiPsk4, mBSSID[idx].WapiKey);
					break;
				default:
					break;
			}
		}
	}

	/* IEEE8021X */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].IEEE8021X);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_IEEE8021X, tmp_buffer);

	/* PreAuth */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].PreAuth);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_PreAuth, tmp_buffer);

	/* PMKCachePeriod */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].PMKCachePeriod);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_PMKCachePeriod, tmp_buffer);

	/* RekeyMethod */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			if (strcmp(mBSSID[idx].RekeyMethod, "") == 0)
				sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "DISABLE");
			else
				sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].RekeyMethod);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_RekeyMethod, tmp_buffer);

	/* RekeyInterval */
	bzero(tmp_buffer, sizeof(char)*260);
	for (idx = 0; idx < 4; idx++)
	{
		if (mBSSID[idx].enable == 1)
		{
			sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].RekeyInterval);
			sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
		}
	}
	if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
		tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
	else 
		{
		tmp_buffer[sizeof(tmp_buffer)-1]='\0';
		diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
		}
	CFG_set(CFG_WLN_RekeyInterval, tmp_buffer);

	if (new_driver == 2)
	{
		/* Radius Server */
		bzero(tmp_buffer, sizeof(char)*260);
		for (idx = 0; idx < 4; idx++)
		{
			if (mBSSID[idx].enable == 1)
			{
				if (strcmp(mBSSID[idx].radius_server, "") == 0)
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", "0");
				else
					sprintf(tmp_buffer+strlen(tmp_buffer),"%s", mBSSID[idx].radius_server);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
		}
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_RADIUS_Server, tmp_buffer);

		/* Radius Port */
		bzero(tmp_buffer, sizeof(char)*260);
		for (idx = 0; idx < 4; idx++)
		{
			if (mBSSID[idx].enable == 1)
			{
				sprintf(tmp_buffer+strlen(tmp_buffer),"%d", mBSSID[idx].radius_port);
				sprintf(tmp_buffer+strlen(tmp_buffer),"%c", ';');
			}
		}
		if (strlen(tmp_buffer)>0 &&strlen(tmp_buffer)<sizeof(tmp_buffer))
			tmp_buffer[strlen(tmp_buffer) - 1] = '\0';
		else 
			{
			tmp_buffer[sizeof(tmp_buffer)-1]='\0';
			diag_printf("[%s %d]tmp_buffer maybe overflow\n",__FUNCTION__,__LINE__);
			}
		CFG_set(CFG_WLN_RADIUS_Port, tmp_buffer);

		/* Radius Secret */
		bzero(tmp_buffer, sizeof(char)*260);
		for (idx = 0; idx < 4; idx++)
		{
			if (mBSSID[idx].enable == 1)
			{
				switch(idx)
				{
					case 0:
						if (strcmp(mBSSID[idx].radius_secret, "") == 0)
							CFG_set(CFG_WLN_RADIUS_Key1, "");
						else
							CFG_set(CFG_WLN_RADIUS_Key1, mBSSID[idx].radius_secret);
						break;
					case 1:
						if (strcmp(mBSSID[idx].radius_secret, "") == 0)
							CFG_set(CFG_WLN_RADIUS_Key2, "");
						else
							CFG_set(CFG_WLN_RADIUS_Key2, mBSSID[idx].radius_secret);
						break;
					case 2:
						if (strcmp(mBSSID[idx].radius_secret, "") == 0)
							CFG_set(CFG_WLN_RADIUS_Key3, "");
						else
							CFG_set(CFG_WLN_RADIUS_Key3, mBSSID[idx].radius_secret);
						break;
					case 3:
						if (strcmp(mBSSID[idx].radius_secret, "") == 0)
							CFG_set(CFG_WLN_RADIUS_Key4, "");
						else
							CFG_set(CFG_WLN_RADIUS_Key4, mBSSID[idx].radius_secret);
						break;
					default:
						break;
				}
			}
		}
	}

	CFG_commit(0);

	return 1;
}

void CGI_get_wlan_wsc_config_state(http_req *req)
{
	char val[255];  
	int s, temp_config;
	struct iwreq iwr;
	struct _WSC_CONFIGURED_VALUE wsc_value;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

	val[0] = '\0';

#ifdef CONFIG_WIRELESS
	memset(&wsc_value, 0, sizeof(wsc_value));
	memset(&iwr, 0, sizeof(iwr));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &wsc_value;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;
		
		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
	       }
	}

	if (found == 1)	
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_WSC_PROFILE, (caddr_t)&iwr) < 0)
		{
			diag_printf("Query RTPRIV_IOCTL_WSC_PROFILE has error.\n");
			WEB_printf(req, "%s", "1");
			return;
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_WSC_PROFILE, (caddr_t)&iwr) < 0)
		{
			diag_printf("Query RTPRIV_IOCTL_WSC_PROFILE has error.\n");
			WEB_printf(req, "%s", "1");
			return;
		}
#endif
	}	
	else
	{
		diag_printf("Can't find ra0.\n");
		WEB_printf(req, "%s", "1");
		return;
	}
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif	

	CFG_get_str(CFG_WLN_WscConfigured, val);
	
	temp_config = atoi(val);

	if (wsc_value.WscConfigured == 1)
		WEB_printf(req, "%s", "1");
	else if (wsc_value.WscConfigured == 2)
		WEB_printf(req, "%s", "2");
	else
		WEB_printf(req, "%s", "1");

#if 0
	if ((temp_config == 0) && (wsc_value.WscConfigured == 2))
	{
		char wsc_tmp[33];
		char wsc_key_tmp[65];

		CFG_set(CFG_WLN_WscConfigured, "1");

		g_wsc_configured = 1;

		sprintf(mBSSID[0].SSID, "%s", wsc_value.WscSsid);
		memset(wsc_tmp , 0, 33);
		sprintf(wsc_tmp, "%s", wsc_value.WscSsid);

		CFG_set(CFG_WLN_WscSSID, &wsc_tmp[0]);

		if (wsc_value.WscAuthMode == 0x0001)
		{
			CFG_set(CFG_WLN_WscAuthType, "1");
			sprintf(mBSSID[0].AuthMode, "%s", "OPEN");
		}
		else if (wsc_value.WscAuthMode == 0x0002)
		{
			CFG_set(CFG_WLN_WscAuthType, "2");
			sprintf(mBSSID[0].AuthMode, "%s", "WPAPSK");
		}
		else if (wsc_value.WscAuthMode == 0x0004)
		{
			CFG_set(CFG_WLN_WscAuthType, "4");
			sprintf(mBSSID[0].AuthMode, "%s", "SHARED");
		}
		else if (wsc_value.WscAuthMode == 0x0008)
		{
			CFG_set(CFG_WLN_WscAuthType, "8");
			sprintf(mBSSID[0].AuthMode, "%s", "WPA");
		}
		else if (wsc_value.WscAuthMode == 0x0010)
		{
			CFG_set(CFG_WLN_WscAuthType, "16");
			sprintf(mBSSID[0].AuthMode, "%s", "WPA2");
		}
		else if (wsc_value.WscAuthMode == 0x0020)
		{
			CFG_set(CFG_WLN_WscAuthType, "32");
			sprintf(mBSSID[0].AuthMode, "%s", "WPA2PSK");
		}
		else if (wsc_value.WscAuthMode == 0x0022)
		{
			CFG_set(CFG_WLN_WscAuthType, "34");
			sprintf(mBSSID[0].AuthMode, "%s", "WPAPSKWPA2PSK");
		}
		else
		{
			CFG_set(CFG_WLN_WscAuthType, "1");
			sprintf(mBSSID[0].AuthMode, "%s", "OPEN");
		}

		if (wsc_value.WscEncrypType == 0x0001)
		{
			CFG_set(CFG_WLN_WscEncrypType, "1");
			sprintf(mBSSID[0].EncrypType, "%s", "NONE");
			mBSSID[0].DefaultKeyID = 1;
			mBSSID[0].SecurityMode = 0;
		}
		else if (wsc_value.WscEncrypType == 0x0002)
		{
			CFG_set(CFG_WLN_WscEncrypType, "2");
			sprintf(mBSSID[0].EncrypType, "%s", "WEP");

			memset(wsc_key_tmp , 0, 65);
			sprintf(wsc_key_tmp, "%s", wsc_value.WscWPAKey);

			if ((strlen(wsc_key_tmp) == 5) || (strlen(wsc_key_tmp) == 13))
			{
				/* Key Entry Method == ASCII */
				mBSSID[0].Key1Type = 1;
				mBSSID[0].Key2Type = 1;
				mBSSID[0].Key3Type = 1;
				mBSSID[0].Key4Type = 1;
			}
			else if ((strlen(wsc_key_tmp) == 10) || (strlen(wsc_key_tmp) == 26))
			{
				/* Key Entry Method == HEX */
				mBSSID[0].Key1Type = 0;
				mBSSID[0].Key2Type = 0;
				mBSSID[0].Key3Type = 0;
				mBSSID[0].Key4Type = 0;
			}
			else
			{
				/* Key Entry Method == ASCII */
				mBSSID[0].Key1Type = 1;
				mBSSID[0].Key2Type = 1;
				mBSSID[0].Key3Type = 1;
				mBSSID[0].Key4Type = 1;
			}

			if (wsc_value.DefaultKeyIdx == 1)
				sprintf(mBSSID[0].Key1Str, "%s", wsc_value.WscWPAKey);
			else if (wsc_value.DefaultKeyIdx == 2)
				sprintf(mBSSID[0].Key2Str, "%s", wsc_value.WscWPAKey);
			else if (wsc_value.DefaultKeyIdx == 3)
				sprintf(mBSSID[0].Key3Str, "%s", wsc_value.WscWPAKey);
			else if (wsc_value.DefaultKeyIdx == 4)
				sprintf(mBSSID[0].Key4Str, "%s", wsc_value.WscWPAKey);

			mBSSID[0].DefaultKeyID = wsc_value.DefaultKeyIdx;
			mBSSID[0].SecurityMode = 1;
		}
		else if (wsc_value.WscEncrypType == 0x0004)
		{
			CFG_set(CFG_WLN_WscEncrypType, "4");
			sprintf(mBSSID[0].EncrypType, "%s", "TKIP");
			mBSSID[0].DefaultKeyID = 2;
			mBSSID[0].SecurityMode = 3;
			sprintf(mBSSID[0].WPAPSK, "%s", wsc_value.WscWPAKey);
			mBSSID[0].WPAPSK[64] = '\0';
		}
		else if (wsc_value.WscEncrypType == 0x0008)
		{
			CFG_set(CFG_WLN_WscEncrypType, "8");
			sprintf(mBSSID[0].EncrypType, "%s", "AES");
			mBSSID[0].DefaultKeyID = 2;
			mBSSID[0].SecurityMode = 3;
			sprintf(mBSSID[0].WPAPSK, "%s", wsc_value.WscWPAKey);
			mBSSID[0].WPAPSK[64] = '\0';
		}
		else if (wsc_value.WscEncrypType == 0x000c)
		{
			CFG_set(CFG_WLN_WscEncrypType, "12");
			sprintf(mBSSID[0].EncrypType, "%s", "TKIPAES");
			mBSSID[0].DefaultKeyID = 2;
			mBSSID[0].SecurityMode = 3;
			sprintf(mBSSID[0].WPAPSK, "%s", wsc_value.WscWPAKey);
			mBSSID[0].WPAPSK[64] = '\0';
		}
		else
		{
			CFG_set(CFG_WLN_WscEncrypType, "1");
			sprintf(mBSSID[0].EncrypType, "%s", "NONE");
			mBSSID[0].DefaultKeyID = 1;
			mBSSID[0].SecurityMode = 0;
		}
		
		memset(wsc_key_tmp , 0, 65);
		if (wsc_value.WscEncrypType >= 0x0002)
		{
			sprintf(wsc_key_tmp, "%s", wsc_value.WscWPAKey);
			CFG_set(CFG_WLN_WscNewKey, &wsc_key_tmp[0]);
		}
		mBSSID[0].IEEE8021X = 0;

		CFG_commit(0);

		//save_mbss_value_to_flash(1);
	}
	else if ((temp_config == 1) && (wsc_value.WscConfigured == 1))
	{
		CFG_set(CFG_WLN_WscConfigured, "0");
		g_wsc_configured = 0;

		CFG_commit(0);
	}
#endif

	return;
}

void CGI_get_wlan_ssid_num(http_req *req)
{
	char val[255];  

	val[0] = '\0';

	CFG_get_str(CFG_WLN_BssidNum, val);

	if (val == "")
		WEB_printf(req, "%s", "1");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_wds_phy_mode(http_req *req)
{
	char val[255];  

	val[0] = '\0';

	CFG_get_str(CFG_WLN_WdsPhyMode, val);

	if (val == "")
		WEB_printf(req, "%s", "0");
	else if (strcmp(val, "CCK") == 0)
		WEB_printf(req, "%s", "0");
	else if (strcmp(val, "OFDM") == 0)
		WEB_printf(req, "%s", "1");
	else if (strcmp(val, "HTMIX") == 0)
		WEB_printf(req, "%s", "2");
	else if (strcmp(val, "GREENFIELD") == 0)
		WEB_printf(req, "%s", "3");

	return;
}

void CGI_get_wlan_apcli_include(http_req *req)
{
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (s < 0)
	{
		WEB_printf(req, "%s", "0");
		return;
	}
	
	strcpy(ifr.ifr_name, "apcli0");

	if (ioctl(s, SIOCGIFFLAGS, &ifr))
		WEB_printf(req, "%s", "0");
	else
		WEB_printf(req, "%s", "1");

	close(s);
	return;
}

void CGI_get_wlan_ht_sta_associate_list(http_req *req)
{
	int s, idx = 0;
	struct iwreq iwr;
	RT_802_11_MAC_TABLE MacTab;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	memset(&MacTab, 0, sizeof(RT_802_11_MAC_TABLE));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &MacTab;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_GET_MAC_TABLE sock fail!!\n");
			return;	
		}
#endif		
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_GET_MAC_TABLE sock fail!!\n");
			return; 
		}
#endif	

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		return;	
	}

	for (idx = 0; idx < MacTab.Num; idx++)
	{
		if (MacTab.Entry[idx].TxRate.field.MODE >= 2)
		{
			WEB_printf(req, "<tr style=\"Font-SIZE: 10pt; BACKGROUND: #ffffff\" onClick=\"SelectRow(this, '%02X:%02X:%02X:%02X:%02X:%02X');\"><td align=\"center\" nowrap>",
															MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
															MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
															MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);

			WEB_printf(req, "%02X:%02X:%02X:%02X:%02X:%02X</td>",  MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
																MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
																MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);

			WEB_printf(req, "<td align=\"center\" nowrap>");
			WEB_printf(req, "%d</td>", MacTab.Entry[idx].Aid);
			WEB_printf(req, "<td align=\"center\" nowrap>");
			if ( MacTab.Entry[idx].Psm == 1)
				WEB_printf(req, "YES</td>");
			else
				WEB_printf(req, "NO</td>");
			
			WEB_printf(req, "</tr>");
		}
	}

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_ht_ba_ori_sta_info(http_req *req)
{
	int s, tid, idx = 0;
	struct iwreq iwr;
	QUERYBA_TABLE BAT;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	memset(&BAT, 0, sizeof(BAT));
	iwr.u.data.pointer = (caddr_t) &BAT;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_QUERY_BATABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_QUERY_BATABLE  fail!!!!!\n");
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_QUERY_BATABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_QUERY_BATABLE  fail!!!!!\n");
			return; 
		}
#endif
	}
	else
	{
		diag_printf("Can't find ra0!!!!!\n");
		return;	
	}
	
	for (idx = 0; idx < BAT.OriNum; idx++)
	{
		WEB_printf(req, "<tr><td align=\"center\" nowrap>");
		WEB_printf(req, "%02X:%02X:%02X:%02X:%02X:%02X</td>",  BAT.BAOriEntry[idx].MACAddr[0], BAT.BAOriEntry[idx].MACAddr[1],
															BAT.BAOriEntry[idx].MACAddr[2], BAT.BAOriEntry[idx].MACAddr[3],
															BAT.BAOriEntry[idx].MACAddr[4], BAT.BAOriEntry[idx].MACAddr[5]);
		for (tid = 0; tid < 8; tid++)
		{
			WEB_printf(req, "<td align=\"center\" nowrap>");
			if (BAT.BAOriEntry[idx].BufSize[tid] == 0)
			WEB_printf(req, "-</td>");
			else
				WEB_printf(req, "%d</td>", BAT.BAOriEntry[idx].BufSize[tid]);
		}
		WEB_printf(req, "</tr>");
	}

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_ht_ba_rec_sta_info(http_req *req)
{
	int s, tid, idx = 0;
	struct iwreq iwr;
	QUERYBA_TABLE BAT;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	memset(&BAT, 0, sizeof(BAT));
	iwr.u.data.pointer = (caddr_t) &BAT;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_QUERY_BATABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_QUERY_BATABLE  fail!!!!!\n");
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_QUERY_BATABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RTPRIV_IOCTL_QUERY_BATABLE  fail!!!!!\n");
			return; 
		}
#endif	

	}
	else
	{
		diag_printf("Can't find ra0!!!!!\n");
		return;	
	}

	for (idx = 0; idx < BAT.RecNum; idx++)
	{
		WEB_printf(req, "<tr><td align=\"center\" nowrap>");
		WEB_printf(req, "%02X:%02X:%02X:%02X:%02X:%02X</td>",  BAT.BARecEntry[idx].MACAddr[0], BAT.BARecEntry[idx].MACAddr[1],
															BAT.BARecEntry[idx].MACAddr[2], BAT.BARecEntry[idx].MACAddr[3],
															BAT.BARecEntry[idx].MACAddr[4], BAT.BARecEntry[idx].MACAddr[5]);
		for (tid = 0; tid < 8; tid++)
		{
			WEB_printf(req, "<td align=\"center\" nowrap>");
			if (BAT.BARecEntry[idx].BufSize[tid] == 0)
				WEB_printf(req, "-</td>");
			else
				WEB_printf(req, "%d</td>", BAT.BARecEntry[idx].BufSize[tid]);
		}
		WEB_printf(req, "</tr>");
	}

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_wsc_use_proxy(http_req *req)
{
	char val[255];  

	val[0] = '\0';

	CFG_get_str(CFG_WLN_WscConfMode, val);

	if (val == "")
		WEB_printf(req, "%s", "0");
	else
	{
		if ((strcmp(val, "2") == 0) || (strcmp(val, "3") == 0) || (strcmp(val, "6") == 0) || (strcmp(val, "7") == 0))
			WEB_printf(req, "%s", "1");
		else
			WEB_printf(req, "%s", "0");
	}

	return;
}

void CGI_get_wlan_wsc_use_internal_reg(http_req *req)
{
	char val[255];  

	val[0] = '\0';

	CFG_get_str(CFG_WLN_WscConfMode, val);

	if (val == "")
		WEB_printf(req, "%s", "0");
	else
	{
		if ((strcmp(val, "4") == 0) || (strcmp(val, "5") == 0) || (strcmp(val, "6") == 0) || (strcmp(val, "7") == 0))
			WEB_printf(req, "%s", "1");
		else
			WEB_printf(req, "%s", "0");
	}

	return;
}

void CGI_get_wlan_wsc_pin_code(http_req *req)
{
	struct iwreq iwr;
	unsigned long WscPinCode = 0;
	
#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &WscPinCode;
	iwr.u.data.flags = RT_OID_WSC_PIN_CODE;

	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "00000000");
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "00000000");
			return; 
		}
#endif

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		WEB_printf(req, "%s", "00000000");
		return;	
	}

	WEB_printf(req, "%08d", (int)WscPinCode);

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_wsc_uuid(http_req *req)
{
	struct iwreq	iwr;
	unsigned char	Wsc_Uuid_Str[37];
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	memset(Wsc_Uuid_Str, 0, 37);
	memset(&iwr, 0, sizeof(iwr));
	
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &Wsc_Uuid_Str;
	iwr.u.data.flags = RT_OID_WSC_UUID;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "");
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "");
			return; 
		}
#endif

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		WEB_printf(req, "%s", "");
		return;	
	}

	WEB_printf(req, "%s", Wsc_Uuid_Str);

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_wsc_dev_pin_code(http_req *req)
{
	struct iwreq iwr;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	char val[255];  
	unsigned long WscPinCode = 0;
	int	found = 0;
	
	val[0] = '\0';

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &WscPinCode;
	iwr.u.data.flags = RT_OID_WSC_PIN_CODE;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "00000000");
			return;	
		}
#endif		
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			WEB_printf(req, "%s", "00000000");
			return; 
		}
#endif	

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		WEB_printf(req, "%s", "00000000");
		return;	
	}

	CFG_get_str(CFG_WLN_WscPinCode, val);

	if ( (strcmp(val, "0") == 0) || (strcmp(val, "") == 0))
		WEB_printf(req, "%08d", (int)WscPinCode);  
	else
		WEB_printf(req, "%s", val); 

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_wsc_current_status(http_req *req)
{
	struct iwreq iwr;
	int WscStatus = 0; 
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &WscStatus;
	iwr.u.data.flags = RT_OID_WSC_QUERY_STATUS;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", WscStatus);
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", WscStatus);
			return; 
		}
#endif	

	}
	else
	{
		diag_printf("Can't find ra0!!!!!\n");
		WEB_printf(req, "%d", 0);
		return;	
	}

	if (WscStatus == STATUS_WSC_FAIL)
	{
		memset(&iwr, 0, sizeof(iwr));
		//strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
		iwr.u.data.pointer = (caddr_t) &WscStatus;
		iwr.u.data.flags = RT_OID_WSC_QUERY_STATUS; 
#ifdef CONFIG_AP_SUPPORT 
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", WscStatus);
			return;	
		} 
#endif		
#ifdef CONFIG_STA_SUPPORT 
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", WscStatus);
			return; 
		} 
#endif	

	}

	WEB_printf(req, "%d", WscStatus);

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void CGI_get_wlan_wsc_encr_type(http_req *req)
{
}

void CGI_get_wlan_wsc_auth_mode(http_req *req)
{
}

void CGI_get_wlan_wsc_ssid(http_req *req)
{
	char val[255];  

	val[0]='\0'; 

	CFG_get_str(CFG_WLN_WscSSID, val);

	if (val == "")
		WEB_printf(req, "%s", "WscNewAP");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_wsc_pass_phrase(http_req *req)
{ 	
	char val[255];  

	val[0] = '\0'; 

	CFG_get_str(CFG_WLN_WscNewKey, val);

	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_wps_process_status(http_req *req)
{ 
	struct iwreq iwr;
	int WscStatus = 0;
	int during=0;
	time_t now_time; 
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int	found = 0;

#ifdef CONFIG_WIRELESS
	memset(&iwr, 0, sizeof(iwr));
	//rncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &WscStatus;
	iwr.u.data.flags = RT_OID_WSC_QUERY_STATUS; 

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", 0);
			return;	
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!!!!\n");
			WEB_printf(req, "%d", 0);
			return; 
		}
#endif	

	}
	else
	{
		diag_printf("Can't find ra0!!!!!\n");
		WEB_printf(req, "%d", WscStatus);
		return;	
	} 

	time(&now_time);
	during = now_time - wps_status_start_time;

	switch (WscStatus)
	{
		case STATUS_WSC_NOTUSED:
			WEB_printf(req, "%s", "WSC NOT USED");
			break;
		case STATUS_WSC_LINK_UP:
			WEB_printf(req, "%s", "WPS AP already Trigger");
			wps_status_flag = 0;
			break;
		case STATUS_WSC_EAPOL_START_SENT:
			WEB_printf(req, "%s", "Sending EAPOL-Start");
			break;
		case STATUS_WSC_EAP_REQ_ID_SENT:
			WEB_printf(req, "%s", "Sending EAP-Rsp(ID)");
			break; 
		//Enrollee
		case STATUS_WSC_EAP_M1_SENT:
			WEB_printf(req, "%s", "Sending M1");
			break;
		case STATUS_WSC_EAP_M2_RECEIVED:
			WEB_printf(req, "%s", "Received M2");
			break;
		case STATUS_WSC_EAP_M2D_RECEIVED:
			WEB_printf(req, "%s", "Received M2D");
			break;
		case STATUS_WSC_EAP_M3_SENT:
			WEB_printf(req, "%s", "Sending M3>");
			break;
		case STATUS_WSC_EAP_M4_RECEIVED:
			WEB_printf(req, "%s", "Received M4");
			break;
		case STATUS_WSC_EAP_M5_SENT:
			WEB_printf(req, "%s", "Sending M5");
			break;
		case STATUS_WSC_EAP_M6_RECEIVED:
			WEB_printf(req, "%s", "Received M6");
			break;
		case STATUS_WSC_EAP_M7_SENT:
			WEB_printf(req, "%s", "Sending M7");
			break;
		case STATUS_WSC_EAP_M8_RECEIVED:
			WEB_printf(req, "%s", "Received M8");
			break; 
		//Registrar
		case STATUS_WSC_EAP_M1_RECEIVED:
			WEB_printf(req, "%s", "Received M1");
			break;
		case STATUS_WSC_EAP_M2_SENT:	
			WEB_printf(req, "%s", "Sending M2");
			break;
		case STATUS_WSC_EAP_M3_RECEIVED:
			WEB_printf(req, "%s", "Received M3");
			break;
		case STATUS_WSC_EAP_M4_SENT:
			WEB_printf(req, "%s", "Sending M4");
			break;
		case STATUS_WSC_EAP_M5_RECEIVED:
			WEB_printf(req, "%s", "Received M5");
			break;
		case STATUS_WSC_EAP_M6_SENT:
			WEB_printf(req, "%s", "Sending M6");
			break;
		case STATUS_WSC_EAP_M7_RECEIVED:
			WEB_printf(req, "%s", "Received M7");
			break;
		case STATUS_WSC_EAP_M8_SENT:
			WEB_printf(req, "%s", "Sending M8");
			break;
		case STATUS_WSC_EAP_RSP_DONE_SENT:
			WEB_printf(req, "%s", "Sending EAP Response (Done)");
			break;
		case STATUS_WSC_CONFIGURED:
			WEB_printf(req, "%s", "Configured");
			break;
		case STATUS_WSC_IDLE:
			if (during >= 119)
			{
				if (wps_status_flag == 0)
				{
					WEB_printf(req, "WPS 2 Mins Timeout !! <br>");
				}

				WEB_printf(req, "<input type=\"button\" value=\"Close Window\" onClick=\"window.close()\">");
			}
			else
				WEB_printf(req, "WPS IDLE!");
			break;
		case STATUS_WSC_FAIL:	
			WEB_printf(req, "WPS FAIL!");
			wps_status_flag = 1;
			break;
		default:
			WEB_printf(req, "%s", "No Suitable message");
			break;
	} 

	return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}

void ConverterStringToDisplay(char *str)
{
	int  len, i;
	char buffer[193];
	char *pOut;

	memset(buffer,0,193);
	len = strlen(str);
	pOut = &buffer[0];

	for (i = 0; i < len; i++)
	{
		/* check special character */

		switch (str[i])
		{
			case '&':
				strcpy (pOut, "&amp;");
				pOut += 5;
				break;

			case '<': 
				strcpy (pOut, "&lt;");
				pOut += 4;
				break;

			case '>': 
				strcpy (pOut, "&gt;");
				pOut += 4;
				break;

			case '"':
				strcpy (pOut, "&quot;");
				pOut += 6;
				break;

			//case ' ':
				//strcpy (pOut, "&nbsp;");
				//pOut += 6;
				//break;

			default:
				if (str[i] <= 31)
				{
					//Device Control Characters
					sprintf(pOut, "&#%02d;", str[i]);
					pOut += 5;
				}
				else if ((str[i]==39) || (str[i]==47) || (str[i]==59) || (str[i]==92))
				{
					// ' / ; (backslash)
					sprintf(pOut, "&#%02d;", str[i]);
					pOut += 5;
				}
				else if (str[i] >= 127)
				{
					//Device Control Characters
					sprintf(pOut, "&#%03d;", str[i]);
					pOut += 6;
				}
				else
				{
					*pOut = str[i];
					pOut++;
				}
				break;
		}
    }

	*pOut = '\0';
	strcpy(str, buffer);

	return;
}

void ConverterStringToDisplay2(char *str)
{
	int  len, i;
	char buffer[193];
	char *pOut;

	memset(buffer,0,193);
	len = strlen(str);
	pOut = &buffer[0];

	for (i = 0; i < len; i++)
	{
		/* check special character */

		switch (str[i])
		{
			case '&':
				strcpy (pOut, "&amp;");
				pOut += 5;
				break;

			case '<':
				strcpy (pOut, "&lt;");
				pOut += 4;
				break;

			case '>':
				strcpy (pOut, "&gt;");
				pOut += 4;
				break;

			case '"':
				strcpy (pOut, "&quot;");
				pOut += 6;
				break;

			case ' ':
				strcpy (pOut, "&nbsp;");
				pOut += 6;
				break;

			default:
				if (str[i] <= 31)
				{
					//Device Control Characters
					sprintf(pOut, "&#%02d;", str[i]);
					pOut += 5;
				}
				else if ((str[i]==39) || (str[i]==47) || (str[i]==59) || (str[i]==92))
				{
					// ' / ; (backslash)
					sprintf(pOut, "&#%02d;", str[i]);
					pOut += 5;
				}
				else if (str[i] >= 127)
				{
					//Device Control Characters
					sprintf(pOut, "&#%03d;", str[i]);
					pOut += 6;
				}
				else
				{
					*pOut = str[i];
					pOut++;
				}
				break;
		}
    }

	*pOut = '\0';
	strcpy(str, buffer);

	return;
}

void CGI_get_wlan_mainssid_for_overview(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_SSID1, val);

	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_multissid1_for_overview(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_SSID2, val);

	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_multissid2_for_overview(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_SSID3, val);

	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_multissid3_for_overview(http_req *req)
{	
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_SSID4, val);

	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_driver_version(http_req *req)
{
	unsigned char version_number[16] = {0};

	if (OidQueryInformation(RT_OID_VERSION_INFO, "ra0", &version_number, sizeof(unsigned char)*16) < 0)
	{
		diag_printf("Query RT_OID_VERSION_INFO has error!!!!!\n");
		WEB_printf(req, "Driver not found");
		return;
	}

	WEB_printf(req, "%s", version_number);
	return;
}

void CGI_get_wlan_rc_type(http_req *req)
{
	unsigned char rc_type = -1;

	if (OidQueryInformation(OID_802_11_NETWORK_TYPES_SUPPORTED, "ra0", &rc_type, sizeof(unsigned char)) < 0)
	{
		diag_printf("Query OID_802_11_NETWORK_TYPES_SUPPORTED has error!!!!!\n");
		WEB_printf(req, "Unknow type");
		return;
	}

	if (((int)rc_type == RFIC_2820) || ((int)rc_type == RFIC_2720) 
		|| ((int)rc_type == RFIC_3020) || ((int)rc_type == RFIC_2020)
		|| ((int)rc_type == RFIC_3021) || ((int)rc_type == RFIC_3022)
		|| ((int)rc_type == RFIC_3053) || ((int)rc_type == RFIC_3853))
	{
		WEB_printf(req, "%s", "2.4G Single Band");
	}
	else if (((int)rc_type == RFIC_2850) || ((int)rc_type == RFIC_2750) 
		|| ((int)rc_type == RFIC_3052) || ((int)rc_type == RFIC_2853)
		|| ((int)rc_type == RFIC_3053) || ((int)rc_type == RFIC_3853))
	{
		WEB_printf(req, "%s", "2.4G/5G Dual Band");
	}
	else
	{
		//WEB_printf(req, "%s", "Unknow Type");
		WEB_printf(req, "%s", "2.4G Single Band");
	}

	return;
}

void CGI_get_wlan_current_wireless_mode(http_req *req)
{
	char val[255];  	
	int  w_mode = 2561;

	val[0] = '\0';

	CFG_get_str(CFG_WLN_ModuleName, val);

	if (strcmp(val, "RT2860") == 0 || strcmp(val, "RT2870") == 0)  
		w_mode = 2860;
	else if (strcmp(val, "RT2561") == 0)
		w_mode = 2561;	
	else if (strcmp(val, "RT3090") == 0)
		w_mode = 3090;
	else if (strcmp(val, "RT3070") == 0)
		w_mode = 3070;
	else if (strcmp(val, "RT2070") == 0)
		w_mode = 2070;
	
	CFG_get_str(CFG_WLN_WirelessMode, val);

	if (val == "")
	{
		WEB_printf(req, "%s", "11b/g WiFi");
		return;
	}

	if (strcmp(val, "0") == 0)
	{
		WEB_printf(req, "%s", "11b/g WiFi");
	}
	else if (strcmp(val, "5") == 0)
	{
		WEB_printf(req, "%s", "11b/g Performance");
	}
	else if (strcmp(val, "1") == 0)
	{
		WEB_printf(req, "%s", "11b");
	}
	else if (strcmp(val, "2") == 0)
	{
		if (w_mode == 2860)
			WEB_printf(req, "%s", "11a");
		else
			WEB_printf(req, "%s", "11g Only");
	}
	else if (strcmp(val, "3") == 0)
		WEB_printf(req, "%s", "11a");
	else if (strcmp(val, "4") == 0)
		WEB_printf(req, "%s", "11g Only");
	else if (strcmp(val, "8") == 0)
		WEB_printf(req, "%s", "11a/n Mixed");
	else if (strcmp(val, "9") == 0)
		WEB_printf(req, "%s", "11b/g/n Mixed");
	else
		WEB_printf(req, "%s", "11b/g WiFi");

	return;
}

void CGI_get_wlan_current_channel(http_req *req)
{
	int  channel_index = 0;
	int  module_name = 2561;
	char val[255];  	

	val[0] = '\0';

	CFG_get_str(CFG_WLN_ModuleName, val);

	if (strcmp(val, "RT2860") == 0 || strcmp(val, "RT2870") == 0 )
		module_name = 2860;
	else if (strcmp(val, "RT3090") == 0)
		module_name = 3090;
	else if (strcmp(val, "RT3070") == 0)
		module_name = 3070;
	else if (strcmp(val, "RT2070") == 0)
		module_name = 2070;
	else
		module_name = 2561;

	CFG_get_str(CFG_WLN_AutoChannelSelect, val);

	if ((strcmp(val, "1") == 0) || ((strcmp(val, "2") == 0)))
	{
		WEB_printf(req, "%s", "Auto Select");
		return;
	}

	memset(val, 0, 255);
	CFG_get_str(CFG_WLN_WirelessMode, val);

	if (module_name == 2561)
	{
		if (strcmp(val, "3") == 0)
		{
			memset(val, 0, 255);
			CFG_get_str(CFG_WLN_Channel, val);
			channel_index = atoi(val);
			WEB_printf(req, "%d MHz(Channel %d)", 5000 + (5*channel_index), channel_index);
		}
		else
		{
			memset(val, 0, 255);
			CFG_get_str(CFG_WLN_Channel, val);

			if (val == "")
			{
				WEB_printf(req, "2452MHz (Channel %d)", 9);
				return;
			}

			channel_index = atoi(val);
			if (channel_index == 14)
				WEB_printf(req, "2484 MHz(Channel %d)", channel_index);
			else
				WEB_printf(req, "%d MHz(Channel %d)", 2407 + (5*channel_index), channel_index);
		}
	}
	else
	{
		if ((strcmp(val, "2") == 0) || (strcmp(val, "8") == 0))
		{
			memset(val, 0, 255);
			CFG_get_str(CFG_WLN_Channel, val);
			channel_index = atoi(val);
			WEB_printf(req, "%d MHz(Channel %d)", 5000 + (5*channel_index), channel_index);
		}
		else
		{
			memset(val, 0, 255);
			CFG_get_str(CFG_WLN_Channel, val);

			if (val == "")
			{
				WEB_printf(req, "2452MHz (Channel %d)", 9);
				return;
			}

			channel_index = atoi(val);
			if (channel_index == 14)
				WEB_printf(req, "2484 MHz(Channel %d)", channel_index);
			else
				WEB_printf(req, "%d MHz(Channel %d)", 2407 + (5*channel_index), channel_index);
		}
	}

	return;
}

void CGI_get_wlan_current_broadcast_ssid(http_req *req)
{	
	char val[255];  
	char	*tok = NULL;
	int HideSSIDTemp;

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_HideSSID, val);

	if (val == "")
	{
		WEB_printf(req, "%s", "");
		return;
	}

	tok = strtok(val,";");
	if (tok)
	HideSSIDTemp = atoi(tok);
	else
	{
		diag_printf("%s :%d  tok =NULL\n",__FUNCTION__,__LINE__);
		HideSSIDTemp=0;
	}
	
	if (HideSSIDTemp == 0)
		WEB_printf(req, "%s", "Enable");
	else if (HideSSIDTemp == 1)
		WEB_printf(req, "%s", "Disable");
		
	return;
}

void CGI_get_wlan_apclient_bssid(http_req *req)
{
	char val[255]={0};

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliBssid, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_auth(http_req *req)
{
	char val[255]={0};

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliAuthMode, val);
	
	WEB_printf( req, "%s",val );

	if (val == "")
		WEB_printf(req, "%s", "OPEN");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_encryp_type(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliEncrypType, val);
	
	WEB_printf( req, "%s",val );

	if (val == "")
		WEB_printf(req, "%s", "NONE");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wep_key_type(http_req *req)
{
	char val[255];  

	val[0]='\0';
	
	CFG_get_str(CFG_WLN_ApCliKey1Type, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "0");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wep_key1(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliKey1Str, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wep_key2(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliKey2Str, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wep_key3(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliKey3Str, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wep_key4(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliKey4Str, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_default_key(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliDefaultKeyID, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "1");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_wpapsk(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliWPAPSK, val);
	
	WEB_printf( req, "%s",val );
	
	if (val == "")
		WEB_printf(req, "%s", "");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_apclient_ssid(http_req *req)
{
	char val[255];  
	char str_buffer[193] = {0};

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_ApCliSsid, val);
	
	if (val == "")
		WEB_printf(req, "%s", "RalinkAPClient");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_wan_connection_mode(http_req *req)
{
	char val[255];  

	val[0] = '\0';
	
	CFG_get_str(CFG_WLN_wanConnectionMode, val);

	if (val == "")
		WEB_printf(req, "%s", "STATIC");
	else
		WEB_printf(req, "%s", val);

	return;
}

void CGI_get_wlan_station_associate_list(http_req *req)
{
	int s, idx = 0;
	struct iwreq iwr;
	RT_802_11_MAC_TABLE MacTab;
#if 0
	char *cck_mode[8] = {"1", "2", "5.5", "11", "1", "2", "5.5", "11"};
	char *ofdm_mode[8] = {"6", "9", "12", "18", "24", "36", "48", "54"};
	char *ht_mode[80]={"6.5" ,"13.0" ,"19.5" ,"26.0" ,"39.0" ,"52.0" ,"58.5" ,"65.0" ,"78" ,"N/A" , // BW=20, GI=800(long)
						"7.2" ,"14.4" ,"21.7" ,"28.9" ,"43.3" ,"57.8" ,"65.0" ,"72.2" ,"86.7" ,"N/A" , // BW=20, GI=400(short)
						"13.5" ,"27.0" ,"40.5" ,"54.0" ,"81.0" ,"108.0" ,"121.5" ,"135.0" ,"162" ,"180"  , // BW=40, GI=800(long)
						"15.0" ,"30.0" ,"45.0" ,"60.0" ,"90.0" ,"120.0" ,"135.0" ,"150.0" ,"180.0" ,"200.0" , // BW=40, GI=400(short)
						"29.3" ,"58.5" ,"87.8" ,"117" ,"175.5" ,"234" ,"263.3" ,"292.5" ,"351" ,"390"  , // BW=80, GI=800(long)
						"32.5" ,"65" ,"97.5" ,"130" ,"195" ,"260" ,"292.5" ,"325" ,"390" ,"433.3" , // BW=80, GI=400(short)
						"58.5" ,"117" ,"175.5" ,"234" ,"351" ,"468" ,"526.5" ,"585" ,"702" ,"780"  , // BW=160, GI=800(long)
						"65" ,"130" ,"195" ,"260" ,"390" ,"520" ,"585" ,"650" ,"780" ,"866.7"  // BW=160, GI=400(short)
						};
#endif
	int during=0;
	time_t now_time; 
	struct eth_drv_sc		*sc;
	cyg_netdevtab_entry_t	*t;
	int found = 0;
	unsigned long TXRate;

#ifdef CONFIG_WIRELESS	

	memset(&iwr, 0, sizeof(iwr));
	memset(&MacTab, 0, sizeof(RT_802_11_MAC_TABLE));
	//srncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &MacTab;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}

	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL fail!!\n");
			return; 
		}
#endif	
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL fail!!\n");
			return; 
		}
#endif

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		return; 
	} 

	for (idx = 0; idx < MacTab.Num; idx++)
	{
		WEB_printf(req, "<tr><td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		WEB_printf(req, "<input type=radio name=sta_mac value=1 onClick=\"del_associate_onClick('%02X:%02X:%02X:%02X:%02X:%02X');\"></td>", MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
																									MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
																									MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);
		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		WEB_printf(req, "%02X:%02X:%02X:%02X:%02X:%02X</td>",	MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
															MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
															MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);

		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");

		if (MacTab.Entry[idx].TxRate.field.MODE == MODE_CCK)
			WEB_printf(req, "CCK</td>");
		else if (MacTab.Entry[idx].TxRate.field.MODE == MODE_OFDM)
			WEB_printf(req, "OFDM</td>");
		else if (MacTab.Entry[idx].TxRate.field.MODE == MODE_HTMIX)
			WEB_printf(req, "HT Mixed</td>");
		else if (MacTab.Entry[idx].TxRate.field.MODE == MODE_HTGREENFIELD)
			WEB_printf(req, "HT GreenField</td>");


		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		WEB_printf(req, "%d</td>", MacTab.Entry[idx].Aid);

		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		if ( MacTab.Entry[idx].Psm == 1)
			WEB_printf(req, "YES</td>");
		else
			WEB_printf(req, "NO</td>");

		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		//WEB_printf(req, "%d</td>", (int)MacTab.Entry[idx].MimoPs);
		if (MacTab.Entry[idx].TxRate.field.MODE >= MODE_HTMIX)
		{
			if ((int)MacTab.Entry[idx].MimoPs == 0)
				WEB_printf(req, "STATIC</td>");
			else if ((int)MacTab.Entry[idx].MimoPs == 1)
				WEB_printf(req, "DYNAMIC</td>");
			else if ((int)MacTab.Entry[idx].MimoPs == 3)
				WEB_printf(req, "NO_LIMIT</td>");
		}
		else
		{
			WEB_printf(req, "NONE</td>");
		}

		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		if (MacTab.Entry[idx].TxRate.field.MODE >= MODE_HTMIX)
		{
			if (MacTab.Entry[idx].TxRate.field.BW == 0)
				WEB_printf(req, "20</td>");
			else if (MacTab.Entry[idx].TxRate.field.BW == 1)
				WEB_printf(req, "40</td>");
			else  if (MacTab.Entry[idx].TxRate.field.BW == 2)
			WEB_printf(req, "80</td>");
			else if (MacTab.Entry[idx].TxRate.field.BW == 3) 
			WEB_printf(req, "160</td>");

		}
		else
		{
			WEB_printf(req, "NONE</td>");
		}
		
		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
#if 0
		
		WEB_printf(req, "<td align=\"center\" bgcolor=\"#FFFFFF\" nowrap>");
		if (MacTab.Entry[idx].TxRate.field.MODE >= MODE_HTMIX)
		{
			if (MacTab.Entry[idx].TxRate.field.BW == 0)
			{
				if (MacTab.Entry[idx].TxRate.field.ShortGI == 0)
				{
					switch (MacTab.Entry[idx].TxRate.field.MCS)
					{
						case 0: 	WEB_printf(req, "%s Mbps</td>", ht_mode[0]);	break;
						case 1: 	WEB_printf(req, "%s Mbps</td>", ht_mode[1]);	break;
						case 2: 	WEB_printf(req, "%s Mbps</td>", ht_mode[2]);	break;
						case 3: 	WEB_printf(req, "%s Mbps</td>", ht_mode[3]);	break;
						case 4: 	WEB_printf(req, "%s Mbps</td>", ht_mode[4]);	break;
						case 5: 	WEB_printf(req, "%s Mbps</td>", ht_mode[5]);	break;
						case 6: 	WEB_printf(req, "%s Mbps</td>", ht_mode[6]);	break;
						case 7: 	WEB_printf(req, "%s Mbps</td>", ht_mode[7]);	break;
						case 8: 	WEB_printf(req, "%s Mbps</td>", ht_mode[8]);	break;
						case 9: 	WEB_printf(req, "%s Mbps</td>", ht_mode[9]);	break;
						case 10:		WEB_printf(req, "%s Mbps</td>", ht_mode[10]);	break;
						case 11:		WEB_printf(req, "%s Mbps</td>", ht_mode[11]);	break;
						case 12:		WEB_printf(req, "%s Mbps</td>", ht_mode[12]);	break;
						case 13:		WEB_printf(req, "%s Mbps</td>", ht_mode[13]);	break;
						case 14:		WEB_printf(req, "%s Mbps</td>", ht_mode[14]);	break;
						case 15:		WEB_printf(req, "%s Mbps</td>", ht_mode[15]);	break;
						default:		WEB_printf(req, "Auto</td>");	break;
					}
				}
				else if (MacTab.Entry[idx].TxRate.field.ShortGI == 1)
				{
					switch (MacTab.Entry[idx].TxRate.field.MCS)
					{
						case 0: 	WEB_printf(req, "%s Mbps</td>", ht_mode[16]);	break;
						case 1: 	WEB_printf(req, "%s Mbps</td>", ht_mode[17]);	break;
						case 2: 	WEB_printf(req, "%s Mbps</td>", ht_mode[18]);	break;
						case 3: 	WEB_printf(req, "%s Mbps</td>", ht_mode[19]);	break;
						case 4: 	WEB_printf(req, "%s Mbps</td>", ht_mode[20]);	break;
						case 5: 	WEB_printf(req, "%s Mbps</td>", ht_mode[21]);	break;
						case 6: 	WEB_printf(req, "%s Mbps</td>", ht_mode[22]);	break;
						case 7: 	WEB_printf(req, "%s Mbps</td>", ht_mode[23]);	break;
						case 8: 	WEB_printf(req, "%s Mbps</td>", ht_mode[24]);	break;
						case 9: 	WEB_printf(req, "%s Mbps</td>", ht_mode[25]);	break;
						case 10:		WEB_printf(req, "%s Mbps</td>", ht_mode[26]);	break;
						case 11:		WEB_printf(req, "%s Mbps</td>", ht_mode[27]);	break;
						case 12:		WEB_printf(req, "%s Mbps</td>", ht_mode[28]);	break;
						case 13:		WEB_printf(req, "%s Mbps</td>", ht_mode[29]);	break;
						case 14:		WEB_printf(req, "%s Mbps</td>", ht_mode[30]);	break;
						case 15:		WEB_printf(req, "%s Mbps</td>", ht_mode[31]);	break;
						default:		WEB_printf(req, "Auto</td>");	break;
					}
				}
			}
			else if (MacTab.Entry[idx].TxRate.field.BW == 1)
			{
				if (MacTab.Entry[idx].TxRate.field.ShortGI == 0)
				{
					switch (MacTab.Entry[idx].TxRate.field.MCS)
					{
						case 0: 	WEB_printf(req, "%s Mbps</td>", ht_mode[32]);	break;
						case 1: 	WEB_printf(req, "%s Mbps</td>", ht_mode[33]);	break;
						case 2: 	WEB_printf(req, "%s Mbps</td>", ht_mode[34]);	break;
						case 3: 	WEB_printf(req, "%s Mbps</td>", ht_mode[35]);	break;
						case 4: 	WEB_printf(req, "%s Mbps</td>", ht_mode[36]);	break;
						case 5: 	WEB_printf(req, "%s Mbps</td>", ht_mode[37]);	break;
						case 6: 	WEB_printf(req, "%s Mbps</td>", ht_mode[38]);	break;
						case 7: 	WEB_printf(req, "%s Mbps</td>", ht_mode[39]);	break;
						case 8: 	WEB_printf(req, "%s Mbps</td>", ht_mode[40]);	break;
						case 9: 	WEB_printf(req, "%s Mbps</td>", ht_mode[41]);	break;
						case 10:		WEB_printf(req, "%s Mbps</td>", ht_mode[42]);	break;
						case 11:		WEB_printf(req, "%s Mbps</td>", ht_mode[43]);	break;
						case 12:		WEB_printf(req, "%s Mbps</td>", ht_mode[44]);	break;
						case 13:		WEB_printf(req, "%s Mbps</td>", ht_mode[45]);	break;
						case 14:		WEB_printf(req, "%s Mbps</td>", ht_mode[46]);	break;
						case 15:		WEB_printf(req, "%s Mbps</td>", ht_mode[47]);	break;
						default:		WEB_printf(req, "Auto</td>");	break;
					}
				}
				else if (MacTab.Entry[idx].TxRate.field.ShortGI == 1)
				{
					switch (MacTab.Entry[idx].TxRate.field.MCS)
					{
						case 0: 	WEB_printf(req, "%s Mbps</td>", ht_mode[50]);	break;
						case 1: 	WEB_printf(req, "%s Mbps</td>", ht_mode[51]);	break;
						case 2: 	WEB_printf(req, "%s Mbps</td>", ht_mode[52]);	break;
						case 3: 	WEB_printf(req, "%s Mbps</td>", ht_mode[53]);	break;
						case 4: 	WEB_printf(req, "%s Mbps</td>", ht_mode[54]);	break;
						case 5: 	WEB_printf(req, "%s Mbps</td>", ht_mode[55]);	break;
						case 6: 	WEB_printf(req, "%s Mbps</td>", ht_mode[56]);	break;
						case 7: 	WEB_printf(req, "%s Mbps</td>", ht_mode[57]);	break;
						case 8: 	WEB_printf(req, "%s Mbps</td>", ht_mode[58]);	break;
						case 9: 	WEB_printf(req, "%s Mbps</td>", ht_mode[59]);	break;
						case 10:		WEB_printf(req, "%s Mbps</td>", ht_mode[60]);	break;
						case 11:		WEB_printf(req, "%s Mbps</td>", ht_mode[61]);	break;
						case 12:		WEB_printf(req, "%s Mbps</td>", ht_mode[62]);	break;
						case 13:		WEB_printf(req, "%s Mbps</td>", ht_mode[63]);	break;
						case 14:		WEB_printf(req, "%s Mbps</td>", ht_mode[64]);	break;
						case 15:		WEB_printf(req, "%s Mbps</td>", ht_mode[65]);	break;
						default:		WEB_printf(req, "Auto</td>");	break;
					}
				}
			}
		}
		else if (MacTab.Entry[idx].TxRate.field.MODE == MODE_OFDM)
		{
			switch (MacTab.Entry[idx].TxRate.field.MCS)
			{
				case 0: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[0]);	break;
				case 1: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[1]);	break;
				case 2: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[2]);	break;
				case 3: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[3]);	break;
				case 4: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[4]);	break;
				case 5: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[5]);	break;
				case 6: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[6]);	break;
				case 7: 	WEB_printf(req, "%s Mbps</td>", ofdm_mode[7]);	break;
				default:		WEB_printf(req, "Auto</td>");	break;
			}
		}
		else
		{
			switch (MacTab.Entry[idx].TxRate.field.MCS)
			{
				case 0: 	WEB_printf(req, "%s Mbps</td>", cck_mode[0]);	break;
				case 1: 	WEB_printf(req, "%s Mbps</td>", cck_mode[1]);	break;
				case 2: 	WEB_printf(req, "%s Mbps</td>", cck_mode[2]);	break;
				case 3: 	WEB_printf(req, "%s Mbps</td>", cck_mode[3]);	break;
				case 8: 	WEB_printf(req, "%s Mbps</td>", cck_mode[4]);	break;
				case 9: 	WEB_printf(req, "%s Mbps</td>", cck_mode[5]);	break;
				case 10:		WEB_printf(req, "%s Mbps</td>", cck_mode[6]);	break;
				case 11:		WEB_printf(req, "%s Mbps</td>", cck_mode[7]);	break;
				default:		WEB_printf(req, "Auto</td>");	break;
			}
		}
		WEB_printf(req, "</tr>");
#else		
	  getRate(MacTab.Entry[idx].TxRate, &TXRate);
	  WEB_printf(req, "%d Mbps</td>", TXRate);
	  WEB_printf(req, "</tr>");
#endif

   }

   return;
#else
	diag_printf("Wireless IF does not init.\n");
	return;
#endif
}


void getWlanMacAddress(char *ifname, char *if_hw)
{
	struct ifreq ifr;
	char *ptr;
	int skfd;
	
	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		diag_printf("Open socket fail!!!!!\n");
		return;
	}

	/* hardware address */
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) 
	{
		diag_printf("SIOCGIFHWADDR fail!!!!!\n");
		close(skfd);
		return;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
	(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	(void) close(skfd);
}

void CGI_get_wlan_current_mac_address(http_req *req)
{
	memset(if_hw, 0, 18);
	
	getWlanMacAddress("ra0", if_hw);
	
	WEB_printf(req, "%s", if_hw);

	return;
}

char * CGI_get_wlan_tx_rx_count(void)
{
	struct iwreq	iwr;
	NDIS_802_11_STATISTICS pStatistics;
	struct eth_drv_sc 		*sc;
	cyg_netdevtab_entry_t 	*t;
	int found = 0;
	int i;

#ifdef CONFIG_WIRELESS
	memset(&pStatistics, 0, sizeof(pStatistics));
	memset(wlan_tx_rx_count, 0, 100);
	memset(&iwr, 0, sizeof(iwr));
	
	iwr.u.data.pointer = (caddr_t) &pStatistics;
	iwr.u.data.flags = OID_802_11_STATISTICS;
	
	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;

		if (strcmp(sc->dev_name, "ra0") == 0) 
		{
			found = 1;
			break;
		}
	}
	
	if (found == 1)
	{
#ifdef CONFIG_AP_SUPPORT	
		if(rt28xx_ap_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			return NULL;	
		}
#endif		
#ifdef CONFIG_STA_SUPPORT	
		if(rt28xx_sta_ioctl(sc, RT_PRIV_IOCTL, (caddr_t)&iwr) < 0)
		{
			diag_printf("RT_PRIV_IOCTL sock fail!!\n");
			return NULL;	
		}
#endif

	}
	else
	{
		diag_printf("Can't find ra0!!\n");
		return NULL;	
	}

	sprintf(wlan_tx_rx_count, "%lld\n%lld\n", pStatistics.ReceivedFragmentCount.QuadPart, pStatistics.TransmittedFragmentCount.QuadPart);
	return &wlan_tx_rx_count[0];
#else
	diag_printf("Wireless IF does not init.\n");
	return NULL;
#endif
}

void CGI_get_wlan_mcs_list(http_req *req)
{
	int idx;

	for (idx = 0; idx < SYS_TX_ANTENNA*8; idx++)
	{
		WEB_printf(req, "<option value = %d>%d</option>\n", idx, idx);		
	}

	if (SYS_TX_ANTENNA != 1)
		WEB_printf(req, "<option value = %d>%d</option>\n", 32, 32);

	WEB_printf(req, "<option value = %d selected>%s</option>\n", 33, "Auto");

	return;
}

void CGI_get_wlan_tx_stream_list(http_req *req)
{
	int idx;

	for (idx = 1; idx < SYS_TX_ANTENNA + 1; idx++)
	{
		WEB_printf(req, "<option value = %d>%d</option>\n", idx, idx);
	}
	
	return;	
}

void CGI_get_wlan_rx_stream_list(http_req *req)
{
	int idx;

	for (idx = 1; idx < SYS_RX_ANTENNA + 1; idx++)
	{
		WEB_printf(req, "<option value = %d>%d</option>\n", idx, idx);
	}
	
	return;	
}

void CGI_get_wlan_antenna_type(http_req *req)
{
	WEB_printf(req, "%d", SYS_TX_ANTENNA);

	return;
}


void CGI_get_ping_test(http_req *req,char *ip)
{
	int value=-1;
	int dsst;

	if ((dsst = nstr2ip(ip)) != 0)
		value=net_ping_test(dsst, 1, 3000);
	WEB_printf( req, "%d and ip=%s and dsst=%d", value,ip,dsst);
}

void CGI_get_ping_result(http_req *req)
{
	char val[255];  	

	if (PING_Result == "" || PING_Result[0]=='\0')
	{
		WEB_printf(req, "%s", "");
	}
	else
	{

		WEB_printf(req, "%s", PING_Result);
	}

	PING_Result[0] = '\0';

	return;
}

#define SIOCIWFIRSTPRIV							0x8BE0

#define RTPRIV_IOCTL_STATISTICS (SIOCIWFIRSTPRIV + 0x09)
#define RTPRIV_IOCTL_GSITESURVEY (SIOCIWFIRSTPRIV + 0x0D)
#define RTPRIV_IOCTL_GET_MAC_TABLE (SIOCIWFIRSTPRIV + 0x0F)
#define RTPRIV_IOCTL_FLAG_UI 0x0001	/* Notidy this private cmd send by UI. */
#define RTPRIV_IOCTL_FLAG_NODUMPMSG 0x0002	/* Notify driver cannot dump msg to stdio/stdout when run this private ioctl cmd */
#define RTPRIV_IOCTL_FLAG_NOSPACE 0x0004	/* Notify driver didn't need copy msg to caller due to the caller didn't reserve space for this cmd */

void CGI_get_scan_result(http_req *req)
{
//自动选择信道
#ifdef CONFIG_WIRELESS
	extern int CmdIwpriv(int argc, char *argv[]);
	{	char *string[]={
		"ra0",
		"set",
		"SiteSurvey="
		};
		CmdIwpriv(3,string);
		cyg_thread_delay(3);
	}
#endif /* CONFIG_WIRELESS */
	//diag_printf("[SCAN]After set siteSurvey\n");
	int cmd;
	struct iwreq param;
	cyg_netdevtab_entry_t *t;
	struct eth_drv_sc *sc;
	int found = 0;

	cmd = RTPRIV_IOCTL_GSITESURVEY;
	param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++)
	{
		sc = (struct eth_drv_sc *)t->device_instance;
		if (strcmp(sc->dev_name, "ra0") == 0) {
			found =1;
			break;
		}
	}
	if ( found == 1 )
	{
		char *TempString=NULL;
		int original_length = 0;

		//diag_printf("[SCAN]Before malloc...\n");
		TempString = malloc(10240);//14*1024
		//diag_printf("[SCAN]After malloc...\n");
		if(TempString==NULL)
		{
			diag_printf("Not enough memory for CmdIwpriv!\n");
			return;
		}
		TempString[0] = '\0';

		param.u.data.pointer = &TempString[0];			
		param.u.data.length = strlen(TempString);
		//diag_printf("cmd:%s [%d][%d]",TempString,param.u.data.length,original_length);
		rt28xx_ap_ioctl(sc, cmd, (caddr_t)&param);
		//diag_printf("[SCAN]After ap ioctl...\n");
		if (param.u.data.length != original_length)
		{
			TempString[param.u.data.length] = '\0';
			if(cmd == RTPRIV_IOCTL_GSITESURVEY)
			{
				diag_printf("[SCAN]Sucess,info len=%d\n",strlen(TempString));
				//int i=0;
				//diag_printf("=>length:%d\n",param.u.data.length);
				//for(i=0; i<param.u.data.length; i++)
				//	diag_printf("%c",TempString[i]);//终端显示调试信息
			}
			//diag_printf("%s", TempString);
		}
		//拆解字符串
		//char *result0 = NULL;
		//result0 = malloc(1025);
		//strncpy(result0,TempString,1024);
		//result0[1024] = '\0';
		//WEB_long_printf(req, "%s", "1111111111111111111111111111111111111111");
		WEB_long_printf(req, "%s", TempString);
		free(TempString);
	}
}

void CGI_get_conn_stat(http_req *req)
{
#ifdef CONFIG_WIRELESS
	extern int CmdIwpriv(int argc, char *argv[]);
	{	char *string[]={
		"apcli0",
		"show",
		"connStatus"
		};
		CmdIwpriv(3,string);
		cyg_thread_delay(3);
	}
#endif /* CONFIG_WIRELESS */
	extern char *connectStat;

	WEB_printf( req, "%s",connectStat);
	diag_printf("connectStat:%s", connectStat);
}

/* Printable ASCII, no spaces or colons: Basic auth splits user:password. */
static int admin_ui_text(const char *s, int min, int max, int allow_colon)
{
    int n = 0;
    if (!s) return 0;
    for (; *s; s++, n++)
        if (*s < 33 || *s > 126 || (!allow_colon && *s == ':')) return 0;
    return n >= min && n <= max;
}

void CGI_admin_apply(http_req *req)
{
    char cur[256], olduser[256], oldpass[256];
    char *user, *pass, *confirm, *current;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    user = WEB_query(req,"USER"); pass = WEB_query(req,"PASSWORD");
    confirm = WEB_query(req,"CONFIRM"); current = WEB_query(req,"CURRENT");
    if (!pass) pass = "";
    if (!confirm) confirm = "";
    if (!admin_ui_text(user,1,31,0)) { WEB_printf(req,"ERROR: user name must be 1-31 printable ASCII characters, without spaces or colons"); return; }
    if (*pass && !admin_ui_text(pass,8,63,1)) { WEB_printf(req,"ERROR: password must be 8-63 printable ASCII characters, without spaces"); return; }
    if (strcmp(pass,confirm)) { WEB_printf(req,"ERROR: passwords do not match"); return; }
    cur[0] = '\0';
    CFG_get_str(CFG_SYS_ADMPASS, cur);
    if (cur[0] && (!current || strcmp(current,cur))) { WEB_printf(req,"ERROR: current password is incorrect"); return; }
    CFG_get_str(CFG_SYS_USERS, olduser);
    strcpy(oldpass, cur);
    if (CFG_set_str(CFG_SYS_USERS,user) < 0 || CFG_set_str(CFG_SYS_ADMPASS,pass) < 0) {
        CFG_set_str(CFG_SYS_USERS,olduser); CFG_set_str(CFG_SYS_ADMPASS,oldpass);
        CFG_commit(CFG_NO_EVENT);
        WEB_printf(req,"ERROR: settings could not be applied"); return;
    }
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    {
        /* Reload HTTP credentials; telnet reads the configuration directly. */
        extern int HTTPD_reconf;
        HTTPD_reconf = 1;
    }
    WEB_printf(req,"OK");
}

/* Host name or IPv4 address: letters, numbers, dots, hyphens; 1-63. */
static int net_ui_host(const char *s)
{
    int n = 0;
    if (!s) return 0;
    for (; *s; s++, n++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '.' || *s == '-')) return 0;
    return n >= 1 && n <= 63;
}

/* WireGuard client. Saving restarts the device; the device key
 * is generated by the firmware and never accepted or returned here. */
static int wg_ui_cidr(const char *s)
{
    int dots = 0, num = 0, val = 0, bits;
    const char *p;
    if (!s || !*s) return 0;
    for (p = s; *p && *p != '/'; p++) {
        if (*p == '.') { if (!num || ++dots > 3) return 0; num = 0; val = 0; continue; }
        if (*p < '0' || *p > '9') return 0;
        val = val * 10 + (*p - '0');
        if (++num > 3 || val > 255) return 0;
    }
    if (dots != 3 || !num || *p != '/') return 0;
    bits = atoi(p + 1);
    if (!p[1] || strlen(p + 1) > 2 || bits < 8 || bits > 32) return 0;
    for (p++; *p; p++) if (*p < '0' || *p > '9') return 0;
    return 1;
}

void CGI_wg_apply(http_req *req)
{
    char cur[256], *en, *addr, *peer, *host, *port, *ka, *psk, *dns, *end, *tr, *wpath, *wname, *wkey, *wd;
    unsigned char tmp[32];
    long p, k;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    en = WEB_query(req,"ENABLED"); addr = WEB_query(req,"ADDRESS"); peer = WEB_query(req,"PEER_PUBLIC_KEY");
    host = WEB_query(req,"ENDPOINT"); port = WEB_query(req,"PORT"); ka = WEB_query(req,"KEEPALIVE");
    psk = WEB_query(req,"PRESHARED_KEY");
    dns = WEB_query(req,"DNS");
    wd = WEB_query(req,"WATCHDOG");
    if (wd && *wd) {
        long w = strtol(wd, &end, 10);
        if (*end || (w != 0 && (w < 5 || w > 1440))) { WEB_printf(req,"ERROR: WATCHDOG must be 0 (off) or 5-1440 minutes"); return; }
    }
    tr = WEB_query(req,"TRANSPORT"); wpath = WEB_query(req,"WSS_PATH"); wname = WEB_query(req,"WSS_NAME"); wkey = WEB_query(req,"WSS_KEY");
    if (tr && strcmp(tr,"udp") && strcmp(tr,"wss")) { WEB_printf(req,"ERROR: TRANSPORT must be udp or wss"); return; }
    if (wpath && *wpath) {
        const char *c;
        if (wpath[0] != '/' || strlen(wpath) > 95) { WEB_printf(req,"ERROR: WSS path must start with / (at most 95 characters)"); return; }
        for (c = wpath; *c; c++) if (*c <= ' ' || *c > '~') { WEB_printf(req,"ERROR: WSS path must be printable ASCII without spaces"); return; }
    }
    if (wname && *wname && !net_ui_host(wname)) { WEB_printf(req,"ERROR: WSS TLS name must be a host name"); return; }
    if (wkey && *wkey && (strlen(wkey) != 64 || strspn(wkey, "0123456789abcdefABCDEF") != 64)) { WEB_printf(req,"ERROR: WSS key must be the server's Ed25519 public key in hex (64 characters)"); return; }
    if (dns && *dns) {
        struct in_addr a;
        if (!inet_aton(dns, &a) || !a.s_addr || a.s_addr == 0xffffffffUL) { WEB_printf(req,"ERROR: DNS must be an IPv4 address, for example 1.1.1.1"); return; }
    }
    if (!en || (strcmp(en,"0") && strcmp(en,"1"))) { WEB_printf(req,"ERROR: ENABLED must be 0 or 1"); return; }
    if (!addr) addr = "";
    if (!peer) peer = "";
    if (!host) host = "";
    if (*addr && !wg_ui_cidr(addr)) { WEB_printf(req,"ERROR: address must be IPv4/prefix, for example 10.8.0.30/24"); return; }
    if (*peer && wg_b64_decode32(tmp, peer)) { WEB_printf(req,"ERROR: peer public key must be a WireGuard key (44 base64 characters)"); return; }
    if (*host && !net_ui_host(host)) { WEB_printf(req,"ERROR: endpoint must be a host name or IPv4 address"); return; }
    p = port ? strtol(port,&end,10) : 0;
    if (!port || *end || p < 1 || p > 65535) { WEB_printf(req,"ERROR: port must be 1-65535"); return; }
    k = ka ? strtol(ka,&end,10) : 25;
    if ((ka && *end) || k < 0 || k > 3600) { WEB_printf(req,"ERROR: keepalive must be 0-3600 seconds"); return; }
    if (psk && *psk && strcmp(psk,"keep") && wg_b64_decode32(tmp, psk)) { WEB_printf(req,"ERROR: preshared key must be 44 base64 characters, empty, or keep"); return; }
    if (!strcmp(en,"1")) {
        if (!*addr || !*peer || !*host) { WEB_printf(req,"ERROR: address, peer public key and endpoint are required to enable WireGuard"); return; }
        cur[0] = '\0';
        CFG_get_str(CFG_SYS_ADMPASS, cur);
        if (!cur[0]) { WEB_printf(req,"ERROR: set an admin password before enabling WireGuard"); return; }
        cur[0] = '\0';
        if (tr) strcpy(cur, tr); else CFG_get_str(CFG_SYS_WG_TRANSPORT, cur);
        if (!strcmp(cur,"wss")) {
            cur[0] = '\0';
            if (wkey) strcpy(cur, wkey); else CFG_get_str(CFG_SYS_WG_WSS_KEY, cur);
            if (!cur[0]) { WEB_printf(req,"ERROR: WSS needs the server's Ed25519 key"); return; }
            cur[0] = '\0';
            if (wpath) strcpy(cur, wpath); else CFG_get_str(CFG_SYS_WG_WSS_PATH, cur);
            if (!cur[0]) { WEB_printf(req,"ERROR: WSS needs a path"); return; }
        }
    }
    sprintf(cur, "%ld", k);
    if (CFG_set_str(CFG_SYS_WG_EN,en) < 0 || CFG_set_str(CFG_SYS_WG_ADDR,addr) < 0 ||
        CFG_set_str(CFG_SYS_WG_PEER,peer) < 0 || CFG_set_str(CFG_SYS_WG_HOST,host) < 0 ||
        CFG_set_str(CFG_SYS_WG_PORT,port) < 0 || CFG_set_str(CFG_SYS_WG_KEEPALIVE,cur) < 0 ||
        (psk && strcmp(psk,"keep") && CFG_set_str(CFG_SYS_WG_PSK,psk) < 0) ||
        (dns && CFG_set_str(CFG_SYS_WG_DNS, *dns ? dns : "1.1.1.1") < 0) ||
        (wd && CFG_set_str(CFG_SYS_WG_WATCHDOG, *wd ? wd : "0") < 0) ||
        (tr && CFG_set_str(CFG_SYS_WG_TRANSPORT,tr) < 0) || (wpath && CFG_set_str(CFG_SYS_WG_WSS_PATH,wpath) < 0) ||
        (wname && CFG_set_str(CFG_SYS_WG_WSS_NAME,wname) < 0) || (wkey && CFG_set_str(CFG_SYS_WG_WSS_KEY,wkey) < 0)) { WEB_printf(req,"ERROR: settings could not be applied"); return; }
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    WEB_printf(req,"OK");
    mon_snd_cmd(MON_CMD_REBOOT);
}

/* Startup script: COMMAND1..COMMAND8, console commands run at the next boot.
 * Saved without restarting; absent fields keep their stored line. */
void CGI_startup_apply(http_req *req)
{
    static char lines[CLI_BOOT_LINES][204];
    char key[12], *v[CLI_BOOT_LINES], *script;
    int n, i;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    script = WEB_query(req, "SCRIPT");
    if (script) {
        /* the whole script, one command per line (\n or \r\n); missing lines are cleared */
        const char *p = script;
        for (n = 0; n < CLI_BOOT_LINES; n++) { lines[n][0] = 0; v[n] = lines[n]; }
        for (n = 0; *p; n++) {
            const char *e = p;
            size_t len;
            while (*e && *e != '\n') e++;
            len = e - p;
            if (len && p[len - 1] == '\r') len--;
            if (n >= CLI_BOOT_LINES) {
                /* trailing empty lines are fine, more commands are not */
                if (len) { WEB_printf(req,"ERROR: the script has more than %d lines", CLI_BOOT_LINES); return; }
            } else {
                if (len > 200) { WEB_printf(req,"ERROR: line %d is longer than 200 characters", n + 1); return; }
                memcpy(lines[n], p, len);
                lines[n][len] = 0;
            }
            p = *e ? e + 1 : e;
        }
    } else {
        for (n = 0; n < CLI_BOOT_LINES; n++) {
            sprintf(key, "COMMAND%d", n + 1);
            v[n] = WEB_query(req, key);
        }
    }
    for (n = 0; n < CLI_BOOT_LINES; n++) {
        if (!v[n]) continue;
        if (strlen(v[n]) > 200) { WEB_printf(req,"ERROR: COMMAND%d is longer than 200 characters", n + 1); return; }
        for (i = 0; v[n][i]; i++)
            if ((unsigned char)v[n][i] < 32 || (unsigned char)v[n][i] > 126) { WEB_printf(req,"ERROR: line %d must be printable ASCII", n + 1); return; }
    }
    for (n = 0; n < CLI_BOOT_LINES; n++)
        if (v[n] && CFG_set_str(CLI_boot_ids[n], v[n]) < 0) { WEB_printf(req,"ERROR: settings could not be applied"); return; }
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    WEB_printf(req,"OK");
}

/* ---- Wi-Fi networks 1..7 (SSID1..SSID7 on ra0..ra6; the radio has 8 beacons
 * and a Wi-Fi uplink takes one). Network 1 is the main one; 2..7 are bridged
 * with it or, in router mode, routed (init/net_extra.c). */
#define NET_MAX 7
static const int net_ssid_ids[NET_MAX] = { CFG_WLN_SSID1, CFG_WLN_SSID2, CFG_WLN_SSID3, CFG_WLN_SSID4, CFG_WLN_SSID5, CFG_WLN_SSID6, CFG_WLN_SSID7 };
static const int net_key_ids[NET_MAX] = { CFG_WLN_WPAPSK1, CFG_WLN_WPAPSK2, CFG_WLN_WPAPSK3, CFG_WLN_WPAPSK4, CFG_WLN_WPAPSK5, CFG_WLN_WPAPSK6, CFG_WLN_WPAPSK7 };
static const int net_ip_ids[NET_MAX - 1] = { CFG_SYS_NET2_IP, CFG_SYS_NET3_IP, CFG_SYS_NET4_IP, CFG_SYS_NET5_IP, CFG_SYS_NET6_IP, CFG_SYS_NET7_IP };
static const int net_reach_ids[NET_MAX - 1] = { CFG_SYS_NET2_REACH, CFG_SYS_NET3_REACH, CFG_SYS_NET4_REACH, CFG_SYS_NET5_REACH, CFG_SYS_NET6_REACH, CFG_SYS_NET7_REACH };
static const int net_inet_ids[NET_MAX - 1] = { CFG_SYS_NET2_INTERNET, CFG_SYS_NET3_INTERNET, CFG_SYS_NET4_INTERNET, CFG_SYS_NET5_INTERNET, CFG_SYS_NET6_INTERNET, CFG_SYS_NET7_INTERNET };
static const int net_via_ids[NET_MAX - 1] = { CFG_SYS_NET2_VIA, CFG_SYS_NET3_VIA, CFG_SYS_NET4_VIA, CFG_SYS_NET5_VIA, CFG_SYS_NET6_VIA, CFG_SYS_NET7_VIA };

/* item idx of a ';' list into out ("" when missing) */
static void net_list_get(char *out, const char *list, int idx)
{
    const char *p = list, *e;
    while (idx-- > 0 && p) { p = strchr(p, ';'); if (p) p++; }
    if (!p) { out[0] = 0; return; }
    e = strchr(p, ';');
    if (!e) e = p + strlen(p);
    memcpy(out, p, e - p);
    out[e - p] = 0;
}

/* list with item idx replaced; padded to NET_MAX items with pad */
static void net_list_set(char *out, const char *list, int idx, const char *val, const char *pad)
{
    char item[64];
    int i;
    out[0] = 0;
    for (i = 0; i < NET_MAX; i++) {
        if (i) strcat(out, ";");
        if (i == idx) { strcat(out, val); continue; }
        net_list_get(item, list, i);
        strcat(out, item[0] ? item : pad);
    }
}

static int net_reach_ok(const char *s)
{
    char buf[80], *t, *save;
    if (strlen(s) >= sizeof buf) return 0;
    strcpy(buf, s);
    for (t = strtok_r(buf, ",", &save); t; t = strtok_r(0, ",", &save))
        if (strcmp(t,"device") && strcmp(t,"lan") && strcmp(t,"wg") &&
            !(t[0] == 'n' && t[1] == 'e' && t[2] == 't' && t[3] >= '1' && t[3] <= '0' + NET_MAX && !t[4])) return 0;
    return 1;
}

static void net_state(http_req *req)
{
    char val[256], list[256], item[64];
    int n, count;
    val[0] = 0; CFG_get_str(CFG_WLN_BssidNum, val);
    count = atoi(val);
    if (wifi_ui_is_router() || wifi_ui_is_gateway()) {
        char ip[20], mask[20];
        unsigned long m;
        int bits = 0;
        CFG_get_str(CFG_LAN_IP, ip);
        CFG_get_str(CFG_LAN_MSK, mask);
        m = ntohl(inet_addr(mask));
        while (m & 0x80000000UL) { bits++; m <<= 1; }
        CFG_get_str(CFG_LAN_DHCPD_EN, val);
        WEB_printf(req, ",\"lan\":{\"address\":\"%s/%d\",\"dhcp\":%d}", ip, bits, atoi(val) == 1);
    }
    if (wifi_ui_is_gateway()) {
        struct in_addr w;
        w.s_addr = SYS_wan_ip;
        /* address the Ethernet WAN got by DHCP; empty until it has one */
        WEB_printf(req, ",\"wan_address\":\"%s\"", SYS_wan_ip ? inet_ntoa(w) : "");
    }
    {
        /* unified view: where the Internet comes from and where Ethernet is */
        int op;
        val[0] = 0; CFG_get_str(CFG_SYS_OPMODE, val); op = atoi(val);
        val[0] = 0; CFG_get_str(CFG_WLN_ApCliEnable, val);
        WEB_printf(req, ",\"uplink_type\":\"%s\",\"ethernet\":\"%s\"", atoi(val) ? "wifi" : "cable",
                   op == 1 ? "wan" : op == 2 ? "net1" : "internet");
    }
    WEB_printf(req, ",\"networks\":[");
    for (n = 0; n < NET_MAX; n++) {
        val[0] = 0; CFG_get_str(net_ssid_ids[n], val);
        WEB_printf(req, "%s{\"id\":%d,\"enabled\":%d,\"ssid\":", n ? "," : "", n + 1, n < count);
        wifi_ui_json(req, val);
        list[0] = 0; CFG_get_str(CFG_WLN_AuthMode, list);
        net_list_get(item, list, n);
        WEB_printf(req, ",\"security\":\"%s\"", strncmp(item, "WPA2PSK", 7) ? "open" : "wpa2");
        list[0] = 0; CFG_get_str(CFG_WLN_NoForwarding, list);
        net_list_get(item, list, n);
        WEB_printf(req, ",\"isolate\":%d", atoi(item) == 1);
        if (!n) {
            /* network 1: the LAN in gateway/router setups, or a NAT network of
             * its own (SYS_NET1_IP) / bridged in bridge-based setups */
            char a[64];
            int bridge_base = wifi_ui_is_router() || wifi_ui_is_gateway() ? 0 : 1;
            a[0] = 0;
            if (!bridge_base) {
                char ip[20], mask[20];
                unsigned long mm;
                int bits = 0;
                CFG_get_str(CFG_LAN_IP, ip); CFG_get_str(CFG_LAN_MSK, mask);
                mm = ntohl(inet_addr(mask));
                while (mm & 0x80000000UL) { bits++; mm <<= 1; }
                snprintf(a, sizeof a, "%s/%d", ip, bits);
            } else CFG_get_str(CFG_SYS_NET1_IP, a);
            WEB_printf(req, ",\"type\":\"%s\",\"address\":", a[0] ? "nat" : "bridge"); wifi_ui_json(req, a);
            val[0] = 0; CFG_get_str(CFG_SYS_NET1_REACH, val);
            WEB_printf(req, ",\"reach\":"); wifi_ui_json(req, val);
            val[0] = 0; CFG_get_str(CFG_SYS_NET1_INTERNET, val);
            WEB_printf(req, ",\"internet\":%d", strcmp(val, "0") != 0);
            val[0] = 0; CFG_get_str(CFG_SYS_NET1_VIA, val);
            WEB_printf(req, ",\"via\":\"%s\"", strcmp(val, "wg") ? "wan" : "wg");
        }
        if (n) {
            val[0] = 0; CFG_get_str(net_ip_ids[n - 1], val);
            WEB_printf(req, ",\"type\":\"%s\",\"address\":", val[0] ? "nat" : "bridge"); wifi_ui_json(req, val);
            val[0] = 0; CFG_get_str(net_reach_ids[n - 1], val);
            WEB_printf(req, ",\"reach\":"); wifi_ui_json(req, val);
            val[0] = 0; CFG_get_str(net_inet_ids[n - 1], val);
            WEB_printf(req, ",\"internet\":%d", strcmp(val, "0") != 0);
            val[0] = 0; CFG_get_str(net_via_ids[n - 1], val);
            WEB_printf(req, ",\"via\":\"%s\"", strcmp(val, "wg") ? "wan" : "wg");
        }
        WEB_printf(req, "}");
    }
    WEB_printf(req, "]");
}

/* POST /networks_apply.html: COUNT (1-7); ISOLATE1; for networks 2..COUNT:
 * SSIDn, SECURITYn (open|wpa2), PASSWORDn (empty keeps a stored WPA2 key),
 * ADDRESSn (IPv4/prefix to route it, router mode only; empty bridges it),
 * INTERNETn (1|0), REACHn (comma list), ISOLATEn (1|0). Saves and restarts. */
void CGI_networks_apply(http_req *req)
{
    extern int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask);
    char key[16], *v, auth[256], enc[256], nofw[256], tmp[256], cur[256], countstr[4];
    char *ssid[NET_MAX], *sec[NET_MAX], *pw[NET_MAX], *addr[NET_MAX], *inet[NET_MAX], *reach[NET_MAX], *iso[NET_MAX], *via[NET_MAX];
    unsigned long ip[NET_MAX], mask[NET_MAX];
    int count, n, m, router = wifi_ui_is_router();
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    v = WEB_query(req, "COUNT");
    if (!v || strlen(v) != 1 || *v < '1' || *v > '0' + NET_MAX) { WEB_printf(req,"ERROR: COUNT must be 1-7"); return; }
    count = *v - '0';
    for (n = 0; n < NET_MAX; n++) {
        ip[n] = mask[n] = 0;
        sprintf(key, "ISOLATE%d", n + 1); iso[n] = WEB_query(req, key);
        if (iso[n] && strcmp(iso[n],"0") && strcmp(iso[n],"1")) { WEB_printf(req,"ERROR: ISOLATE%d must be 0 or 1", n + 1); return; }
        if (n == 0 || n >= count) continue;
        sprintf(key, "SSID%d", n + 1); ssid[n] = WEB_query(req, key);
        sprintf(key, "SECURITY%d", n + 1); sec[n] = WEB_query(req, key);
        sprintf(key, "PASSWORD%d", n + 1); pw[n] = WEB_query(req, key);
        sprintf(key, "ADDRESS%d", n + 1); addr[n] = WEB_query(req, key);
        sprintf(key, "INTERNET%d", n + 1); inet[n] = WEB_query(req, key);
        sprintf(key, "REACH%d", n + 1); reach[n] = WEB_query(req, key);
        sprintf(key, "VIA%d", n + 1); via[n] = WEB_query(req, key);
        if (via[n] && strcmp(via[n],"wan") && strcmp(via[n],"wg")) { WEB_printf(req,"ERROR: VIA%d must be wan or wg", n + 1); return; }
        if (!wifi_ui_text(ssid[n],1,32)) { WEB_printf(req,"ERROR: SSID%d must be 1-32 bytes", n + 1); return; }
        if (!sec[n] || (strcmp(sec[n],"open") && strcmp(sec[n],"wpa2"))) { WEB_printf(req,"ERROR: SECURITY%d must be open or wpa2", n + 1); return; }
        if (!strcmp(sec[n],"wpa2") && (!pw[n] || !*pw[n])) {
            /* keep the stored key if this network already used WPA2 */
            cur[0] = 0; CFG_get_str(CFG_WLN_AuthMode, cur);
            net_list_get(tmp, cur, n);
            cur[0] = 0; CFG_get_str(net_key_ids[n], cur);
            if (strncmp(tmp,"WPA2PSK",7) || !wifi_ui_key(cur)) { WEB_printf(req,"ERROR: PASSWORD%d is required (8-63 ASCII characters)", n + 1); return; }
            pw[n] = 0;
        } else if (!strcmp(sec[n],"wpa2") && !wifi_ui_key(pw[n])) { WEB_printf(req,"ERROR: PASSWORD%d must be 8-63 ASCII characters", n + 1); return; }
        if (addr[n] && *addr[n]) {
            if (!router) { WEB_printf(req,"ERROR: routed networks (ADDRESS%d) need router mode", n + 1); return; }
            if (net_extra_parse(addr[n], &ip[n], &mask[n])) { WEB_printf(req,"ERROR: ADDRESS%d must be IPv4/prefix (8-30), for example 10.0.%d.1/24", n + 1, n + 1); return; }
        }
        if (inet[n] && strcmp(inet[n],"0") && strcmp(inet[n],"1")) { WEB_printf(req,"ERROR: INTERNET%d must be 0 or 1", n + 1); return; }
        if (reach[n] && !net_reach_ok(reach[n])) { WEB_printf(req,"ERROR: REACH%d: comma list of device, lan, net2 ... net7, wg", n + 1); return; }
    }
    /* no overlapping ranges: LAN, routed networks, WireGuard */
    {
        unsigned long lip = 0, lmask = 0, wip = 0, wmask = 0;
        char a[20], b[20];
        if (router) { CFG_get_str(CFG_LAN_IP, a); CFG_get_str(CFG_LAN_MSK, b); lip = inet_addr(a); lmask = inet_addr(b); }
        tmp[0] = 0; CFG_get_str(CFG_SYS_WG_ADDR, tmp);
        if (tmp[0]) net_extra_parse(tmp, &wip, &wmask);
        for (n = 1; n < count; n++) {
            unsigned long mm;
            if (!ip[n]) continue;
            mm = mask[n] & lmask;
            if (lip && (ip[n] & mm) == (lip & mm)) { WEB_printf(req,"ERROR: ADDRESS%d overlaps the LAN", n + 1); return; }
            mm = mask[n] & wmask;
            if (wip && (ip[n] & mm) == (wip & mm)) { WEB_printf(req,"ERROR: ADDRESS%d overlaps the WireGuard network", n + 1); return; }
            for (m = 1; m < n; m++) {
                mm = mask[n] & mask[m];
                if (ip[m] && (ip[n] & mm) == (ip[m] & mm)) { WEB_printf(req,"ERROR: ADDRESS%d overlaps ADDRESS%d", n + 1, m + 1); return; }
            }
        }
    }
    /* apply */
    auth[0] = enc[0] = nofw[0] = 0;
    CFG_get_str(CFG_WLN_AuthMode, auth);
    CFG_get_str(CFG_WLN_EncrypType, enc);
    CFG_get_str(CFG_WLN_NoForwarding, nofw);
    for (n = 0; n < NET_MAX; n++) {
        if (iso[n]) { net_list_set(tmp, nofw, n, iso[n], "0"); strcpy(nofw, tmp); }
        if (n == 0 || n >= count) continue;
        net_list_set(tmp, auth, n, strcmp(sec[n],"open") ? "WPA2PSK" : "OPEN", "OPEN"); strcpy(auth, tmp);
        net_list_set(tmp, enc, n, strcmp(sec[n],"open") ? "AES" : "NONE", "NONE"); strcpy(enc, tmp);
        if (CFG_set_str(net_ssid_ids[n], ssid[n]) < 0 ||
            (pw[n] && CFG_set_str(net_key_ids[n], strcmp(sec[n],"open") ? pw[n] : "") < 0) ||
            CFG_set_str(net_ip_ids[n - 1], addr[n] ? addr[n] : "") < 0 ||
            CFG_set_str(net_inet_ids[n - 1], inet[n] ? inet[n] : "1") < 0 ||
            CFG_set_str(net_reach_ids[n - 1], reach[n] ? reach[n] : "") < 0 ||
            CFG_set_str(net_via_ids[n - 1], via[n] ? via[n] : "wan") < 0) { WEB_printf(req,"ERROR: settings could not be applied"); return; }
    }
    sprintf(countstr, "%d", count);
    if (CFG_set_str(CFG_WLN_BssidNum, countstr) < 0 || CFG_set_str(CFG_WLN_AuthMode, auth) < 0 ||
        CFG_set_str(CFG_WLN_EncrypType, enc) < 0 || CFG_set_str(CFG_WLN_NoForwarding, nofw) < 0) { WEB_printf(req,"ERROR: settings could not be applied"); return; }
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    WEB_printf(req,"OK");
    mon_snd_cmd(MON_CMD_REBOOT);
}

/* POST /setup_apply.html: the whole Wi-Fi/network setup in one request.
 * UPLINK cable|wifi (wifi: UPLINK_SSID, UPLINK_SECURITY, UPLINK_PASSWORD,
 * optional UPLINK_BSSID); CHANNEL; ETHERNET net1|internet (Wi-Fi uplink);
 * COUNT 1-7; for each network n: SSIDn, SECURITYn, PASSWORDn, TYPEn
 * (nat|bridge), and for NAT networks ADDRESSn, INTERNETn, REACHn, VIAn;
 * ISOLATEn; DHCP1 (network 1 when it is the main LAN).
 * Without any bridged network the SDK's gateway (cable) or router (Wi-Fi)
 * mode runs with network 1 as its LAN; otherwise opmode 3 bridges the
 * uplink with the bridged networks and the NAT networks (network 1
 * included) are routed out of the bridge (init/net_extra.c). Saves and
 * restarts. */
void CGI_setup_apply(http_req *req)
{
    extern int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask);
    char key[16], *v, *uplink, *upssid, *upsec, *upkey, *bssid, *channel, *eth, *dhcp1, *end;
    char *ssid[NET_MAX], *sec[NET_MAX], *pw[NET_MAX], *type[NET_MAX], *addr[NET_MAX], *inet[NET_MAX], *reach[NET_MAX], *iso[NET_MAX], *via[NET_MAX];
    unsigned long ip[NET_MAX], mask[NET_MAX];
    char auth[256], enc[256], nofw[256], tmp[256], cur[256], curup[64], curupkey[80], countstr[4];
    char lanip[20], lanmask[20], dstart[20], dend[20];
    int count, n, m, wifi, nat[NET_MAX], bridged = 0, ch;
    struct setup_old { int id; char old[256]; } *olds;
    int nold = 0;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    if (wifi_ui_busy) { WEB_printf(req,"ERROR: configuration is busy"); return; }
    uplink = WEB_query(req,"UPLINK");
    if (!uplink || (strcmp(uplink,"cable") && strcmp(uplink,"wifi"))) { WEB_printf(req,"ERROR: UPLINK must be cable or wifi"); return; }
    wifi = !strcmp(uplink,"wifi");
    channel = WEB_query(req,"CHANNEL");
    ch = channel ? strtol(channel,&end,10) : 0;
    if (!channel || *end || ch < 1 || ch > 13) { WEB_printf(req,"ERROR: CHANNEL must be 1-13 (with a Wi-Fi uplink, the uplink's channel)"); return; }
    upssid = WEB_query(req,"UPLINK_SSID"); upsec = WEB_query(req,"UPLINK_SECURITY");
    upkey = WEB_query(req,"UPLINK_PASSWORD"); bssid = WEB_query(req,"UPLINK_BSSID");
    eth = WEB_query(req,"ETHERNET"); dhcp1 = WEB_query(req,"DHCP1");
    if (wifi) {
        if (!wifi_ui_text(upssid,1,32)) { WEB_printf(req,"ERROR: UPLINK_SSID must be 1-32 bytes"); return; }
        if (!upsec || (strcmp(upsec,"open") && strcmp(upsec,"wpa2") && strcmp(upsec,"mixed"))) { WEB_printf(req,"ERROR: UPLINK_SECURITY must be wpa2, mixed or open"); return; }
        if (strcmp(upsec,"open") && (!upkey || !*upkey)) {
            curup[0] = curupkey[0] = 0;
            CFG_get_str(CFG_WLN_ApCliSsid,curup);
            CFG_get_str(CFG_WLN_ApCliWPAPSK,curupkey);
            if (!strcmp(curup,upssid)) upkey = curupkey;
        }
        if (strcmp(upsec,"open") && !wifi_ui_key(upkey)) { WEB_printf(req,"ERROR: UPLINK_PASSWORD must be 8-63 ASCII characters"); return; }
        if (bssid && *bssid && !wifi_ui_mac(bssid)) { WEB_printf(req,"ERROR: UPLINK_BSSID must be aa:bb:cc:dd:ee:ff or empty"); return; }
        if (eth && strcmp(eth,"net1") && strcmp(eth,"internet")) { WEB_printf(req,"ERROR: ETHERNET must be net1 or internet"); return; }
        if (eth && !strcmp(eth,"internet")) bridged = 1;
    }
    if (dhcp1 && strcmp(dhcp1,"0") && strcmp(dhcp1,"1")) { WEB_printf(req,"ERROR: DHCP1 must be 0 or 1"); return; }
    v = WEB_query(req, "COUNT");
    if (!v || strlen(v) != 1 || *v < '1' || *v > '0' + NET_MAX) { WEB_printf(req,"ERROR: COUNT must be 1-7"); return; }
    count = *v - '0';
    for (n = 0; n < count; n++) {
        ip[n] = mask[n] = 0;
        sprintf(key, "SSID%d", n + 1); ssid[n] = WEB_query(req, key);
        sprintf(key, "SECURITY%d", n + 1); sec[n] = WEB_query(req, key);
        sprintf(key, "PASSWORD%d", n + 1); pw[n] = WEB_query(req, key);
        sprintf(key, "TYPE%d", n + 1); type[n] = WEB_query(req, key);
        sprintf(key, "ADDRESS%d", n + 1); addr[n] = WEB_query(req, key);
        sprintf(key, "INTERNET%d", n + 1); inet[n] = WEB_query(req, key);
        sprintf(key, "REACH%d", n + 1); reach[n] = WEB_query(req, key);
        sprintf(key, "ISOLATE%d", n + 1); iso[n] = WEB_query(req, key);
        sprintf(key, "VIA%d", n + 1); via[n] = WEB_query(req, key);
        if (!wifi_ui_text(ssid[n],1,32)) { WEB_printf(req,"ERROR: SSID%d must be 1-32 bytes", n + 1); return; }
        if (!sec[n] || (strcmp(sec[n],"open") && strcmp(sec[n],"wpa2"))) { WEB_printf(req,"ERROR: SECURITY%d must be open or wpa2", n + 1); return; }
        if (!strcmp(sec[n],"wpa2") && (!pw[n] || !*pw[n])) {
            cur[0] = 0; CFG_get_str(CFG_WLN_AuthMode, cur);
            net_list_get(tmp, cur, n);
            cur[0] = 0; CFG_get_str(net_key_ids[n], cur);
            if (strncmp(tmp,"WPA2PSK",7) || !wifi_ui_key(cur)) { WEB_printf(req,"ERROR: PASSWORD%d is required (8-63 ASCII characters)", n + 1); return; }
            pw[n] = 0;
        } else if (!strcmp(sec[n],"wpa2") && !wifi_ui_key(pw[n])) { WEB_printf(req,"ERROR: PASSWORD%d must be 8-63 ASCII characters", n + 1); return; }
        if (!type[n] || (strcmp(type[n],"nat") && strcmp(type[n],"bridge"))) { WEB_printf(req,"ERROR: TYPE%d must be nat or bridge", n + 1); return; }
        nat[n] = !strcmp(type[n],"nat");
        if (!nat[n]) bridged = 1;
        if (nat[n]) {
            if (!addr[n] || net_extra_parse(addr[n], &ip[n], &mask[n])) { WEB_printf(req,"ERROR: ADDRESS%d must be IPv4/prefix (8-30), for example 10.0.%d.1/24", n + 1, n + 1); return; }
            if (inet[n] && strcmp(inet[n],"0") && strcmp(inet[n],"1")) { WEB_printf(req,"ERROR: INTERNET%d must be 0 or 1", n + 1); return; }
            if (reach[n] && !net_reach_ok(reach[n])) { WEB_printf(req,"ERROR: REACH%d: comma list of device, lan, net1 ... net7, wg", n + 1); return; }
            if (via[n] && strcmp(via[n],"wan") && strcmp(via[n],"wg")) { WEB_printf(req,"ERROR: VIA%d must be wan or wg", n + 1); return; }
        }
        if (iso[n] && strcmp(iso[n],"0") && strcmp(iso[n],"1")) { WEB_printf(req,"ERROR: ISOLATE%d must be 0 or 1", n + 1); return; }
    }
    if (wifi && eth && !strcmp(eth,"net1") && bridged) { WEB_printf(req,"ERROR: ETHERNET=net1 needs network 1 as NAT and no bridged network; use ETHERNET=internet"); return; }
    /* no overlapping ranges among NAT networks and WireGuard */
    {
        unsigned long wip = 0, wmask = 0;
        tmp[0] = 0; CFG_get_str(CFG_SYS_WG_ADDR, tmp);
        if (tmp[0]) net_extra_parse(tmp, &wip, &wmask);
        for (n = 0; n < count; n++) {
            unsigned long mm;
            if (!ip[n]) continue;
            mm = mask[n] & wmask;
            if (wip && (ip[n] & mm) == (wip & mm)) { WEB_printf(req,"ERROR: ADDRESS%d overlaps the WireGuard network", n + 1); return; }
            for (m = 0; m < n; m++) {
                mm = mask[n] & mask[m];
                if (ip[m] && (ip[n] & mm) == (ip[m] & mm)) { WEB_printf(req,"ERROR: ADDRESS%d overlaps ADDRESS%d", n + 1, m + 1); return; }
            }
        }
    }
    if (nat[0] && !bridged) {
        /* network 1 is the SDK LAN: address, mask and its DHCP pool */
        struct in_addr a;
        unsigned long base = ntohl(ip[0] & mask[0]);
        a.s_addr = ip[0]; strcpy(lanip, inet_ntoa(a));
        a.s_addr = mask[0]; strcpy(lanmask, inet_ntoa(a));
        a.s_addr = htonl(base + 100); strcpy(dstart, inet_ntoa(a));
        a.s_addr = htonl(base + 199 < ntohl(ip[0] | ~mask[0]) ? base + 199 : ntohl(ip[0] | ~mask[0]) - 1); strcpy(dend, inet_ntoa(a));
    }
    /* apply; on a failed set every changed item gets its old value back */
    olds = calloc(64, sizeof(*olds));
    if (!olds) { WEB_printf(req,"ERROR: insufficient memory"); return; }
#define SET(k,val) do { if (nold >= 64) goto fail; olds[nold].id = (k); olds[nold].old[0] = 0; CFG_get_str((k), olds[nold].old); nold++; \
                        if (CFG_set_str((k),(char *)(val)) < 0) goto fail; } while (0)
    if (!bridged) {
        SET(CFG_SYS_OPMODE, wifi ? "2" : "1");
        SET(CFG_LAN_IP_MODE, "1");
        SET(CFG_LAN_IP, lanip);
        SET(CFG_LAN_MSK, lanmask);
        SET(CFG_LAN_DHCPD_START, dstart);
        SET(CFG_LAN_DHCPD_END, dend);
        SET(CFG_LAN_DHCPD_EN, dhcp1 && !strcmp(dhcp1,"0") ? "0" : "1");
        if (!wifi) SET(CFG_WAN_IP_MODE, "2");
        SET(CFG_SYS_NET1_IP, "");
    } else {
        SET(CFG_SYS_OPMODE, "3");
        SET(CFG_LAN_IP_MODE, "0");
        SET(CFG_LAN_DHCPD_EN, "0");
        SET(CFG_SYS_NET1_IP, nat[0] ? addr[0] : "");
    }
    SET(CFG_WLN_ApCliEnable, wifi ? "1" : "0");
    /* bridged clients behind a Wi-Fi uplink need the driver's MAC repeater */
    SET(CFG_WLN_MACRepeaterEn, wifi && bridged ? "1" : "0");
    if (wifi) {
        SET(CFG_WLN_ApCliSsid, upssid);
        SET(CFG_WLN_ApCliBssid, bssid ? bssid : "");
        SET(CFG_WLN_ApCliAuthMode, !strcmp(upsec,"open") ? "OPEN" : !strcmp(upsec,"mixed") ? "WPAPSKWPA2PSK" : "WPA2PSK");
        SET(CFG_WLN_ApCliEncrypType, !strcmp(upsec,"open") ? "NONE" : !strcmp(upsec,"mixed") ? "TKIPAES" : "AES");
        SET(CFG_WLN_ApCliWPAPSK, !strcmp(upsec,"open") ? "" : upkey);
    }
    SET(CFG_WLN_EN, "1");
    SET(CFG_WLN_AutoSSID, "1");
    SET(CFG_WLN_WirelessMode, "9");
    SET(CFG_WLN_HT_BW, "0");
    SET(CFG_WLN_AutoChannelSelect, "0");
    SET(CFG_WLN_Channel, channel);
    auth[0] = enc[0] = nofw[0] = 0;
    CFG_get_str(CFG_WLN_AuthMode, auth);
    CFG_get_str(CFG_WLN_EncrypType, enc);
    CFG_get_str(CFG_WLN_NoForwarding, nofw);
    for (n = 0; n < count; n++) {
        net_list_set(tmp, auth, n, strcmp(sec[n],"open") ? "WPA2PSK" : "OPEN", "OPEN"); strcpy(auth, tmp);
        net_list_set(tmp, enc, n, strcmp(sec[n],"open") ? "AES" : "NONE", "NONE"); strcpy(enc, tmp);
        net_list_set(tmp, nofw, n, iso[n] && !strcmp(iso[n],"1") ? "1" : "0", "0"); strcpy(nofw, tmp);
        SET(net_ssid_ids[n], ssid[n]);
        if (pw[n]) SET(net_key_ids[n], strcmp(sec[n],"open") ? pw[n] : "");
        if (n) SET(net_ip_ids[n - 1], nat[n] ? addr[n] : "");
        SET(n ? net_inet_ids[n - 1] : CFG_SYS_NET1_INTERNET, nat[n] && inet[n] ? inet[n] : "1");
        SET(n ? net_reach_ids[n - 1] : CFG_SYS_NET1_REACH, nat[n] && reach[n] ? reach[n] : (n ? "" : "device"));
        SET(n ? net_via_ids[n - 1] : CFG_SYS_NET1_VIA, nat[n] && via[n] ? via[n] : "wan");
    }
    sprintf(countstr, "%d", count);
    SET(CFG_WLN_BssidNum, countstr);
    SET(CFG_WLN_AuthMode, auth);
    SET(CFG_WLN_EncrypType, enc);
    SET(CFG_WLN_NoForwarding, nofw);
#undef SET
    free(olds);
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    WEB_printf(req,"OK");
    mon_snd_cmd(MON_CMD_REBOOT);
    return;
fail:
    while (nold-- > 0) CFG_set_str(olds[nold].id, olds[nold].old);
    free(olds);
    CFG_commit(CFG_NO_EVENT);
    WEB_printf(req,"ERROR: settings could not be applied");
}

/* Site survey as JSON; the page parses the driver's fixed-width table. */
void CGI_wifi_scan(http_req *req)
{
    extern int CmdIwpriv(int argc, char *argv[]);
    char *survey[] = { "ra0", "set", "SiteSurvey=" };
    struct iwreq param;
    cyg_netdevtab_entry_t *t;
    struct eth_drv_sc *sc = NULL;
    char *text;

    for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) {
        struct eth_drv_sc *c = (struct eth_drv_sc *)t->device_instance;
        if (!strcmp(c->dev_name, "ra0")) { sc = c; break; }
    }
    if (!sc || wifi_ui_busy) { WEB_printf(req, "{\"error\":\"busy\",\"raw\":\"\"}"); return; }
    text = malloc(10240);
    if (!text) { WEB_printf(req, "{\"error\":\"memory\",\"raw\":\"\"}"); return; }
    CmdIwpriv(3, survey);
    cyg_thread_delay(300); /* Let the survey visit all channels. */
    text[0] = '\0';
    memset(&param, 0, sizeof(param));
    param.u.data.flags = RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG;
    param.u.data.pointer = text;
    param.u.data.length = 0;
    rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_GSITESURVEY, (caddr_t)&param);
    if (param.u.data.length > 0 && param.u.data.length < 10240) text[param.u.data.length] = '\0';
    else text[0] = '\0';
    WEB_printf(req, "{\"error\":\"\",\"raw\":");
    wifi_ui_json(req, text);
    WEB_printf(req, "}");
    free(text);
}

void CGI_system_apply(http_req *req)
{
    char *action = WEB_query(req,"ACTION");
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    if (wifi_ui_busy) { WEB_printf(req,"ERROR: configuration is busy"); return; }
    if (action && !strcmp(action,"reboot")) {
        WEB_printf(req,"OK");
        mon_snd_cmd(MON_CMD_REBOOT);
    } else if (action && !strcmp(action,"factory")) {
        WEB_printf(req,"OK");
        CGI_reset_default();
    } else if (action && !strcmp(action,"name")) {
        /* mDNS host name (<name>.local): letters, digits and '-', 1-63; empty turns it off */
        char *name = WEB_query(req,"NAME");
        int i, n = name ? (int)strlen(name) : -1;
        if (n < 0 || n > 63 || (n && (name[0] == '-' || name[n - 1] == '-'))) { WEB_printf(req,"ERROR: NAME must be 1-63 letters, digits or '-' (not at the ends), or empty"); return; }
        for (i = 0; i < n; i++)
            if (!isalnum((unsigned char)name[i]) && name[i] != '-') { WEB_printf(req,"ERROR: NAME must be 1-63 letters, digits or '-' (not at the ends), or empty"); return; }
        if (CFG_set_str(CFG_SYS_MDNS_NAME, name) < 0) { WEB_printf(req,"ERROR: settings could not be applied"); return; }
        CFG_commit(CFG_NO_EVENT);
        if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
        WEB_printf(req,"OK");
    } else
        WEB_printf(req,"ERROR: ACTION must be reboot, factory or name");
}

/* GET /config_backup.html: all settings as text (NAME=value lines), except
 * the WireGuard device key and the entropy seed, which never leave the
 * device. Contains the Wi-Fi, uplink and admin passwords. */
void CGI_config_backup(http_req *req)
{
    extern int CFG_backup_text(char *buf, int size);
    char *buf;
    int n, i;
    buf = malloc(16384);
    if (!buf) { WEB_printf(req,"ERROR: insufficient memory"); return; }
    n = CFG_backup_text(buf, 16384);
    if (n < 0) { free(buf); WEB_printf(req,"ERROR: settings could not be read"); return; }
    for (i = 0; i < n; i += 256)
        WEB_printf(req, "%.*s", n - i < 256 ? n - i : 256, buf + i);
    free(buf);
}

/* POST /config_restore.html (multipart field "config", a file from
 * config_backup): applies every setting in it except the device key and
 * seed, saves and restarts. Needs an admin password. */
void CGI_config_restore(http_req *req)
{
    extern int CFG_restore_text(char *buf, int n);
    char cur[80], *file, *copy;
    int len = 0;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    cur[0] = '\0';
    CFG_get_str(CFG_SYS_ADMPASS, cur);
    if (!cur[0]) { WEB_printf(req,"ERROR: set an admin password before restoring settings"); return; }
    file = WEB_upload_file(req, "config", &len);
    if (!file || len <= 0 || len > 16000) { WEB_printf(req,"ERROR: no settings file (multipart field \"config\", up to 16000 bytes)"); return; }
    copy = malloc(len + 1);
    if (!copy) { WEB_printf(req,"ERROR: insufficient memory"); return; }
    memcpy(copy, file, len);
    copy[len] = 0;
    if (CFG_restore_text(copy, len)) { free(copy); WEB_printf(req,"ERROR: this is not a settings file from this device's backup"); return; }
    free(copy);
    CFG_commit(CFG_NO_EVENT);
    if (CFG_save_user()) { WEB_printf(req,"ERROR: saving to flash failed"); return; }
    WEB_printf(req,"OK");
    mon_snd_cmd(MON_CMD_REBOOT);
}

static int wifi_ui_uplink_connected(void)
{
    extern int rt28xx_apcli_connected(struct eth_drv_sc *net_dev);
    cyg_netdevtab_entry_t *t;

    for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) {
        struct eth_drv_sc *sc = (struct eth_drv_sc *)t->device_instance;
        if (!strcmp(sc->dev_name, "ra0")) return rt28xx_apcli_connected(sc);
    }
    return -1;
}

/* Firmware update from the web interface: POST multipart field "firmware"
 * (a zxrouter uImage) to /firmware_apply.html?ACTION=check|test|install.
 * check validates only; test runs it in RAM (a restart returns to the
 * installed firmware); install writes the firmware partition with the same
 * checks as "ramboot install" and restarts. Needs an admin password. */
extern int ramboot_web(unsigned char *image, unsigned int size, int mode,
                       void *owner, void (*release)(void *), const char **err);

static void fw_release(void *owner)
{
    http_upload_content *c = (http_upload_content *)owner;
    if (!c) return;
    if (c->buf) free(c->buf);
    free(c);
}

void CGI_firmware_apply(http_req *req)
{
    char cur[256], *action = WEB_query(req, "ACTION"), *file;
    const char *err = "none";
    int len = 0, mode;
    http_upload_content *owner;
    if (req->method != METHOD_POST) { WEB_printf(req,"ERROR: POST required"); return; }
    if (!action) { WEB_printf(req,"ERROR: ACTION must be check, test or install"); return; }
    if (!strcmp(action,"check")) mode = 0;
    else if (!strcmp(action,"test")) mode = 1;
    else if (!strcmp(action,"install")) mode = 2;
    else { WEB_printf(req,"ERROR: ACTION must be check, test or install"); return; }
    cur[0] = '\0';
    CFG_get_str(CFG_SYS_ADMPASS, cur);
    if (!cur[0]) { WEB_printf(req,"ERROR: set an admin password before updating firmware"); return; }
    file = WEB_upload_file(req, "firmware", &len);
    if (!file || len <= 0) { WEB_printf(req,"ERROR: no firmware file (multipart field \"firmware\")"); return; }
    /* the image stays in the upload buffer; the RAM-boot worker frees it */
    owner = req->content;
    req->content = 0;
    if (ramboot_web((unsigned char *)file, (unsigned int)len, mode, owner, fw_release, &err)) {
        WEB_printf(req,"ERROR: %s", err);
        return;
    }
    WEB_printf(req,"OK");
}
