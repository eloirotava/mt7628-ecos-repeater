/* Host test for cli/cmd_boot.c: command-tree walk and startup results.
 * Built by tools/test_wifi_ui.py with -DCLI_BOOT_HOST_TEST and -I cli. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define diag_printf printf

typedef struct _stCLI_cmd {
	char *name;
	int (*func)(int, char **);
	char *doc;
	int mode;
	struct _stCLI_cmd *prev, *next;
} stCLI_cmd;
#define CLI_CMD_FLAG_SUBCMD 2
#define CLI_CMD_FLAG_INITED 0x10
enum { CFG_SYS_BOOT1 = 1, CFG_SYS_BOOT2, CFG_SYS_BOOT3, CFG_SYS_BOOT4, CFG_SYS_BOOT5, CFG_SYS_BOOT6, CFG_SYS_BOOT7, CFG_SYS_BOOT8, CFG_SYS_BOOT9, CFG_SYS_BOOT10, CFG_SYS_BOOT11, CFG_SYS_BOOT12, CFG_SYS_BOOT13, CFG_SYS_BOOT14, CFG_SYS_BOOT15, CFG_SYS_BOOT16 };

static char cfg[17][256];
static int CFG_get_str(int id, char *val) { strcpy(val, cfg[id]); return 0; }

static int route_argc, inits;
static char route_args[4][32];
static int route_cmd(int argc, char **argv)
{
	int i;
	route_argc = argc;
	for (i = 0; i < argc && i < 4; i++) strcpy(route_args[i], argv[i]);
	return argc == 4 ? 0 : -1;
}
static int show_cmd(int argc, char **argv) { (void)argv; return argc; }
static int net_init(int argc, char **argv) { (void)argc; (void)argv; inits++; return 0; }

/* root -> net -> route/show; root -> show */
static stCLI_cmd net_route = { "route", route_cmd, "", 0, 0, 0 };
static stCLI_cmd net_show = { "show", show_cmd, "", 0, 0, &net_route };
static stCLI_cmd net_tbl = { "NET", net_init, "", 0, 0, &net_show };
static stCLI_cmd root_show = { "show", show_cmd, "", 0, 0, 0 };
static stCLI_cmd root_net = { "net", (int (*)(int, char **))&net_tbl, "", CLI_CMD_FLAG_SUBCMD, 0, &root_show };
static stCLI_cmd root = { "CMD", 0, "", 0, 0, &root_net };

#include "cmd_boot.c"

int main(void)
{
	char l[256];
	strcpy(l, "  net   route add 10.9.0.0 255.255.0.0 192.168.1.2 ");
	assert(CLI_exec_line(&root, l) == 0);
	assert(route_argc == 4 && !strcmp(route_args[0], "add") && !strcmp(route_args[3], "192.168.1.2"));
	assert(inits == 1);
	strcpy(l, "net\troute add x");
	assert(CLI_exec_line(&root, l) == -1);
	assert(inits == 1); /* submenu initialised once */
	strcpy(l, "show a b"); assert(CLI_exec_line(&root, l) == 2);
	strcpy(l, "net show"); assert(CLI_exec_line(&root, l) == 0);
	strcpy(l, "net"); assert(CLI_exec_line(&root, l) == CLI_EXEC_INCOMPLETE);
	strcpy(l, "reboot"); assert(CLI_exec_line(&root, l) == CLI_EXEC_UNKNOWN);
	strcpy(l, "net nope"); assert(CLI_exec_line(&root, l) == CLI_EXEC_UNKNOWN);
	strcpy(l, "   "); assert(CLI_exec_line(&root, l) == CLI_EXEC_EMPTY);

	assert(!strcmp(CLI_boot_result(0), "pending"));
	strcpy(cfg[1], "net route add 10.9.0.0 255.255.0.0 192.168.1.2");
	strcpy(cfg[3], "bogus");
	strcpy(cfg[4], "net route add only");
	strcpy(cfg[8], "show");
	CLI_boot_run(&root);
	assert(!strcmp(CLI_boot_result(0), "ok"));
	assert(!strcmp(CLI_boot_result(1), "empty"));
	assert(!strcmp(CLI_boot_result(2), "unknown command"));
	assert(!strcmp(CLI_boot_result(3), "error -1"));
	assert(!strcmp(CLI_boot_result(7), "ok"));
	assert(!strcmp(cfg[1], "net route add 10.9.0.0 255.255.0.0 192.168.1.2")); /* config untouched */
	puts("PASS: startup script command-tree walk, results and isolation from the config");
	return 0;
}
