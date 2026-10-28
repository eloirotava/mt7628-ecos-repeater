/* Startup script: up to CLI_BOOT_LINES console commands (SYS_BOOT1..8) run
 * once at boot, after the LAN is configured, as if typed at CMD>, e.g.
 *   net route add 10.9.0.0 255.255.0.0 192.168.1.2
 *   cfg set SYS_NAME extender
 * A line walks the command tree: submenu names, then the command and its
 * arguments. "reboot" is not part of the tree, so a script cannot loop the
 * device through restarts. Output goes to the console log; the result of
 * each line is kept for the web interface. */
#ifndef CLI_BOOT_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <string.h>
#include <stdio.h>
#include <cli_cmd.h>
#include <cfg_def.h>
#include <cfg_id.h>
#endif
#include "cmd_boot.h"

extern int CFG_get_str(int id, char *val);

static char results[CLI_BOOT_LINES][24];
static volatile int boot_done;

static void table_init(stCLI_cmd *t)
{
	if (t->func && !(t->mode & CLI_CMD_FLAG_INITED)) {
		t->func(0, 0);
		t->mode |= CLI_CMD_FLAG_INITED;
	}
}

/* Splits line in place on spaces and tabs; returns argc. */
static int split(char *line, char **argv, int max)
{
	int argc = 0;
	char *p = line;
	while (*p && argc < max) {
		while (*p == ' ' || *p == '\t') *p++ = 0;
		if (!*p) break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t') p++;
	}
	return argc;
}

int CLI_exec_line(stCLI_cmd *root, char *line)
{
	char *argv[CLI_BOOT_ARGV];
	int argc = split(line, argv, CLI_BOOT_ARGV), i = 0;
	stCLI_cmd *t = root, *cp;

	if (argc == 0) return CLI_EXEC_EMPTY;
	table_init(t);
	for (;;) {
		for (cp = t->next; cp; cp = cp->next)
			if (!strcmp(argv[i], cp->name)) break;
		if (!cp) return CLI_EXEC_UNKNOWN;
		if (cp->mode & CLI_CMD_FLAG_SUBCMD) {
			t = (stCLI_cmd *)cp->func;
			table_init(t);
			if (++i == argc) return CLI_EXEC_INCOMPLETE;
			continue;
		}
		return cp->func(argc - i - 1, argv + i + 1);
	}
}

const char *CLI_boot_result(int n)
{
	if (n < 0 || n >= CLI_BOOT_LINES) return "";
	return boot_done ? results[n] : "pending";
}

static void describe(char *out, size_t size, int rc)
{
	switch (rc) {
	case CLI_EXEC_EMPTY:      snprintf(out, size, "empty"); break;
	case CLI_EXEC_UNKNOWN:    snprintf(out, size, "unknown command"); break;
	case CLI_EXEC_INCOMPLETE: snprintf(out, size, "incomplete"); break;
	default:                  snprintf(out, size, rc < 0 ? "error %d" : "ok", rc); break;
	}
}

const int CLI_boot_ids[CLI_BOOT_LINES] = {
	CFG_SYS_BOOT1, CFG_SYS_BOOT2, CFG_SYS_BOOT3, CFG_SYS_BOOT4,
	CFG_SYS_BOOT5, CFG_SYS_BOOT6, CFG_SYS_BOOT7, CFG_SYS_BOOT8,
};

/* Runs every non-empty line in order; one failure does not stop the rest. */
void CLI_boot_run(stCLI_cmd *root)
{
	char line[256], shown[256];
	int n, rc;
	for (n = 0; n < CLI_BOOT_LINES; n++) {
		line[0] = 0;
		CFG_get_str(CLI_boot_ids[n], line);
		strncpy(shown, line, sizeof shown - 1);
		shown[sizeof shown - 1] = 0;
		rc = CLI_exec_line(root, line);
		describe(results[n], sizeof results[n], rc);
		if (rc != CLI_EXEC_EMPTY) diag_printf("startup %d: %s -> %s\n", n + 1, shown, results[n]);
	}
	boot_done = 1;
}

#ifndef CLI_BOOT_HOST_TEST
extern stCLI_cmd sys_cmds[];

static cyg_handle_t boot_handle;
static cyg_thread boot_obj;
static char boot_stack[8192];

static void boot_thread(cyg_addrword_t arg)
{
	(void)arg;
	/* after the LAN, its default route and the rescue address are up */
	cyg_thread_delay(20 * 100);
	CLI_boot_run(&sys_cmds[0]);
}

void CLI_boot_start(void)
{
	cyg_thread_create(15, boot_thread, 0, "startup", boot_stack, sizeof boot_stack, &boot_handle, &boot_obj);
	cyg_thread_resume(boot_handle);
}
#endif
