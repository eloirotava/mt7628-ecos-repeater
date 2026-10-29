/* Startup script (cmd_boot.c) */
#ifndef CMD_BOOT_H
#define CMD_BOOT_H

#define CLI_BOOT_LINES 16
#define CLI_BOOT_ARGV  25

/* CLI_exec_line results besides the command's own return value */
#define CLI_EXEC_EMPTY      (-1000)
#define CLI_EXEC_UNKNOWN    (-1001)
#define CLI_EXEC_INCOMPLETE (-1002) /* a submenu name without a command */

struct _stCLI_cmd;
int CLI_exec_line(struct _stCLI_cmd *root, char *line); /* modifies line */
void CLI_boot_run(struct _stCLI_cmd *root);
void CLI_boot_start(void);
const char *CLI_boot_result(int n); /* "pending", "ok", "unknown command", ... */
extern const int CLI_boot_ids[CLI_BOOT_LINES];

#endif
