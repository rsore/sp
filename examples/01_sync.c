#define SP_LOG_ERROR(msg) fprintf(stderr, "Error: %s\n", (msg))
#define SP_LOG_INFO(msg)  puts((msg))
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

#include <stdio.h>
#include <string.h>

// Note: sp.h logs the executed command via SP_LOG_INFO.

int
child_main(void)
{
    puts("Hello from child");

    return 0;
}

int
main(int    argc,
     char **argv)
{
    // Disable stdout and stderr buffering
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // child_main() will be called when program is run with --child
    if (argc > 1 && strcmp(argv[1], "--child") == 0) return child_main();

    Sp_Cmd cmd = {0};
    // Re-run this executable as a child process
    sp_cmd_add_args(&cmd, argv[0], "--child");
    int exit_code = sp_cmd_exec_sync(&cmd);
    sp_cmd_free(&cmd);

    return exit_code;
}
