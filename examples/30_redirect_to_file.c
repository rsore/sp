#define SP_LOG_ERROR(msg) fprintf(stderr, "Error: %s\n", (msg))
#define SP_LOG_INFO(msg)  puts((msg))
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

#include <stdio.h>
#include <string.h>

static int
child_main(void)
{
    puts("[child] line 1");
    puts("[child] line 2");
    fputs("[child] some error\n", stderr);
    puts("[child] line 3");
    return 0;
}


int
main(int    argc,
     char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        return child_main();
    }

    Sp_Cmd cmd = {0};

    // stdout/stderr -> separate files
    sp_cmd_add_args(&cmd, argv[0], "--child");
    sp_cmd_redirect_stdout_to_file(&cmd, "redirect_to_file_out.txt", SP_FILE_WRITE_TRUNC);  // TRUNC will overwrite existing file
    sp_cmd_redirect_stderr_to_file(&cmd, "redirect_to_file_err.txt", SP_FILE_WRITE_APPEND); // APPEND will append to existing file
    int code1 = sp_cmd_exec_sync(&cmd);

    // stdout/stderr -> merged file (2>&1)
    sp_cmd_reset(&cmd);
    sp_cmd_add_args(&cmd, argv[0], "--child");
    sp_cmd_redirect_stderr_to_stdout(&cmd);
    sp_cmd_redirect_stdout_to_file(&cmd, "redirect_to_file_merged.txt", SP_FILE_WRITE_TRUNC);
    int code2 = sp_cmd_exec_sync(&cmd);

    sp_cmd_free(&cmd);

    puts("[parent] wrote redirect_to_file_out.txt, redirect_to_file_err.txt, redirect_to_file_merged.txt");
    return code1 ? code1 : code2;
}
