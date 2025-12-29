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
    puts("[child] line 3");
    return 2;
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

    Sp_Cmd  cmd = {0};
    Sp_Pipe out = {0};

    sp_cmd_add_args(&cmd, argv[0], "--child");

    // To capture stderr instead, use sp_cmd_redirect_stderr_pipe(&cmd, &out).
    sp_cmd_redirect_stdout_pipe(&cmd, &out);

    // Run the child. After a successful exec, `out` is a valid read pipe.
    Sp_Proc proc = sp_cmd_exec_async(&cmd);
    sp_cmd_free(&cmd);

    // Read stdout from the pipe, write to stdout and track total bytes read
    char buf[64];
    size_t total = 0;
    size_t n;
    while (sp_pipe_read(&out, buf, sizeof(buf), &n) && n) {
        fwrite(buf, 1, n, stdout);
        total += n;
    }
    sp_pipe_close(&out);

    int code = sp_proc_wait(&proc);
    printf("\n[parent] captured %zu bytes, exit=%d\n", total, code);
    return code;
}
