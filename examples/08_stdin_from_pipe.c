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
    char buf[16];
    while (fgets(buf, sizeof(buf), stdin)) {
        fputs(buf, stdout);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        return child_main();
    }

    Sp_Cmd cmd = {0};
    Sp_Pipe in = {0};
    sp_cmd_add_args(&cmd, argv[0], "--child");
    sp_cmd_redirect_stdin_pipe(&cmd, &in);

    Sp_Proc proc = sp_cmd_exec_async(&cmd);
    sp_cmd_free(&cmd);

    const char *buf1 = "Hello world";
    const char *buf2 = "\n";
    const char *buf3 = "Foo bar baz\n";

    // Note: sp_pipe_write may do partial writes. Production code should loop
    //       until all bytes are written. Check `n` after each call.

    size_t n;
    sp_pipe_write(&in, buf1, strlen(buf1), &n);
    sp_pipe_write(&in, buf2, strlen(buf2), &n);
    sp_pipe_write(&in, buf3, strlen(buf3), &n);
    sp_pipe_close(&in);

    int exit_code = sp_proc_wait(&proc);

    return exit_code;
}
