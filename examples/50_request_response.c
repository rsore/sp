#include <stdio.h>
#include <string.h>

#define USE_SIMPLE_LOGGER
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

static int
child_main(void)
{
    char buf[64];
    while (fgets(buf, sizeof(buf), stdin)) {
        for (char *p = buf; *p; ++p) {
            if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 'a' + 'A');
        }
        fputs(buf, stdout);
    }
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

    Sp_Cmd  cmd = {0};
    Sp_Pipe in  = {0};
    Sp_Pipe out = {0};

    sp_cmd_add_args(&cmd, argv[0], "--child");
    sp_cmd_redirect_stdin_pipe(&cmd, &in);
    sp_cmd_redirect_stdout_pipe(&cmd, &out);

    Sp_Proc proc = sp_cmd_exec_async(&cmd);
    sp_cmd_free(&cmd);

    // Send request
    const char *req = "hello child\nhow are you?\n";
    size_t n;
    sp_pipe_write(&in, req, strlen(req), &n);
    sp_pipe_close(&in); // signal end of request

    // Read response
    char buf[64];
    while (sp_pipe_read(&out, buf, sizeof(buf), &n) && n) {
        fwrite(buf, 1, n, stdout);
    }
    sp_pipe_close(&out);

    int exit_code = sp_proc_wait(&proc);

    return exit_code;
}
