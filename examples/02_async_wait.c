#define SP_LOG_ERROR(msg) fprintf(stderr, "Error: %s\n", (msg))
#define SP_LOG_INFO(msg)  puts((msg))
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

#include <stdio.h>
#include <string.h>

static int
child_main(const char *id)
{
    printf("[child %s] hello\n", id);
    return (strcmp(id, "A") == 0) ? 0 : 1;
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        const char *id = (argc > 2) ? argv[2] : "?";
        return child_main(id);
    }

    Sp_Cmd cmd = {0};
    sp_cmd_add_args(&cmd, argv[0], "--child", "A");
    // Start first process
    Sp_Proc a = sp_cmd_exec_async(&cmd);

    // Reuse same cmd object to reduce allocations
    sp_cmd_reset(&cmd);
    sp_cmd_add_args(&cmd, argv[0], "--child", "B");
    // Start second process
    Sp_Proc b = sp_cmd_exec_async(&cmd);

    sp_cmd_free(&cmd);

    // Wait for processes in whatever order you want.
    int b_code = sp_proc_wait(&b);
    int a_code = sp_proc_wait(&a);

    printf("[parent] child B exit: %d\n", b_code);
    printf("[parent] child A exit: %d\n", a_code);
    return (a_code != 0) ? a_code : b_code;
}
