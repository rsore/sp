#include <stdio.h>

#define SP_LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO] " fmt, __VA_ARGS__)
#define SP_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR]" fmt, __VA_ARGS__)
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "sp.h"


int
main(void)
{
    SpCmd cmd = {0};
    sp_cmd_add_arg(&cmd, "echo");
    sp_cmd_add_arg(&cmd, "hello");

    for (size_t i = 0; i < cmd.args.size; ++i) {
        printf("Arg: %s\n", cmd.args.buffer[i].buffer);
    }

    int exit_code = sp_cmd_exec_sync(&cmd);
    printf("Exit code: %d\n", exit_code);

    sp_cmd_free(&cmd);

    return 0;
}
