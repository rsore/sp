#include <stdio.h>

#define SP_LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO] " fmt "\n", __VA_ARGS__)
#define SP_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", __VA_ARGS__)
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "sp.h"

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    SpCmd cmd = {0};
    sp_cmd_reset(&cmd);
    sp_cmd_add_arg(&cmd, "ping");
    sp_cmd_add_arg(&cmd, "127.0.0.1");
    sp_cmd_add_arg(&cmd, "-n");
    sp_cmd_add_arg(&cmd, "3");

    SpProc p = sp_cmd_exec_async(&cmd);

    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");
    printf("bing-bong\n");

    printf("Exit code: %d\n", sp_proc_wait(&p));

    sp_cmd_free(&cmd);

    return 0;
}
