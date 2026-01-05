#include <stdio.h>
#include <string.h>

#define SP_USE_SIMPLE_LOGGER
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

typedef struct {
    size_t    index;
    Sp_Batch *batch;
} BatchCmdLogUserData;

static void
batch_cmd_log(unsigned int  level,
              const char   *msg,
              void         *user_data)
{
    BatchCmdLogUserData *ud = (BatchCmdLogUserData *)user_data;

    if (level & SP_LOG_LEVEL_ECHO_CMD) {
        printf("[%zu/%zu] %s\n",
               ud->index,
               ud->batch->cmds.size,
               msg);
        ud->index++;
        return;
    }

    fputs(msg, stderr);
    fputc('\n', stderr);
}

int
child_main(const char *id)
{
    printf("[child %s] Hello\n", id);

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
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        const char *id = (argc > 2) ? argv[2] : "?";
        return child_main(id);
    }

    Sp_Batch batch = sp_batch_init();
    Sp_Cmd   cmd   = sp_cmd_init();
    BatchCmdLogUserData user_data = {.index = 1, .batch = &batch};

    sp_batch_set_logger(&batch, batch_cmd_log, &user_data);

    static const char *ids[] = { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };
    for (size_t i = 0; i < (sizeof(ids) / sizeof(ids[0])); ++i) {
        sp_cmd_add_args(&cmd, argv[0], "--child", ids[i]);
        sp_cmd_redirect_stdout_null(&cmd);
        sp_batch_add_cmd(&batch, &cmd);
        // sp_batch_add_cmd() copies cmd, so we can reuse/reset it.
        sp_cmd_reset(&cmd);
    }
    sp_cmd_free(&cmd);

    // Run up to 3 child processes at once.
    // Passing 0 means "no limit" (spawn all commands concurrently).
    size_t max_parallel = 3;

    // Output order is nondeterministic because children run concurrently.
    int exit_code = sp_batch_run(&batch, max_parallel);
    sp_batch_free(&batch);

    return exit_code;
}
