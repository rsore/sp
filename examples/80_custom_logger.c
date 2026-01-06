#include <stdio.h>
#include <string.h>

// Define a default logger
#define SP_LOG(level, msg)                      \
    do {                                        \
        if  (level == SP_LOG_LEVEL_ECHO_CMD) {  \
            printf("CMD: %s\n", msg);           \
            break;                              \
        }                                       \
        fputs(msg, stderr);                     \
                                                \
    } while (0)

#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

typedef struct {
    size_t    index;
    Sp_Batch *batch;
} BatchCmdLogUserData;

// More fancy runtime logger with user-data, intended
// for use with a batch, to label indices of commands
// ([1/12], [2/12], [3/12], ...)
static void
batch_cmd_log(unsigned int  level,
              const char   *msg,
              void         *user_data)
{
    BatchCmdLogUserData *ud = (BatchCmdLogUserData *)user_data;

    if (level & SP_LOG_LEVEL_ECHO_CMD) {
        size_t total = ud->batch->cmds.size;

        int width = 1;
        for (size_t t = total; t >= 10; t /= 10) {
            width++;
        }

        printf("[%*zu/%zu] %s\n",
               width,
               ud->index,
               total,
               msg);

        ud->index++;
        return;
    }

    fputs(msg, stderr);
    fputc('\n', stderr);
}

int
child_standalone_main()
{
    puts("[child] Some standalone program");

    return 0;
}

int
child_batch_main(const char *id)
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

    Sp_Cmd   cmd   = sp_cmd_init();
    Sp_Batch batch = sp_batch_init();

    if (argc > 1 && strcmp(argv[1], "--child-standalone") == 0) {
        return child_standalone_main();
    }

    if (argc > 1 && strcmp(argv[1], "--child-batch") == 0) {
        const char *id = (argc > 2) ? argv[2] : "?";
        return child_batch_main(id);
    }

    // Child with SP_LOG() logger
    sp_cmd_add_args(&cmd, argv[0], "--child-standalone");
    sp_cmd_redirect_stdout_null(&cmd);
    int exit_code = sp_cmd_exec_sync(&cmd);
    if (exit_code != 0) goto done;

    // Batch with custom runtime logger
    BatchCmdLogUserData user_data = {
        .index = 1,
        .batch = &batch
    };
    // Set a logger for all the commands in the batch.
    sp_batch_set_logger(&batch, batch_cmd_log, &user_data);
    // Set a custom log mask to filter away log messages you don't want
    sp_batch_set_log_mask(&batch, SP_LOG_LEVEL_ECHO_CMD | SP_LOG_LEVEL_ERROR);

    // You can also set logger and mask per command, using the equivelant
    // `sp_cmd_set_logger` and `sp_cmd_set_log_mask`.

    static const char *ids[] = { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };
    for (size_t i = 0; i < (sizeof(ids) / sizeof(ids[0])); ++i) {
        sp_cmd_reset(&cmd);
        sp_cmd_add_args(&cmd, argv[0], "--child-batch", ids[i]);
        sp_cmd_redirect_stdout_null(&cmd);
        sp_batch_add_cmd(&batch, &cmd);
    }

    size_t max_parallel = 3;
    exit_code = sp_batch_run(&batch, max_parallel);

done:
    sp_cmd_free(&cmd);
    sp_batch_free(&batch);

    return exit_code;
}
