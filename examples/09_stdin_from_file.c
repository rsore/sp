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
    // Read stdin and count bytes/lines
    char buf[128];
    size_t bytes = 0;
    size_t lines = 0;

    while (fgets(buf, sizeof(buf), stdin)) {
        bytes += strlen(buf);
        lines += 1;
    }

    printf("[child] lines=%zu bytes=%zu\n", lines, bytes);
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

    const char *path = "stdin_input.txt";

    // Create an input file for the child.
    FILE *f = fopen(path, "wb");
    if (!f) {
        SP_LOG_ERROR("fopen failed");
        return 1;
    }
    fputs("first line\n", f);
    fputs("second line\n", f);
    fputs("third line\n", f);
    fclose(f);

    // Spawn child with stdin redirected from that file.
    Sp_Cmd cmd = {0};
    sp_cmd_add_args(&cmd, argv[0], "--child");
    sp_cmd_redirect_stdin_from_file(&cmd, path);

    int exit_code = sp_cmd_exec_sync(&cmd);
    sp_cmd_free(&cmd);

    printf("[parent] ran child with stdin from %s (exit=%d)\n", path, exit_code);
    return exit_code;
}
