#define SP_LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO] " fmt "\n", __VA_ARGS__)
#define SP_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", __VA_ARGS__)
#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "sp.h"

#include <stdio.h>

/* int */
/* main(void) */
/* { */
/*     SpCmd cmd = {0}; */
/*     SpPipe out = {0}; */

/*     sp_cmd_add_arg(&cmd, "cmd.exe"); */
/*     sp_cmd_add_arg(&cmd, "/C"); */
/*     sp_cmd_add_arg(&cmd, "echo HELLO_PIPE"); */

/*     sp_cmd_redirect_stdout_pipe(&cmd, &out); */

/*     SpProc p = sp_cmd_exec_async(&cmd); */

/*     char buf[256]; */
/*     size_t n = 0; */
/*     while (sp_pipe_read(&out, buf, sizeof(buf), &n) && n > 0) { */
/*         fwrite(buf, 1, n, stdout); */
/*     } */
/*     sp_pipe_close(&out); */

/*     int code = sp_proc_wait(&p); */
/*     printf("\nexit=%d\n", code); */

/*     sp_cmd_free(&cmd); */

/*     return 0; */
/* } */

static int file_read_all(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return 1;
}

static int str_contains(const char *haystack, const char *needle)
{
    return haystack && needle && strstr(haystack, needle) != NULL;
}

static void cmd_build_cmdexe(SpCmd *cmd, const char *line)
{
    // cmd.exe /C "<line>"
    sp_cmd_add_arg(cmd, "cmd.exe");
    sp_cmd_add_arg(cmd, "/C");
    sp_cmd_add_arg(cmd, line);
}

static void cmd_build_cmdexe_delayed(SpCmd *cmd, const char *line)
{
    sp_cmd_add_arg(cmd, "cmd.exe");
    sp_cmd_add_arg(cmd, "/V:ON");
    sp_cmd_add_arg(cmd, "/C");
    sp_cmd_add_arg(cmd, line);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    // Basic setup
    system("cmd.exe /C mkdir sp_test_out >NUL 2>&1");

    char buf[8192];

    // 1) stdout -> file trunc
    {
        printf("[1] stdout -> file (trunc)\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\out1.txt", SP_FILE_WRITE_TRUNC);
        cmd_build_cmdexe(&cmd, "echo HELLO_OUT");

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\out1.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read out1.txt\n");
        } else if (!str_contains(buf, "HELLO_OUT")) {
            printf("  FAIL: out1.txt missing HELLO_OUT. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 2) stdout -> file append
    {
        printf("[2] stdout -> file (append)\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\out2.txt", SP_FILE_WRITE_TRUNC);
        cmd_build_cmdexe(&cmd, "echo LINE1");
        (void)sp_cmd_exec_sync(&cmd);

        sp_cmd_reset(&cmd);

        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\out2.txt", SP_FILE_WRITE_APPEND);
        cmd_build_cmdexe(&cmd, "echo LINE2");
        (void)sp_cmd_exec_sync(&cmd);

        if (!file_read_all("sp_test_out\\out2.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read out2.txt\n");
        } else if (!str_contains(buf, "LINE1") || !str_contains(buf, "LINE2")) {
            printf("  FAIL: out2.txt missing LINE1/LINE2. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 3) stderr -> file trunc (and stdout inherit)
    {
        printf("[3] stderr -> file (trunc)\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stderr_to_file(&cmd, "sp_test_out\\err1.txt", SP_FILE_WRITE_TRUNC);

        // This prints to stderr:
        //   1>&2 sends stdout to stderr (in cmd)
        cmd_build_cmdexe(&cmd, "echo HELLO_ERR 1>&2");

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\err1.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read err1.txt\n");
        } else if (!str_contains(buf, "HELLO_ERR")) {
            printf("  FAIL: err1.txt missing HELLO_ERR. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 4) stderr -> stdout merge, stdout -> file
    {
        printf("[4] merge stderr->stdout, stdout -> file\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\merged.txt", SP_FILE_WRITE_TRUNC);
        sp_cmd_redirect_stderr_to_stdout(&cmd);

        // Emit one line to stdout and one to stderr
        cmd_build_cmdexe(&cmd, "echo OUT_LINE & echo ERR_LINE 1>&2");

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\merged.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read merged.txt\n");
        } else if (!str_contains(buf, "OUT_LINE") || !str_contains(buf, "ERR_LINE")) {
            printf("  FAIL: merged.txt missing OUT_LINE/ERR_LINE. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 5) stdout null, stderr file (ensure stdout is suppressed)
    {
        printf("[5] stdout -> null, stderr -> file\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdout_null(&cmd);
        sp_cmd_redirect_stderr_to_file(&cmd, "sp_test_out\\err2.txt", SP_FILE_WRITE_TRUNC);

        // stdout + stderr both produced; stdout should go to NUL, stderr to file.
        cmd_build_cmdexe(&cmd, "echo OUT_SHOULD_BE_NULL & echo ERR_SHOULD_BE_IN_FILE 1>&2");

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\err2.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read err2.txt\n");
        } else if (!str_contains(buf, "ERR_SHOULD_BE_IN_FILE")) {
            printf("  FAIL: err2.txt missing expected stderr line. Got: %s\n", buf);
        } else if (str_contains(buf, "OUT_SHOULD_BE_NULL")) {
            printf("  FAIL: stdout line leaked into stderr file. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 6) stdin from file (cmd reads from stdin via SET /P)
    {
        printf("[6] stdin <- file\n");
        // Create input file with content
        FILE *f = fopen("sp_test_out\\in1.txt", "wb");
        if (!f) {
            printf("  FAIL: could not create in1.txt\n");
        } else {
            fputs("INPUT_VALUE\r\n", f);
            fclose(f);
        }

        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdin_from_file(&cmd, "sp_test_out\\in1.txt");
        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\in_read.txt", SP_FILE_WRITE_TRUNC);

        // SET /P reads a line from stdin into variable X; then echo it.
        cmd_build_cmdexe_delayed(&cmd, "set /p X= & echo READ:!X!");
        /* cmd_build_cmdexe(&cmd, "set /p X= & echo READ:%X%"); */

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\in_read.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read in_read.txt\n");
        } else if (!str_contains(buf, "READ:INPUT_VALUE")) {
            printf("  FAIL: stdin read did not work. Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    // 7) stdin null (program should see EOF and not block)
    {
        printf("[7] stdin <- null (should not block)\n");
        SpCmd cmd = SP_ZERO_INIT;

        sp_cmd_redirect_stdin_null(&cmd);
        sp_cmd_redirect_stdout_to_file(&cmd, "sp_test_out\\stdin_null.txt", SP_FILE_WRITE_TRUNC);

        // If stdin is EOF immediately, SET /P sets empty; we then echo AFTER.
        cmd_build_cmdexe(&cmd, "set /p X= & echo AFTER");

        int code = sp_cmd_exec_sync(&cmd);
        if (code != 0) printf("  FAIL: exit code %d\n", code);

        if (!file_read_all("sp_test_out\\stdin_null.txt", buf, sizeof(buf))) {
            printf("  FAIL: could not read stdin_null.txt\n");
        } else if (!str_contains(buf, "AFTER")) {
            printf("  FAIL: did not reach AFTER (stdin null might have blocked). Got: %s\n", buf);
        } else {
            printf("  OK\n");
        }

        sp_cmd_free(&cmd);
    }

    printf("Done.\n");
    return 0;
}



/* #include <stdio.h> */

/* #define SP_LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO] " fmt "\n", __VA_ARGS__) */
/* #define SP_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", __VA_ARGS__) */
/* #define SP_IMPLEMENTATION */
/* #define SPDEF static inline */
/* #include "sp.h" */

/* int */
/* main(void) */
/* { */
/*     setvbuf(stdout, NULL, _IONBF, 0); */

/*     SpCmd cmd = {0}; */
/*     sp_cmd_reset(&cmd); */
/*     sp_cmd_add_arg(&cmd, "ping"); */
/*     sp_cmd_add_arg(&cmd, "127.0.0.1s"); */
/*     sp_cmd_add_arg(&cmd, "-n"); */
/*     sp_cmd_add_arg(&cmd, "3"); */

/*     sp_cmd_redirect_stdout_to_file(&cmd, "ping_output.txt", SP_FILE_WRITE_APPEND); */
/*     sp_cmd_redirect_stderr_to_file(&cmd, "ping_output_err.txt", SP_FILE_WRITE_TRUNC); */

/*     SpProc p = sp_cmd_exec_async(&cmd); */

/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */
/*     printf("bing-bong\n"); */

/*     printf("Exit code: %d\n", sp_proc_wait(&p)); */

/*     sp_cmd_free(&cmd); */

/*     return 0; */
/* } */
