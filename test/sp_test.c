#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#define SP_IMPLEMENTATION
#define SP_EMBED_LICENSE
#define SPDEF static inline
#include "../sp.h"

#include "minitest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *g_argv0 = NULL;

#if defined(_WIN32)

#include <windows.h>
#include <direct.h>

#define SP_PATH_SEP "\\"

static inline void
ensure_out_dir(void)
{
    _mkdir("sp_test_out");
}

static inline int
get_self_path(char        *buf,
              size_t       cap,
              const char  *argv0)
{
    (void)argv0;
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
    return (n > 0 && n < cap);
}

static inline void
sp_sleep_ms(int ms)
{
    Sleep((DWORD)ms);
}

#else

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#define SP_PATH_SEP "/"

static inline void
ensure_out_dir(void)
{
    if (mkdir("sp_test_out", 0777) != 0 && errno != EEXIST) {}
}

static inline int
get_self_path(char        *buf,
              size_t       cap,
              const char  *argv0)
{
    (void)argv0; // Unused on some platforms
#if defined(__APPLE__)
    uint32_t size = (uint32_t)cap;
    if (_NSGetExecutablePath(buf, &size) != 0) return 0;
    return 1;
#elif defined(__linux__)
    ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n <= 0 || (size_t)n >= cap) return 0;
    buf[n] = 0;
    return 1;
#else
    if (!argv0 || !argv0[0]) return 0;
    strncpy(buf, argv0, cap - 1);
    buf[cap - 1] = 0;
    return 1;
#endif
}

static inline void
sp_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

#endif

static inline void
normalize_newlines(char *s)
{
    char *r = s;
    char *w = s;
    while (*r) {
        if (r[0] == '\r' && r[1] == '\n') r++;
        *w++ = *r++;
    }
    *w = 0;
}

static inline int
file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

static inline void
file_remove(const char *path)
{
    (void)remove(path);
}

static inline int
file_read_all(const char  *path,
              char        *buf,
              size_t       cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = 0;
    fclose(f);
    return 1;
}

static inline int
str_contains(const char  *haystack,
             const char  *needle)
{
    return haystack && needle && strstr(haystack, needle) != NULL;
}

static inline int
pipe_read_all(Sp_Pipe *p,
              char    *buf,
              size_t   cap)
{
    size_t off = 0;
    for (;;) {
        size_t n = 0;
        if (!sp_pipe_read(p, buf + off, (cap - 1) - off, &n)) return 0;
        if (n == 0) break;
        off += n;
        if (off >= cap - 1) break;
    }
    buf[off] = 0;
    return 1;
}

static inline int
pipe_write_all(Sp_Pipe    *p,
               const void *data,
               size_t      len)
{
    const unsigned char *s = (const unsigned char *)data;
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        if (!sp_pipe_write(p, s + off, len - off, &n)) return 0;
        off += n;
    }
    return 1;
}

static inline void
build_self_child(Sp_Cmd     *cmd,
                 const char *self,
                 const char *mode,
                 const char *arg)
{
    sp_cmd_add_arg(cmd, self);
    sp_cmd_add_arg(cmd, "--sp-child");
    sp_cmd_add_arg(cmd, mode);
    if (arg) sp_cmd_add_arg(cmd, arg);
}


static inline void
build_self_child_write_file_exit(Sp_Cmd     *cmd,
                                 const char *self,
                                 const char *path,
                                 const char *content,
                                 int         exit_code)
{
    char code_buf[32];
    snprintf(code_buf, sizeof(code_buf), "%d", exit_code);

    sp_cmd_add_arg(cmd, self);
    sp_cmd_add_arg(cmd, "--sp-child");
    sp_cmd_add_arg(cmd, "write-file-exit");
    sp_cmd_add_arg(cmd, path);
    sp_cmd_add_arg(cmd, content);
    sp_cmd_add_arg(cmd, code_buf);
}

static inline int
sp_child_main(int     argc,
              char  **argv)
{
    if (argc < 3) return 2;
    const char *mode = argv[2];

    if (strcmp(mode, "exit") == 0) {
        int code = (argc >= 4) ? atoi(argv[3]) : 0;
        return code;
    }

    if (strcmp(mode, "stdout") == 0) {
        const char *msg = (argc >= 4) ? argv[3] : "OUT";
        fputs(msg, stdout);
        fputs("\n", stdout);
        return 0;
    }

    if (strcmp(mode, "stderr") == 0) {
        const char *msg = (argc >= 4) ? argv[3] : "ERR";
        fputs(msg, stderr);
        fputs("\n", stderr);
        return 0;
    }

    if (strcmp(mode, "both") == 0) {
        fputs("OUT_LINE\n", stdout);
        fputs("ERR_LINE\n", stderr);
        return 0;
    }

    if (strcmp(mode, "echo-stdin") == 0) {
        char line[512];
        if (!fgets(line, sizeof(line), stdin)) {
            fputs("EOF\n", stdout);
            return 0;
        }
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        printf("READ:%s\n", line);
        return 0;
    }

    if (strcmp(mode, "expect-eof-then-print") == 0) {
        int c = fgetc(stdin);
        if (c == EOF) {
            fputs("AFTER\n", stdout);
            return 0;
        }
        fputs("NOT_EOF\n", stdout);
        return 0;
    }

    if (strcmp(mode, "copy-stdin-to-stdout") == 0) {
        char buf[1024];
        size_t n = 0;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            fwrite(buf, 1, n, stdout);
        }
        return 0;
    }

    if (strcmp(mode, "spam-stdout") == 0) {
        int bytes = (argc >= 4) ? atoi(argv[3]) : 0;
        for (int i = 0; i < bytes; i++) fputc('A' + (i % 26), stdout);
        return 0;
    }

    if (strcmp(mode, "sleep-ms") == 0) {
        int ms = (argc >= 4) ? atoi(argv[3]) : 10;
        sp_sleep_ms(ms);
        return 0;
    }

        if (strcmp(mode, "write-file-exit") == 0) {
        if (argc < 6) return 2;

        const char *path = argv[3];
        const char *text = argv[4];
        int exit_code = atoi(argv[5]);

        FILE *f = fopen(path, "wb");
        if (!f) return 4;
        fputs(text, f);
        fclose(f);

        return exit_code;
    }

if (strcmp(mode, "write-file-after-sleep") == 0) {
        if (argc < 6) return 2;

        const char *path = argv[3];
        const char *text = argv[4];
        int ms = atoi(argv[5]);

        sp_sleep_ms(ms);

        FILE *f = fopen(path, "wb");
        if (!f) return 4;
        fputs(text, f);
        fclose(f);

        return 0;
    }

    return 3;
}

MT_DEFINE_TEST(exec_sync_exit_code)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd cmd = SP_ZERO_INIT;
    build_self_child(&cmd, self, "exit", "7");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 7);

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_pipe_captures)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "stdout", "HELLO_PIPE");

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_PIPE\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stderr_to_stdout_merge_pipe)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    sp_cmd_redirect_stderr_to_stdout(&cmd);
    build_self_child(&cmd, self, "both", NULL);

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char buf[4096] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "OUT_LINE\n"));
    MT_CHECK_THAT(str_contains(buf, "ERR_LINE\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdin_from_file)
{
    ensure_out_dir();

    {
        FILE *f = fopen("sp_test_out" SP_PATH_SEP "in.txt", "wb");
        MT_ASSERT_THAT(f != NULL);
        fputs("INPUT_VALUE\n", f);
        fclose(f);
    }

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_from_file(&cmd, "sp_test_out" SP_PATH_SEP "in.txt");
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "echo-stdin", NULL);

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "READ:INPUT_VALUE\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_file_trunc)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *path = "sp_test_out" SP_PATH_SEP "out_trunc.txt";

    Sp_Cmd cmd = SP_ZERO_INIT;
    sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stdout", "HELLO_OUT");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 0);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_OUT\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_file_append)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *path = "sp_test_out" SP_PATH_SEP "out_append.txt";

    {
        Sp_Cmd cmd = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
        build_self_child(&cmd, self, "stdout", "LINE1");
        (void)sp_cmd_exec_sync(&cmd);
        sp_cmd_free(&cmd);
    }

    {
        Sp_Cmd cmd = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_APPEND);
        build_self_child(&cmd, self, "stdout", "LINE2");
        (void)sp_cmd_exec_sync(&cmd);
        sp_cmd_free(&cmd);
    }

    char buf[4096] = SP_ZERO_INIT;
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "LINE1\n"));
    MT_CHECK_THAT(str_contains(buf, "LINE2\n"));
}

MT_DEFINE_TEST(stderr_file_trunc)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *path = "sp_test_out" SP_PATH_SEP "err_trunc.txt";

    Sp_Cmd cmd = SP_ZERO_INIT;
    sp_cmd_redirect_stderr_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stderr", "HELLO_ERR");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 0);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_ERR\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_null_stderr_pipe)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe err = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_pipe(&cmd, &err);
    build_self_child(&cmd, self, "stdout", "OUT_SHOULD_BE_NULL");

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&err, buf, sizeof(buf)));
    sp_pipe_close(&err);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(buf[0] == '\0');

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdin_null_eof)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "expect-eof-then-print", NULL);

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char buf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "AFTER\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdin_pipe_roundtrip)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe inw = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_pipe(&cmd, &inw);
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "copy-stdin-to-stdout", NULL);

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    const char *msg = "HELLO_THROUGH_STDIN\nSECOND_LINE\n";
    MT_ASSERT_THAT(pipe_write_all(&inw, msg, strlen(msg)));
    sp_pipe_close(&inw);

    char buf[4096] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_THROUGH_STDIN\n"));
    MT_CHECK_THAT(str_contains(buf, "SECOND_LINE\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_pipe_large_output)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd  cmd = SP_ZERO_INIT;
    Sp_Pipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "spam-stdout", "200000");

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    static char buf[262144];
    buf[0] = 0;
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    MT_CHECK_THAT(strlen(buf) > 150000);

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(cmd_reset_clears_stdio_and_args)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *path = "sp_test_out" SP_PATH_SEP "reset_out.txt";

    Sp_Cmd cmd = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stdout", "FIRST");
    int code1 = sp_cmd_exec_sync(&cmd);
    MT_ASSERT_THAT(code1 == 0);

    char filebuf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(file_read_all(path, filebuf, sizeof(filebuf)));
    normalize_newlines(filebuf);
    MT_ASSERT_THAT(str_contains(filebuf, "FIRST\n"));

    sp_cmd_reset(&cmd);

    Sp_Pipe out = SP_ZERO_INIT;
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "stdout", "SECOND");

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    char pipebuf[2048] = SP_ZERO_INIT;
    MT_ASSERT_THAT(pipe_read_all(&out, pipebuf, sizeof(pipebuf)));
    sp_pipe_close(&out);

    int code2 = sp_proc_wait(&p);
    MT_CHECK_THAT(code2 == 0);

    normalize_newlines(pipebuf);
    MT_CHECK_THAT(str_contains(pipebuf, "SECOND\n"));

    MT_ASSERT_THAT(file_read_all(path, filebuf, sizeof(filebuf)));
    normalize_newlines(filebuf);
    MT_CHECK_THAT(str_contains(filebuf, "FIRST\n"));
    MT_CHECK_THAT(!str_contains(filebuf, "SECOND\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(cmd_reset_clears_pipe_config)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    Sp_Cmd cmd = SP_ZERO_INIT;

    {
        Sp_Pipe out = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_pipe(&cmd, &out);
        build_self_child(&cmd, self, "stdout", "ONE");

        Sp_Proc p = sp_cmd_exec_async(&cmd);

        char buf[2048] = SP_ZERO_INIT;
        MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
        sp_pipe_close(&out);

        int code = sp_proc_wait(&p);
        MT_ASSERT_THAT(code == 0);
    }

    sp_cmd_reset(&cmd);

    {
        Sp_Pipe err = SP_ZERO_INIT;
        sp_cmd_redirect_stderr_pipe(&cmd, &err);
        build_self_child(&cmd, self, "stderr", "TWO");

        Sp_Proc p = sp_cmd_exec_async(&cmd);

        char buf[2048] = SP_ZERO_INIT;
        MT_ASSERT_THAT(pipe_read_all(&err, buf, sizeof(buf)));
        sp_pipe_close(&err);

        int code = sp_proc_wait(&p);
        MT_CHECK_THAT(code == 0);

        normalize_newlines(buf);
        MT_CHECK_THAT(str_contains(buf, "TWO\n"));
        MT_CHECK_THAT(!str_contains(buf, "ONE\n"));
    }

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(cmd_multiple_args_in_one)
{
    Sp_Cmd cmd = SP_ZERO_INIT;

    sp_cmd_add_args(&cmd, "foo", "bar", "baz");
    MT_ASSERT_THAT(cmd.args.size == 3);
    sp_cmd_add_args(&cmd, "foo");
    MT_ASSERT_THAT(cmd.args.size == 4);

   const char *some_args[] = {"hello", "world"};
   sp_cmd_add_args_n(&cmd, some_args, 2);
   MT_ASSERT_THAT(cmd.args.size == 6);

   sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(proc_detach_allows_child_to_finish)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *path = "sp_test_out" SP_PATH_SEP "detach.txt";
    file_remove(path);

    Sp_Cmd cmd = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_null(&cmd);

    sp_cmd_add_arg(&cmd, self);
    sp_cmd_add_arg(&cmd, "--sp-child");
    sp_cmd_add_arg(&cmd, "write-file-after-sleep");
    sp_cmd_add_arg(&cmd, path);
    sp_cmd_add_arg(&cmd, "DETACH_OK\n");
    sp_cmd_add_arg(&cmd, "100");

    Sp_Proc p = sp_cmd_exec_async(&cmd);

    sp_proc_detach(&p);
    sp_proc_detach(&p);

    char buf[1024] = SP_ZERO_INIT;
    int ok = 0;

    for (int i = 0; i < 200; i++) {
        if (file_exists(path)) {
            if (file_read_all(path, buf, sizeof(buf))) {
                normalize_newlines(buf);
                if (str_contains(buf, "DETACH_OK\n")) {
                    ok = 1;
                    break;
                }
            }
        }
        sp_sleep_ms(10);
    }

    MT_CHECK_THAT(ok);

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(batch_exec_sync_fail_fast_sequential)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self), g_argv0));

    const char *p1 = "sp_test_out" SP_PATH_SEP "batch_1.txt";
    const char *p2 = "sp_test_out" SP_PATH_SEP "batch_2.txt";
    const char *p3 = "sp_test_out" SP_PATH_SEP "batch_3.txt";

    (void)remove(p1);
    (void)remove(p2);
    (void)remove(p3);

    Sp_Batch batch = SP_ZERO_INIT;
    Sp_Cmd   cmd   = SP_ZERO_INIT;

    sp_cmd_reset(&cmd);
    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_null(&cmd);
    build_self_child_write_file_exit(&cmd, self, p1, "OK1\n", 0);
    sp_batch_add_cmd(&batch, &cmd);

    sp_cmd_reset(&cmd);
    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_null(&cmd);
    build_self_child_write_file_exit(&cmd, self, p2, "FAIL2\n", 7);
    sp_batch_add_cmd(&batch, &cmd);

    sp_cmd_reset(&cmd);
    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_null(&cmd);
    build_self_child_write_file_exit(&cmd, self, p3, "SHOULD_NOT_RUN\n", 0);
    sp_batch_add_cmd(&batch, &cmd);

    int code = sp_batch_exec_sync(&batch, 1);
    MT_CHECK_THAT(code == 7);

    MT_CHECK_THAT(file_exists(p1));
    MT_CHECK_THAT(file_exists(p2));
    MT_CHECK_THAT(!file_exists(p3));

    sp_cmd_free(&cmd);
    sp_batch_free(&batch);
}


int
main(int     argc,
     char  **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--sp-child") == 0) {
        return sp_child_main(argc, argv);
    }

    g_argv0 = (argc >= 1) ? argv[0] : NULL;

    MT_INIT();

    MT_RUN_TEST(exec_sync_exit_code);
    MT_RUN_TEST(stdout_pipe_captures);
    MT_RUN_TEST(stderr_to_stdout_merge_pipe);
    MT_RUN_TEST(stdin_from_file);
    MT_RUN_TEST(stdout_file_trunc);
    MT_RUN_TEST(stdout_file_append);
    MT_RUN_TEST(stderr_file_trunc);
    MT_RUN_TEST(stdout_null_stderr_pipe);
    MT_RUN_TEST(stdin_null_eof);
    MT_RUN_TEST(stdin_pipe_roundtrip);
    MT_RUN_TEST(stdout_pipe_large_output);
    MT_RUN_TEST(cmd_reset_clears_stdio_and_args);
    MT_RUN_TEST(cmd_reset_clears_pipe_config);
    MT_RUN_TEST(cmd_multiple_args_in_one);
    MT_RUN_TEST(proc_detach_allows_child_to_finish);
    MT_RUN_TEST(batch_exec_sync_fail_fast_sequential);

    MT_PRINT_SUMMARY();
    return MT_EXIT_CODE;
}
