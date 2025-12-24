#define SP_IMPLEMENTATION
#define SPDEF static inline
#include "../sp.h"

#include "minitest.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <direct.h>

#  define SP_PATH_SEP "\\"

  static inline void
  ensure_out_dir(void)
  {
      _mkdir("sp_test_out");
  }

  static inline int
  get_self_path(char   *buf,
                size_t  cap)
  {
      DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
      return (n > 0 && n < cap);
  }

#else
#  include <sys/stat.h>
#  include <unistd.h>

#  define SP_PATH_SEP "/"

  static inline void
  ensure_out_dir(void)
  {
      if (mkdir("sp_test_out", 0777) != 0 && errno != EEXIST) {}
  }

  static inline int
  get_self_path(char   *buf,
                size_t  cap)
  {
      // Best-effort Linux
      ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
      if (n <= 0) return 0;
      buf[n] = 0;
      return 1;
  }

#endif

static inline void
normalize_newlines(char *s)
{
    // Convert CRLF -> LF in-place
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\r' && r[1] == '\n') { r++; }
        *w++ = *r++;
    }
    *w = 0;
}

static inline int
file_read_all(const char *path,
              char       *buf,
              size_t      cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = 0;
    fclose(f);
    return 1;
}

static inline int
str_contains(const char *h,
             const char *n)
{
    return h && n && strstr(h, n) != NULL;
}

static inline int
pipe_read_all(SpPipe *p,
              char   *buf,
              size_t  cap)
{
    size_t off = 0;
    while (1) {
        size_t n  = 0;
        int    ok = sp_pipe_read(p, buf + off, (cap - 1) - off, &n);
        if (!ok) return 0;
        if (n == 0) break;
        off += n;
        if (off >= cap - 1) break;
    }
    buf[off] = 0;
    return 1;
}

/* ---------------- child mode ---------------- */

static inline int
sp_child_main(int argc, char **argv)
{
    // argv: --sp-child <mode> [args...]
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
        // strip newline
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        printf("READ:%s\n", line);
        return 0;
    }

    if (strcmp(mode, "spam-stdout") == 0) {
        // argv[3] = bytes
        int bytes = (argc >= 4) ? atoi(argv[3]) : 0;
        for (int i = 0; i < bytes; i++) fputc('A' + (i % 26), stdout);
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
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            fwrite(buf, 1, n, stdout);
        }
        return 0;
    }

#if defined(_WIN32)
    if (strcmp(mode, "sleep-ms") == 0) {
        int ms = (argc >= 4) ? atoi(argv[3]) : 10;
        Sleep((DWORD)ms);
        return 0;
    }
#else
    if (strcmp(mode, "sleep-ms") == 0) {
        int ms = (argc >= 4) ? atoi(argv[3]) : 10;
        usleep((useconds_t)ms * 1000);
        return 0;
    }
#endif

    return 3;
}

static int
pipe_write_all(SpPipe     *p,
               const void *data,
               size_t      len)
{
    const unsigned char *s = (const unsigned char *)data;
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        int ok = sp_pipe_write(p, s + off, len - off, &n);
        if (!ok) return 0;
        off += n; // partial writes allowed
    }
    return 1;
}

static inline void
build_self_child(SpCmd      *cmd,
                 const char *self,
                 const char *mode,
                 const char *arg)
{
    sp_cmd_add_arg(cmd, self);
    sp_cmd_add_arg(cmd, "--sp-child");
    sp_cmd_add_arg(cmd, mode);
    if (arg) sp_cmd_add_arg(cmd, arg);
}




MT_DEFINE_TEST(exec_sync_exit_code)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    build_self_child(&cmd, self, "exit", "7");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 7);

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_pipe_captures)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "stdout", "HELLO_PIPE");

    SpProc p = sp_cmd_exec_async(&cmd);

    char buf[2048];
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
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    sp_cmd_redirect_stderr_to_stdout(&cmd);
    build_self_child(&cmd, self, "both", NULL);

    SpProc p = sp_cmd_exec_async(&cmd);

    char buf[4096];
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

    // Write input file
    FILE *f = fopen("sp_test_out" SP_PATH_SEP "in.txt", "wb");
    MT_ASSERT_THAT(f != NULL);
    fputs("INPUT_VALUE\n", f);
    fclose(f);

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    sp_cmd_redirect_stdin_from_file(&cmd, "sp_test_out" SP_PATH_SEP "in.txt");

    SpPipe out = SP_ZERO_INIT;
    sp_cmd_redirect_stdout_pipe(&cmd, &out);

    build_self_child(&cmd, self, "echo-stdin", NULL);

    SpProc p = sp_cmd_exec_async(&cmd);

    char buf[2048];
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
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    const char *path = "sp_test_out" SP_PATH_SEP "out_trunc.txt";

    SpCmd cmd = SP_ZERO_INIT;
    sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stdout", "HELLO_OUT");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 0);

    char buf[2048];
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_OUT\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_file_append)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    const char *path = "sp_test_out" SP_PATH_SEP "out_append.txt";

    // First write (trunc)
    {
        SpCmd cmd = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
        build_self_child(&cmd, self, "stdout", "LINE1");
        (void)sp_cmd_exec_sync(&cmd);
        sp_cmd_free(&cmd);
    }

    // Second write (append)
    {
        SpCmd cmd = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_APPEND);
        build_self_child(&cmd, self, "stdout", "LINE2");
        (void)sp_cmd_exec_sync(&cmd);
        sp_cmd_free(&cmd);
    }

    char buf[4096];
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "LINE1\n"));
    MT_CHECK_THAT(str_contains(buf, "LINE2\n"));
}

MT_DEFINE_TEST(stderr_file_trunc)
{
    ensure_out_dir();

    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    const char *path = "sp_test_out" SP_PATH_SEP "err_trunc.txt";

    SpCmd cmd = SP_ZERO_INIT;
    sp_cmd_redirect_stderr_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stderr", "HELLO_ERR");

    int code = sp_cmd_exec_sync(&cmd);
    MT_CHECK_THAT(code == 0);

    char buf[2048];
    MT_ASSERT_THAT(file_read_all(path, buf, sizeof(buf)));
    normalize_newlines(buf);
    MT_CHECK_THAT(str_contains(buf, "HELLO_ERR\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdout_null_stderr_pipe)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe err = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_null(&cmd);
    sp_cmd_redirect_stderr_pipe(&cmd, &err);

    // Child writes only to stdout here; we should see nothing on stderr.
    build_self_child(&cmd, self, "stdout", "OUT_SHOULD_BE_NULL");

    SpProc p = sp_cmd_exec_async(&cmd);

    char buf[2048];
    MT_ASSERT_THAT(pipe_read_all(&err, buf, sizeof(buf)));
    sp_pipe_close(&err);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    normalize_newlines(buf);
    MT_CHECK_THAT(buf[0] == '\0'); // stderr should be empty

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(stdin_null_eof)
{
    char self[1024] = SP_ZERO_INIT;
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_null(&cmd);
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "expect-eof-then-print", NULL);

    SpProc p = sp_cmd_exec_async(&cmd);

    char buf[2048];
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
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe inw = SP_ZERO_INIT;
    SpPipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdin_pipe(&cmd, &inw);
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "copy-stdin-to-stdout", NULL);

    SpProc p = sp_cmd_exec_async(&cmd);

    const char *msg = "HELLO_THROUGH_STDIN\nSECOND_LINE\n";
    MT_ASSERT_THAT(pipe_write_all(&inw, msg, strlen(msg)));
    sp_pipe_close(&inw);

    char buf[4096];
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
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;
    SpPipe out = SP_ZERO_INIT;

    sp_cmd_redirect_stdout_pipe(&cmd, &out);

    // 200KB output
    build_self_child(&cmd, self, "spam-stdout", "200000");

    SpProc p = sp_cmd_exec_async(&cmd);

    // Read into a reasonably large buffer; allow truncation if cap is smaller,
    // but ensure we read "a lot" and don't hang/crash.
    static char buf[262144]; // 256KB
    MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
    sp_pipe_close(&out);

    int code = sp_proc_wait(&p);
    MT_CHECK_THAT(code == 0);

    // Expect at least close to 200k bytes read
    MT_CHECK_THAT(strlen(buf) > 150000);

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(cmd_reset_clears_stdio_and_args)
{
    ensure_out_dir();

    char self[1024] = {0};
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    const char *path = "sp_test_out" SP_PATH_SEP "reset_out.txt";

    SpCmd cmd = SP_ZERO_INIT;

    // Run 1: stdout -> file
    sp_cmd_redirect_stdout_to_file(&cmd, path, SP_FILE_WRITE_TRUNC);
    build_self_child(&cmd, self, "stdout", "FIRST");
    int code1 = sp_cmd_exec_sync(&cmd);
    MT_ASSERT_THAT(code1 == 0);

    char filebuf[2048];
    MT_ASSERT_THAT(file_read_all(path, filebuf, sizeof(filebuf)));
    normalize_newlines(filebuf);
    MT_ASSERT_THAT(str_contains(filebuf, "FIRST\n"));

    // Reset should clear args + stdio back to inherit
    sp_cmd_reset(&cmd);

    // Run 2: stdout -> pipe (explicitly set after reset)
    SpPipe out = SP_ZERO_INIT;
    sp_cmd_redirect_stdout_pipe(&cmd, &out);
    build_self_child(&cmd, self, "stdout", "SECOND");

    SpProc p = sp_cmd_exec_async(&cmd);

    char pipebuf[2048];
    MT_ASSERT_THAT(pipe_read_all(&out, pipebuf, sizeof(pipebuf)));
    sp_pipe_close(&out);

    int code2 = sp_proc_wait(&p);
    MT_CHECK_THAT(code2 == 0);

    normalize_newlines(pipebuf);
    MT_CHECK_THAT(str_contains(pipebuf, "SECOND\n"));

    // File should still only contain FIRST (SECOND should NOT have gone to file)
    MT_ASSERT_THAT(file_read_all(path, filebuf, sizeof(filebuf)));
    normalize_newlines(filebuf);
    MT_CHECK_THAT(str_contains(filebuf, "FIRST\n"));
    MT_CHECK_THAT(!str_contains(filebuf, "SECOND\n"));

    sp_cmd_free(&cmd);
}

MT_DEFINE_TEST(cmd_reset_clears_pipe_config)
{
    char self[1024] = {0};
    MT_ASSERT_THAT(get_self_path(self, sizeof(self)));

    SpCmd cmd = SP_ZERO_INIT;

    // First run: stdout -> pipe
    {
        SpPipe out = SP_ZERO_INIT;
        sp_cmd_redirect_stdout_pipe(&cmd, &out);
        build_self_child(&cmd, self, "stdout", "ONE");

        SpProc p = sp_cmd_exec_async(&cmd);

        char buf[2048];
        MT_ASSERT_THAT(pipe_read_all(&out, buf, sizeof(buf)));
        sp_pipe_close(&out);

        int code = sp_proc_wait(&p);
        MT_ASSERT_THAT(code == 0);
    }

    sp_cmd_reset(&cmd);

    // Second run: stderr -> pipe only
    {
        SpPipe err = SP_ZERO_INIT;
        sp_cmd_redirect_stderr_pipe(&cmd, &err);
        build_self_child(&cmd, self, "stderr", "TWO");

        SpProc p = sp_cmd_exec_async(&cmd);

        char buf[2048];
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



int main(int argc, char **argv)
{
    // child mode entry
    if (argc >= 2 && strcmp(argv[1], "--sp-child") == 0) {
        return sp_child_main(argc, argv);
    }

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

    MT_PRINT_SUMMARY();
    return MT_EXIT_CODE;
}
