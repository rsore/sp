/**
 * sp.h — Cross-platform API for subprocess management,
 *        targeting Windows and POSIX.
 *
 * Version: 0.1.0
 *
 * ~~ LIBRARY INTEGRATION ~~
 * `sp.h` is a single-header C and C++ library, and can easily be integrated
 * in your project by defining SP_IMPLEMENTATION in one translation unit before
 * including the header. This will prompt `sp.h` to include all function
 * definitions in that translation unit.
 *
 * ~~ CUSTOMIZATION ~~
 * Certain behavior of `sp.h` can be customized by defining some
 * preprocessor definitions before including the `sp.h`:
 *  - SP_IMPLEMENTATION .......................... Include all function definitions.
 *  - SPDEF ...................................... Prefixed to all functions.
 *                                                 Example: `#define SPDEF static inline`
 *                                                 Default: Nothing
 *  - SP_ASSERT(cond) ............................ Assertion function for `sp.h` to use.
 *                                                 Default: libc assert.
 *  - SP_LOG_INFO(fmt, ...) ...................... Used to print commands as they are run.
 *                                                 Uses printf-style formatting.
 *                                                 Default: Nothing.
 *  - SP_LOG_ERROR(fmt, ...) ..................... Used to print error messages as they occur.
 *                                                 Uses printf-style formatting.
 *                                                 Default: Nothing.
 *  - SP_REALLOC(ptr, new_size) && SP_FREE(ptr) .. Define custom allocators for `sp.h`.
 *                                                 Must match the semantics of libc realloc and free.
 *                                                 Default: `libc realloc` and `libc free`.
 *
 * ~~ NOTES ~~
 * - When a subprocess inherits the console, its output may appear before
 *   the parent process's stdout output due to C runtime buffering.
 *   If ordered or interleaved output is required, disable buffering or
 *   flush explicitly (e.g. setvbuf(stdout, NULL, _IONBF, 0)).
 *
 * ~~ ATTRIBUTION ~~
 * Some of the implementation of `sp.h` is inspired/based on Tsoding's
 * `nob.h` (public domain). Specifically the subprocess-related parts of `nob.h`.
 * https://github.com/tsoding/nob.h/blob/7deb15dcdbcb113794b79c60aabea6bada50aa93/nob.h
 *
 * ~~ LICENSE ~~
 * `sp.h` is licensed under the 3-Clause BSD license. Full license text is
 * at the end of this file.
 */


#ifndef SP_H_INCLUDED_
#define SP_H_INCLUDED_

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifndef SPDEF
#  define SPDEF
#endif

#ifndef SP_ASSERT
#  include <assert.h>
#  define SP_ASSERT(cond) assert((cond))
#endif

#if defined(SP_REALLOC) != defined(SP_FREE)
#  error "IF YOU DEFINE ONE OF SP_REALLOC OR SP_FREE, THEN BOTH SP_REALLOC AND SP_FREE MUST BE DEFINED"
#else
#endif
#ifndef SP_REALLOC
#  define SP_REALLOC(ptr, new_size) realloc((ptr), (new_size))
#endif
#ifndef SP_FREE
#  define SP_FREE(ptr) free((ptr))
#endif

#ifndef SP_LOG_INFO
#  define SP_LOG_INFO(fmt, ...) ((void)(0))
#endif

#ifndef SP_LOG_ERROR
#  define SP_LOG_ERROR(fmt, ...) ((void)(0))
#endif

#ifdef __cplusplus
#  define SP_NOEXCEPT noexcept
#else
#  define SP_NOEXCEPT
#endif

#if defined(__cplusplus) && (__cplusplus >= 201703L)
#  define SP_NODISCARD [[nodiscard]]
#else
#  define SP_NODISCARD
#endif

#ifndef SP_NATIVE_MAX
  #define SP_NATIVE_MAX (sizeof(void*))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char   *buffer;
    size_t  size;
    size_t  capacity;
} SpString;

// Dynamic array
typedef struct {
    SpString *buffer;
    size_t    size;
    size_t    capacity;
} SpStrings;

typedef enum {
    SP_REDIR_INHERIT = 0,   // use parent's std handle
    SP_REDIR_NULL,          // /dev/null or NUL, no output
    SP_REDIR_FILE,          // path-based file
    SP_REDIR_PIPE,          // create pipe (parent keeps one end)
    SP_REDIR_TO_STDOUT,     // merge stderr into stdout
} SpRedirKind;

typedef enum {
    SP_FILE_READ = 0,       // for stdin
    SP_FILE_WRITE_TRUNC,    // for stdout/stderr
    SP_FILE_WRITE_APPEND    // for stdout/stderr
} SpFileMode;

typedef enum {
    SP_PIPE_READ  = 1, // parent reads (child writes)
    SP_PIPE_WRITE = 2  // parent writes (child reads)
} SpPipeMode;

typedef struct {
    unsigned char handle[SP_NATIVE_MAX];
    unsigned char handle_size;
    SpPipeMode    mode;
} SpPipe;

typedef struct {
    SpRedirKind kind;

    // file config
    SpString   file_path;
    SpFileMode file_mode;

    // pipe config
    SpPipe    *out_pipe;
} SpRedirect;

typedef struct {
    SpRedirect stdin_redir;
    SpRedirect stdout_redir;
    SpRedirect stderr_redir;
} SpStdio;

// Command builder
typedef struct {
    SpStrings args;
    size_t internal_strings_already_initted; // We reuse allocated strings after cmd_reset

    SpStdio stdio;
} SpCmd;

// Dynamic array
typedef struct {
    SpCmd  *buffer;
    size_t  size;
    size_t  capacity;
} SpCmds;

// Process in flight
typedef struct {
  // Handle is different per platform (HANDLE vs pid_t)
  unsigned char handle[SP_NATIVE_MAX];
  unsigned char handle_size;
} SpProc;

// Dynamic array
typedef struct {
    SpProc *buffer;
    size_t  size;
    size_t  capacity;
} SpProcs;


// Adds arg to cmd, may allocate memory
SPDEF void sp_cmd_add_arg(SpCmd *cmd, const char *arg) SP_NOEXCEPT;

// *out_n == 0 means EOF (child closed its end).
SP_NODISCARD SPDEF int sp_pipe_read(SpPipe *p, void *buf, size_t cap, size_t *out_n) SP_NOEXCEPT;
// Partial writes are allowed; check *out_n.
SP_NODISCARD SPDEF int sp_pipe_write(SpPipe *p, const void *buf, size_t len, size_t *out_n) SP_NOEXCEPT;
// Always succeeds; safe to call multiple times.
SPDEF void sp_pipe_close(SpPipe *p) SP_NOEXCEPT;

// Redirection of stdout, stderr and stdin. Call these to configure cmd *before*
// calling any exec function. Default behavior is subprocess inherits stdio
// of calling process.
SPDEF void sp_cmd_redirect_stdin_null(SpCmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdin_from_file(SpCmd *cmd, const char *path) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdout_null(SpCmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdout_to_file(SpCmd *cmd, const char *path, SpFileMode mode) SP_NOEXCEPT; // mode: TRUNC/APPEND
SPDEF void sp_cmd_redirect_stderr_null(SpCmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stderr_to_file(SpCmd *cmd, const char *path, SpFileMode mode) SP_NOEXCEPT; // mode: TRUNC/APPEND
SPDEF void sp_cmd_redirect_stderr_to_stdout(SpCmd *cmd) SP_NOEXCEPT; // merge 2>&1
SPDEF void sp_cmd_redirect_stdin_pipe(SpCmd *cmd, SpPipe *out_write) SP_NOEXCEPT; // parent writes -> child stdin.  *out_write becomes valid after successful exec
SPDEF void sp_cmd_redirect_stdout_pipe(SpCmd *cmd, SpPipe *out_read) SP_NOEXCEPT; // parent reads  <- child stdout. *out_read  becomes valid after successful exec
SPDEF void sp_cmd_redirect_stderr_pipe(SpCmd *cmd, SpPipe *out_read) SP_NOEXCEPT; // parent reads  <- child stderr. *out_read  becomes valid after successful exec

// Run cmd asynchronously in a subprocess, returns process handle.
// Must manually sp_proc_wait() for it later.
SP_NODISCARD SPDEF SpProc sp_cmd_exec_async(SpCmd *cmd) SP_NOEXCEPT;
// Run cmd synchronously in a subprocess, returns exit code of subprocess
SPDEF int sp_cmd_exec_sync(SpCmd *cmd) SP_NOEXCEPT;

// Resets to no args, but does not free underlying memory
SPDEF void sp_cmd_reset(SpCmd *cmd) SP_NOEXCEPT;
// Resets cmd, and frees underlying memory
SPDEF void sp_cmd_free(SpCmd *cmd) SP_NOEXCEPT;

// Wait for subprocess in flight to exit, returning its exit code
SPDEF int sp_proc_wait(SpProc *proc) SP_NOEXCEPT;

#ifdef __cplusplus
}
#endif

/**
 * Implementation details follows
 */
#ifdef SP_IMPLEMENTATION

// Windows or POSIX
#if defined(_WIN32) || defined(_WIN64)
#  define SP_WINDOWS 1
#  define SP_POSIX   0
#elif defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
#  define SP_WINDOWS 0
#  define SP_POSIX   1
#else
#  error "Unsupported platform for `sp.h`"
#endif


#include <stdio.h>

#if SP_WINDOWS
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#if SP_POSIX
#  include <sys/types.h>
#endif


#ifdef __cplusplus
#  define SP_ZERO_INIT {}
#else
#  define SP_ZERO_INIT {0}
#endif

/**
 * Dynamic array implementation
 * To define a dynamic array type for type T,
 * use the following template:
 *
 *   typedef struct {
 *       T      *buffer;
 *       size_t  capacity;
 *       size_t  size;
 *   } Ts;
 */
#ifdef __cplusplus
#define SP_DARRAY_NEW_BUFFER_TYPE_(arr) decltype((arr)->buffer)
#else
#define SP_DARRAY_NEW_BUFFER_TYPE_(arr) void*
#endif
#define sp_darray_grow_to_fit_(arr, new_capacity)                       \
    do {                                                                \
        if ((new_capacity) <= (arr)->capacity) break;                   \
        size_t sp_darray_new_capacity_ = (arr)->capacity ? (arr)->capacity * 2 : 16; \
        while (sp_darray_new_capacity_ < (new_capacity)) sp_darray_new_capacity_ *= 2; \
        const size_t sp_alloc_size_ = sp_darray_new_capacity_ * sizeof(*(arr)->buffer); \
        SP_DARRAY_NEW_BUFFER_TYPE_(arr) sp_new_buffer_ = (SP_DARRAY_NEW_BUFFER_TYPE_(arr))SP_REALLOC((arr)->buffer, sp_alloc_size_); \
        SP_ASSERT(sp_new_buffer_);                                    \
        (arr)->buffer = sp_new_buffer_;                                \
        (arr)->capacity = sp_darray_new_capacity_;                     \
    } while (0)

#define sp_darray_append_(arr, new_element)             \
    do {                                                \
        sp_darray_grow_to_fit_((arr), (arr)->size+1);   \
        (arr)->buffer[(arr)->size++] = (new_element);   \
    } while (0)

#define sp_darray_free_(arr)                                            \
    do {                                                                \
        if ((arr)->buffer) SP_FREE((arr)->buffer);                     \
        (arr)->buffer = NULL; (arr)->capacity = 0; (arr)->size = 0;     \
    } while (0)

#define sp_darray_foreach_(arr, type, it)                               \
    for (type *it = (arr)->buffer; it < (arr)->buffer+(arr)->size; ++it)

#define sp_darray_copy_(src, dest)                                      \
    do {                                                                \
        sp_darray_grow_to_fit_((dest), (src)->size);                    \
        memcpy((dest)->buffer, (src)->buffer, (src)->size * sizeof(*(src)->buffer)); \
        (dest)->size = (src)->size;                                     \
    } while (0)


static inline char *
sp_strdup_(const char *str)
{
    size_t len = strlen(str);
    char *buf = (char *)SP_REALLOC(NULL, len+1);
    if (!buf) return NULL;
    memcpy(buf, str, len);
    buf[len] = '\0';
    return buf;
}

#define SP_STRING_FMT_STR(str) "%.*s"
#define SP_STRING_FMT_ARG(str) (int)(str).size, (str).buffer

static inline void
sp_string_ensure_null_(SpString *str)
{
    sp_darray_grow_to_fit_(str, str->size + 1);
    str->buffer[str->size] = '\0';
}

static inline SpString
sp_string_make_(const char *c_str)
{
    SpString str = SP_ZERO_INIT;
    size_t len = strlen(c_str);

    str.buffer = sp_strdup_(c_str);
    SP_ASSERT(str.buffer);

    str.size = len;
    str.capacity = len;

    sp_string_ensure_null_(&str);

    return str;
}

static inline void
sp_string_replace_content_(SpString   *str,
                           const char *new_content)
{
    size_t new_len = strlen(new_content);

    sp_darray_grow_to_fit_(str, new_len + 1);
    memcpy(str->buffer, new_content, new_len);
    str->size = new_len;
    str->buffer[str->size] = '\0';
}

static inline void
sp_string_append_char_(SpString *str,
                       char      c)
{
    sp_darray_grow_to_fit_(str, str->size + 2);
    str->buffer[str->size++] = c;
    str->buffer[str->size] = '\0';
}

static inline void
sp_string_append_cstr_(SpString   *str,
                       const char *cstr)
{
    size_t len = strlen(cstr);
    sp_darray_grow_to_fit_(str, str->size + len + 1);
    memcpy(str->buffer + str->size, cstr, len);
    str->size += len;
    str->buffer[str->size] = '\0';
}

static inline void
sp_string_append_string_(SpString       *str,
                         const SpString *to_append)
{
    sp_darray_grow_to_fit_(str, str->size + to_append->size + 1);
    memcpy(str->buffer + str->size, to_append->buffer, to_append->size);
    str->size += to_append->size;
    str->buffer[str->size] = '\0';
}

static inline int
sp_string_contains_any_(const SpString *s,
                        const char     *chars)
{
    const char *buf = s->buffer ? s->buffer : "";
    size_t len = s->size;

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)buf[i];
        for (const char *p = chars; *p; ++p) {
            if (c == (unsigned char)*p) return 1;
        }
    }
    return 0;
}

static inline void
sp_string_clear_(SpString *str)
{
    str->size = 0;
    if (str->buffer) str->buffer[0] = '\0';
}

static inline void
sp_string_free_(SpString *str)
{
    sp_darray_free_(str);
}

static inline SpString
sp_sprint(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int need = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (need < 0) {
        SpString result = SP_ZERO_INIT;
        return result;
    }

    char *buffer = (char *)SP_REALLOC(NULL, (size_t)need+1);

    va_start(args, fmt);
    vsnprintf(buffer, (size_t)need + 1, fmt, args);
    buffer[(size_t)need] = '\0';
    va_end(args);

    SpString result = SP_ZERO_INIT;
    sp_string_append_cstr_(&result, buffer);

    return result;
}

static inline void
sp_proc_handle_store_by_bytes_(SpProc     *proc,
                               const void *value,
                               size_t      value_size)
{
    SP_ASSERT(proc && value);
    SP_ASSERT(value_size <= SP_NATIVE_MAX);
    memcpy(proc->handle, value, value_size);
    proc->handle_size = (unsigned char)value_size;
}

static inline void
sp_proc_handle_load_by_bytes_(const SpProc *proc,
                              void         *out,
                              size_t        out_size)
{
    SP_ASSERT(proc && out);
    SP_ASSERT((size_t)proc->handle_size == out_size);
    memcpy(out, proc->handle, out_size);
}


static inline int
sp_proc_is_valid_(const SpProc* proc)
{
    return proc && proc->handle_size != 0;
}


typedef char sp_native_fits_pipe_[(SP_NATIVE_MAX >= sizeof(HANDLE)) ? 1 : -1];

static inline void
sp_pipe_handle_store_by_bytes_(SpPipe     *p,
                               const void *value,
                               size_t      value_size,
                               SpPipeMode  mode)
{
    SP_ASSERT(p && value);
    SP_ASSERT(value_size <= SP_NATIVE_MAX);

    memcpy(p->handle, value, value_size);
    p->handle_size = (unsigned char)value_size;
    p->mode = mode;
}

static inline void
sp_pipe_handle_load_by_bytes_(const SpPipe *p,
                              void         *out,
                              size_t        out_size)
{
    SP_ASSERT(p && out);
    SP_ASSERT((size_t)p->handle_size == out_size);

    memcpy(out, p->handle, out_size);
}

static inline int
sp_pipe_is_valid_(const SpPipe *p)
{
    return p && p->handle_size != 0;
}

static inline void
sp_redirect_set_file_(SpRedirect *r,
                      const char *path,
                      SpFileMode  mode)
{
    SP_ASSERT(r);
    SP_ASSERT(path);

    if (r->file_path.buffer) {
        sp_string_replace_content_(&r->file_path, path);
    } else {
        r->file_path = sp_string_make_(path);
    }

    r->file_mode = mode;
    r->kind = SP_REDIR_FILE;

}

static inline void
sp_redirect_reset_keep_alloc_(SpRedirect *r)
{
    if (r->file_path.buffer) {
        sp_string_clear_(&r->file_path);
    }
    r->out_pipe = NULL;
    r->kind = SP_REDIR_INHERIT;
}

static inline void
sp_redirect_free_alloc_(SpRedirect *r)
{
    if (r->file_path.buffer) {
        sp_string_free_(&r->file_path);
    }
    memset(r, 0, sizeof(*r));
}


static inline SpString
sp_win32_strerror(DWORD err)
{
#ifndef SP_WIN32_ERR_MSG_SIZE
#  define SP_WIN32_ERR_MSG_SIZE (4 * 1024)
#endif // SP_WIN32_ERR_MSG_SIZE

    static char win32_error_message[SP_WIN32_ERR_MSG_SIZE] = SP_ZERO_INIT;
    DWORD error_message_size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, // dwFlags
                                              NULL,                                                       // lpSource
                                              err,                                                        // dwMessageId
                                              LANG_USER_DEFAULT,                                          // dwLanguageId
                                              win32_error_message,                                        // lpBuffer
                                              SP_WIN32_ERR_MSG_SIZE,                                      // nSize
                                              NULL);                                                      // Arguments

    if (error_message_size == 0) {
        if (GetLastError() != ERROR_MR_MID_NOT_FOUND) {
            SpString result = sp_sprint("Could not get error message for 0x%lX", err);
            if (result.buffer == NULL) return sp_string_make_("");
            return result;
        } else {
            SpString result = sp_sprint("Invalid Windows Error code (0x%lX)", err);
            if (result.buffer == NULL) return sp_string_make_("");
            return result;
        }
    }

    while (error_message_size > 1 && isspace(win32_error_message[error_message_size - 1])) {
        win32_error_message[--error_message_size] = '\0';
    }

    return sp_string_make_(win32_error_message);
}

static inline void
sp_win32_log_last_error_(const char *context)
{
    DWORD err = GetLastError();
    SpString msg = sp_win32_strerror(err);
    SP_LOG_ERROR("%s: %s", context, msg.buffer);
    sp_string_free_(&msg);
}



SPDEF void
sp_cmd_add_arg(SpCmd      *cmd,
               const char *arg) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    if (cmd->args.size < cmd->internal_strings_already_initted) {
        sp_string_replace_content_(&cmd->args.buffer[cmd->args.size++], arg);
    } else {
        SpString str = sp_string_make_(arg);
        sp_darray_append_(&cmd->args, str);
        cmd->internal_strings_already_initted += 1;
    }
}

SPDEF void
sp_cmd_redirect_stdin_null(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stdin_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stdin_from_file(SpCmd *cmd, const char *path) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    sp_redirect_set_file_(&cmd->stdio.stdin_redir, path, SP_FILE_READ);
}

SPDEF void
sp_cmd_redirect_stdout_null(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stdout_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stdout_to_file(SpCmd *cmd, const char *path, SpFileMode mode) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    // stdout must be write mode
    SP_ASSERT(mode == SP_FILE_WRITE_TRUNC || mode == SP_FILE_WRITE_APPEND);

    sp_redirect_set_file_(&cmd->stdio.stdout_redir, path, mode);
}

SPDEF void
sp_cmd_redirect_stderr_null(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stderr_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stderr_to_file(SpCmd *cmd, const char *path, SpFileMode mode) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    // stderr must be write mode
    SP_ASSERT(mode == SP_FILE_WRITE_TRUNC || mode == SP_FILE_WRITE_APPEND);

    sp_redirect_set_file_(&cmd->stdio.stderr_redir, path, mode);
}

SPDEF void
sp_cmd_redirect_stderr_to_stdout(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stderr_redir.kind = SP_REDIR_TO_STDOUT;
}

SPDEF void
sp_cmd_redirect_stdin_pipe(SpCmd *cmd, SpPipe *out_write) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_write);

    memset(out_write, 0, sizeof(*out_write));
    cmd->stdio.stdin_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stdin_redir.out_pipe = out_write;

}

SPDEF void
sp_cmd_redirect_stdout_pipe(SpCmd *cmd, SpPipe *out_read) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_read);

    memset(out_read, 0, sizeof(*out_read));
    cmd->stdio.stdout_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stdout_redir.out_pipe = out_read;
}

SPDEF void
sp_cmd_redirect_stderr_pipe(SpCmd *cmd, SpPipe *out_read) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_read);

    memset(out_read, 0, sizeof(*out_read));
    cmd->stdio.stderr_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stderr_redir.out_pipe = out_read;
}

SPDEF int
sp_cmd_exec_sync(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    SpProc proc = sp_cmd_exec_async(cmd);
    int exit_code = sp_proc_wait(&proc);
    return exit_code;
}

SPDEF void
sp_cmd_reset(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->args.size = 0;

    sp_redirect_reset_keep_alloc_(&cmd->stdio.stdin_redir);
    sp_redirect_reset_keep_alloc_(&cmd->stdio.stdout_redir);
    sp_redirect_reset_keep_alloc_(&cmd->stdio.stderr_redir);
}

SPDEF void
sp_cmd_free(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    for (size_t i = 0; i < cmd->internal_strings_already_initted; ++i) {
        sp_string_free_(&cmd->args.buffer[i]);
    }
    sp_darray_free_(&cmd->args);
    cmd->internal_strings_already_initted = 0;

    sp_redirect_free_alloc_(&cmd->stdio.stdin_redir);
    sp_redirect_free_alloc_(&cmd->stdio.stdout_redir);
    sp_redirect_free_alloc_(&cmd->stdio.stderr_redir);
}


/**
 * Windows implementation follows
 */
#if SP_WINDOWS

// Compile-time check that SP_NATIVE_MAX is large enough
typedef char sp_native_fits_handle_[(SP_NATIVE_MAX >= sizeof(HANDLE)) ? 1 : -1];

static inline void
sp_proc_set_handle_(SpProc *proc,
                    HANDLE  handle)
{
  sp_proc_handle_store_by_bytes_(proc, &handle, sizeof(handle));
}

static inline HANDLE
sp_proc_get_handle_(SpProc* proc)
{
  HANDLE handle = NULL;
  sp_proc_handle_load_by_bytes_(proc, &handle, sizeof(handle));
  return handle;
}

static inline void
sp_pipe_set_handle_(SpPipe     *p,
                    HANDLE      h,
                    SpPipeMode  mode)
{
    sp_pipe_handle_store_by_bytes_(p, &h, sizeof(h), mode);
}

static inline HANDLE
sp_pipe_get_handle_(const SpPipe *p)
{
    HANDLE h = NULL;
    sp_pipe_handle_load_by_bytes_(p, &h, sizeof(h));
    return h;
}

/**
 * Windows command-line quoting for CreateProcess / CommandLineToArgvW.
 * Caller must sp_string_free_() the returned string.
 */
static inline SpString
sp_win32_quote_cmd_(const SpCmd *cmd)
{
    SpString result = SP_ZERO_INIT;

    for (size_t i = 0; i < cmd->args.size; ++i) {
        const SpString *argp = &cmd->args.buffer[i];
        const char *s = argp->buffer ? argp->buffer : "";
        size_t len = argp->size;

        if (i > 0) sp_string_append_char_(&result, ' ');

        // Need quotes if:
        //    - empty
        //    - contains whitespace (space/tab/nl/vtab) or a quote
        //    - or ends with a backslash
        int needs_quote = ((len == 0) ||
                           sp_string_contains_any_(argp, " \t\n\v\"") ||
                           (len > 0 && s[len - 1] == '\\'));

        if (!needs_quote) {
            sp_string_append_string_(&result, argp);
            continue;
        }

        sp_string_append_char_(&result, '\"');

        // Count backslashes and emit them once we know what follows.
        size_t bs = 0;

        for (size_t j = 0; j < len; ++j) {
            char c = s[j];

            if (c == '\\') {
                bs++;
                continue;
            }

            if (c == '\"') {
                // Emit 2*bs backslashes, then one backslash to escape the quote.
                for (size_t k = 0; k < bs * 2 + 1; ++k)
                    sp_string_append_char_(&result, '\\');
                sp_string_append_char_(&result, '\"');
                bs = 0;
                continue;
            }

            // Normal char: emit pending backslashes as-is.
            for (size_t k = 0; k < bs; ++k)
                sp_string_append_char_(&result, '\\');
            bs = 0;

            sp_string_append_char_(&result, c);
        }

        // Before the closing quote, emit 2*bs backslashes.
        for (size_t k = 0; k < bs * 2; ++k)
            sp_string_append_char_(&result, '\\');

        sp_string_append_char_(&result, '\"');
    }

    return result;
}

static inline HANDLE
sp_win32_open_inheritable_file_(const char *path,
                                DWORD       desired_access,
                                DWORD       creation_disposition)
{
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    // Share broadly
    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    HANDLE h = CreateFileA(path,
                           desired_access,
                           share,
                           &sa,
                           creation_disposition,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    return h;
}

static inline HANDLE
sp_win32_open_inheritable_null_(DWORD desired_access)
{
    // NUL is the Windows null device
    return sp_win32_open_inheritable_file_("NUL", desired_access, OPEN_EXISTING);
}

static inline int
sp_win32_seek_to_end_(HANDLE h)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;

    // FILE_END seeks relative to end.
    if (!SetFilePointerEx(h, zero, NULL, FILE_END)) {
        return 0;
    }
    return 1;
}

static inline int
sp_win32_apply_redir_(const SpRedirect *r,
                      int               is_stdin,
                      HANDLE           *out_handle,
                      int              *out_should_close)
{
    SP_ASSERT(r);
    SP_ASSERT(out_handle);
    SP_ASSERT(out_should_close);

    *out_should_close = 0;

    switch (r->kind) {
    case SP_REDIR_INHERIT:
        *out_handle = GetStdHandle(is_stdin ? STD_INPUT_HANDLE : STD_OUTPUT_HANDLE);
        return (*out_handle != NULL && *out_handle != INVALID_HANDLE_VALUE);

    case SP_REDIR_NULL: {
        DWORD access = is_stdin ? GENERIC_READ : GENERIC_WRITE;
        HANDLE h = sp_win32_open_inheritable_null_(access);
        if (h == INVALID_HANDLE_VALUE) return 0;
        *out_handle = h;
        *out_should_close = 1;
        return 1;
    }

    case SP_REDIR_FILE: {
        const char *path = r->file_path.buffer ? r->file_path.buffer : "";
        if (is_stdin) {
            // stdin: read from file
            HANDLE h = sp_win32_open_inheritable_file_(path, GENERIC_READ, OPEN_EXISTING);
            if (h == INVALID_HANDLE_VALUE) return 0;
            *out_handle = h;
            *out_should_close = 1;
            return 1;
        } else {
            // stdout/stderr: write to file
            if (r->file_mode == SP_FILE_WRITE_TRUNC) {
                HANDLE h = sp_win32_open_inheritable_file_(path, GENERIC_WRITE, CREATE_ALWAYS);
                if (h == INVALID_HANDLE_VALUE) return 0;
                *out_handle = h;
                *out_should_close = 1;
                return 1;
            } else if (r->file_mode == SP_FILE_WRITE_APPEND) {
                HANDLE h = sp_win32_open_inheritable_file_(path, FILE_APPEND_DATA, OPEN_ALWAYS);
                if (h == INVALID_HANDLE_VALUE) return 0;
                (void)sp_win32_seek_to_end_(h);
                *out_handle = h;
                *out_should_close = 1;
                return 1;
            } else {
                SP_ASSERT(0 && "sp: Invalid mode for output");
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    }

    case SP_REDIR_TO_STDOUT:
        // Not applied here; handled after stdout is resolved.
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;

    case SP_REDIR_PIPE:
        // TODO: Not supported
        return 0;
    }

    return 0;
}


SPDEF void
sp_pipe_close(SpPipe *p) SP_NOEXCEPT
{
    if (!sp_pipe_is_valid_(p)) return;
    HANDLE h = sp_pipe_get_handle_(p);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    memset(p, 0, sizeof(*p));
}

SP_NODISCARD SPDEF int
sp_pipe_read(SpPipe *p,
             void   *buf,
             size_t  cap,
             size_t *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);

    *out_n = 0;

    if (!sp_pipe_is_valid_(p) || p->mode != SP_PIPE_READ) {
        SP_LOG_ERROR("%s", "sp_pipe_read: invalid pipe or wrong mode");
        return 0;
    }

    HANDLE h = sp_pipe_get_handle_(p);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;

    DWORD got = 0;
    DWORD want = (cap > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (DWORD)cap;

    BOOL ok = ReadFile(h, buf, want, &got, NULL);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE) { // EOF
            *out_n = 0;
            return 1;
        }
        SpString msg = sp_win32_strerror(err);
        SP_LOG_ERROR("sp_pipe_read failed: %s", msg.buffer);
        sp_string_free_(&msg);
        return 0;
    }

    *out_n = (size_t)got;
    return 1;
}

SP_NODISCARD SPDEF int
sp_pipe_write(SpPipe *p, const void *buf, size_t len, size_t *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);
    *out_n = 0;

    if (!sp_pipe_is_valid_(p) || p->mode != SP_PIPE_WRITE) {
        SP_LOG_ERROR("%s", "sp_pipe_write: invalid pipe or wrong mode");
        return 0;
    }

    HANDLE h = sp_pipe_get_handle_(p);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;

    DWORD wrote = 0;
    DWORD want = (len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (DWORD)len;

    BOOL ok = WriteFile(h, buf, want, &wrote, NULL);
    if (!ok) {
        sp_win32_log_last_error_("sp_pipe_write failed");
        return 0;
    }

    *out_n = (size_t)wrote;
    return 1;
}

static inline int
sp_win32_make_pipe_(HANDLE *out_parent_end,
                    HANDLE *out_child_end,
                    int     parent_reads)
{
    SP_ASSERT(out_parent_end && out_child_end);

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_h = NULL, write_h = NULL;
    if (!CreatePipe(&read_h, &write_h, &sa, 0)) {
        return 0;
    }

    if (parent_reads) {
        // Parent reads read_h, must not be inheritable. Child inherits write_h.
        if (!SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(read_h);
            CloseHandle(write_h);
            return 0;
        }
        *out_parent_end = read_h;
        *out_child_end  = write_h;
        return 1;
    } else {
        // Parent writes write_h, must not be inheritable. Child inherits read_h.
        if (!SetHandleInformation(write_h, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(read_h);
            CloseHandle(write_h);
            return 0;
        }
        *out_parent_end = write_h;
        *out_child_end  = read_h;
        return 1;
    }
}

SPDEF SpProc
sp_cmd_exec_async(SpCmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    STARTUPINFO startup_info;
    ZeroMemory(&startup_info, sizeof(STARTUPINFO));
    startup_info.cb = sizeof(STARTUPINFO);
    startup_info.dwFlags |= STARTF_USESTDHANDLES;

    HANDLE h_in  = NULL;
    HANDLE h_out = NULL;
    HANDLE h_err = NULL;

    int close_in  = 0;
    int close_out = 0;
    int close_err = 0;

    BOOL success = 0;
    SpString cmd_quoted = SP_ZERO_INIT;

    // Child ends of pipes that exist in the parent prior to CreateProcess; must be closed in parent after success/fail.
    HANDLE stdin_child_end  = NULL; int close_stdin_child_end  = 0;
    HANDLE stdout_child_end = NULL; int close_stdout_child_end = 0;
    HANDLE stderr_child_end = NULL; int close_stderr_child_end = 0;

    // Out-pipe pointers (may be NULL if not requested)
    SpPipe *stdin_out  = cmd->stdio.stdin_redir.out_pipe;
    SpPipe *stdout_out = cmd->stdio.stdout_redir.out_pipe;
    SpPipe *stderr_out = cmd->stdio.stderr_redir.out_pipe;

    // Make sure requested out pipes start invalid
    if (cmd->stdio.stdin_redir.kind  == SP_REDIR_PIPE)  { SP_ASSERT(stdin_out);  memset(stdin_out,  0, sizeof(*stdin_out)); }
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stdout_out); memset(stdout_out, 0, sizeof(*stdout_out)); }
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stderr_out); memset(stderr_out, 0, sizeof(*stderr_out)); }

    // ---- stdin ----
    if (cmd->stdio.stdin_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_win32_make_pipe_(&parent_end, &child_end, /*parent_reads=*/0)) {
            sp_win32_log_last_error_("CreatePipe(stdin) failed");
            goto fail;
        }
        // child reads:
        h_in = child_end;
        stdin_child_end = child_end;
        close_stdin_child_end = 1;

        // parent writes:
        sp_pipe_set_handle_(stdin_out, parent_end, SP_PIPE_WRITE);
    } else {
        if (!sp_win32_apply_redir_(&cmd->stdio.stdin_redir, 1, &h_in, &close_in)) {
            sp_win32_log_last_error_("Failed to apply stdin redirection");
            goto fail;
        }
    }

    // ---- stdout ----
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_win32_make_pipe_(&parent_end, &child_end, /*parent_reads=*/1)) {
            sp_win32_log_last_error_("CreatePipe(stdout) failed");
            goto fail;
        }
        // child writes:
        h_out = child_end;
        stdout_child_end = child_end;
        close_stdout_child_end = 1;

        // parent reads:
        sp_pipe_set_handle_(stdout_out, parent_end, SP_PIPE_READ);
    } else {
        if (!sp_win32_apply_redir_(&cmd->stdio.stdout_redir, 0, &h_out, &close_out)) {
            sp_win32_log_last_error_("Failed to apply stdout redirection");
            goto fail;
        }
    }

    // ---- stderr ----
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_TO_STDOUT) {
        h_err = h_out;   // merge into stdout (even if stdout is a pipe)
        close_err = 0;   // stdout "owns" the handle if it needs closing
    } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_win32_make_pipe_(&parent_end, &child_end, /*parent_reads=*/1)) {
            sp_win32_log_last_error_("CreatePipe(stderr) failed");
            goto fail;
        }
        h_err = child_end;
        stderr_child_end = child_end;
        close_stderr_child_end = 1;

        sp_pipe_set_handle_(stderr_out, parent_end, SP_PIPE_READ);
    } else {
        if (cmd->stdio.stderr_redir.kind == SP_REDIR_INHERIT) {
            h_err = GetStdHandle(STD_ERROR_HANDLE);
            if (h_err == NULL || h_err == INVALID_HANDLE_VALUE) {
                sp_win32_log_last_error_("GetStdHandle(STD_ERROR_HANDLE) failed");
                goto fail;
            }
        } else {
            if (!sp_win32_apply_redir_(&cmd->stdio.stderr_redir, 0, &h_err, &close_err)) {
                sp_win32_log_last_error_("Failed to apply stderr redirection");
                goto fail;
            }
        }
    }

    startup_info.hStdInput  = h_in;
    startup_info.hStdOutput = h_out;
    startup_info.hStdError  = h_err;

    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_info, sizeof(PROCESS_INFORMATION));

    cmd_quoted = sp_win32_quote_cmd_(cmd);
    SP_ASSERT(cmd_quoted.size < 32768 && "sp: Windows requires command line (incl NUL) < 32767 chars");

    SP_LOG_INFO(SP_STRING_FMT_STR(cmd_quoted), SP_STRING_FMT_ARG(cmd_quoted));

    success = CreateProcessA(NULL,
                             cmd_quoted.buffer,
                             NULL,
                             NULL,
                             TRUE,
                             0,
                             NULL,
                             NULL,
                             &startup_info,
                             &proc_info);

    sp_string_free_(&cmd_quoted);

    if (!success) {
        sp_win32_log_last_error_("CreateProcessA failed");
        goto fail;
    }

    // Close child ends of pipes in parent (child inherited them)
    if (close_stdin_child_end)  CloseHandle(stdin_child_end);
    if (close_stdout_child_end) CloseHandle(stdout_child_end);
    if (close_stderr_child_end) CloseHandle(stderr_child_end);

    // Close any file/NUL handles opened in parent
    if (close_in)  CloseHandle(h_in);
    if (close_out) CloseHandle(h_out);
    if (close_err) CloseHandle(h_err);

    CloseHandle(proc_info.hThread);
    {
        SpProc proc = SP_ZERO_INIT;
        sp_proc_set_handle_(&proc, proc_info.hProcess);
        return proc;
    }

fail:
    // Close any child ends created
    if (close_stdin_child_end && stdin_child_end)  CloseHandle(stdin_child_end);
    if (close_stdout_child_end && stdout_child_end) CloseHandle(stdout_child_end);
    if (close_stderr_child_end && stderr_child_end) CloseHandle(stderr_child_end);

    // Close any file/NUL handles opened
    if (close_in && h_in && h_in != INVALID_HANDLE_VALUE) CloseHandle(h_in);
    if (close_out && h_out && h_out != INVALID_HANDLE_VALUE) CloseHandle(h_out);
    if (close_err && h_err && h_err != INVALID_HANDLE_VALUE) CloseHandle(h_err);

    // Close any parent ends created (invalidate out pipes)
    if (cmd->stdio.stdin_redir.kind  == SP_REDIR_PIPE && stdin_out)  sp_pipe_close(stdin_out);
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE && stdout_out) sp_pipe_close(stdout_out);
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE && stderr_out) sp_pipe_close(stderr_out);

    {
        SpProc proc = SP_ZERO_INIT;
        return proc;
    }
}

SPDEF int
sp_proc_wait(SpProc *proc) SP_NOEXCEPT
{
    SP_ASSERT(proc);

    if (!sp_proc_is_valid_(proc)) {
        SP_LOG_ERROR("%s", "sp_proc_wait called on invalid process handle");
        return -1;
    }

    HANDLE h = sp_proc_get_handle_(proc);
    if (h == NULL) {
        SP_LOG_ERROR("sp_proc_wait got NULL HANDLE");
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    DWORD w = WaitForSingleObject(h, INFINITE);
    if (w == WAIT_FAILED) {
        sp_win32_log_last_error_("WaitForSingleObject failed");
        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }
    if (w != WAIT_OBJECT_0) {
        // Unexpected, but not a GetLastError()-style failure
        SP_LOG_ERROR("WaitForSingleObject returned unexpected status: 0x%lX", (unsigned long)w);
        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h, &exit_code)) {
        sp_win32_log_last_error_("GetExitCodeProcess failed");
        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    CloseHandle(h);
    memset(proc, 0, sizeof(*proc));

    return (int)exit_code;
}

#endif // SP_WINDOWS



/**
 * POSIX implementation follows
 */
#if SP_POSIX

// Compile-time check that SP_NATIVE_MAX is large enough
typedef char sp_native_fits_handle_[(SP_NATIVE_MAX >= sizeof(pid_t)) ? 1 : -1];

static inline void
sp_proc_set_pid_(SpProc* proc, pid_t pid)
{
  sp_proc_handle_store_by_bytes_(proc, &pid, sizeof(pid));
}

static inline pid_t
sp_proc_get_pid_(const SpProc* proc)
{
  pid_t pid = (pid_t)0;
  sp_proc_handle_load_by_bytes_(proc, &pid, sizeof(pid));
  return pid;
}

#endif // SP_POSIX

#endif // SP_IMPLEMENTATION

#endif // SP_H_INCLUDED_

/**
 * BSD-3-CLAUSE LICENSE
 *
 * Copyright 2025 rsore
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
