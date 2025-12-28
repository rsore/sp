/**
 * sp.h — Cross-platform API for subprocess management,
 *        targeting Windows and POSIX.
 *
 * Version: 2.1.0
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
 *  - SP_EMBED_LICENSE ........................... Embeds BSD-3-Clause license text
 *                                                 in the program binary.
 *  - SPDEF ...................................... Prefixed to all functions.
 *                                                 Example: `#define SPDEF static inline`
 *                                                 Default: Nothing
 *  - SP_ASSERT(cond) ............................ Assertion function for `sp.h` to use.
 *                                                 Default: libc assert.
 *  - SP_LOG_INFO(msg) ........................... Used to print commands as they are run.
 *                                                 msg is NUL-terminated cstr.
 *                                                 msg is only valid during the callback/macro expansion.
 *                                                 copy if you need to keep it.
 *                                                 Default: Nothing.
 *  - SP_LOG_ERROR(msg) .......................... Used to print error messages as they occur.
 *                                                 msg is NUL-terminated cstr.
 *                                                 msg is only valid during the callback/macro expansion.
 *                                                 copy if you need to keep it.
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
} Sp_String;

// Dynamic array
typedef struct {
    Sp_String *buffer;
    size_t    size;
    size_t    capacity;
} Sp_Strings;

typedef enum {
    SP_REDIR_INHERIT = 0,   // use parent's std handle
    SP_REDIR_NULL,          // /dev/null or NUL, no output
    SP_REDIR_FILE,          // path-based file
    SP_REDIR_PIPE,          // create pipe (parent keeps one end)
    SP_REDIR_TO_STDOUT,     // merge stderr into stdout
} Sp_RedirKind;

typedef enum {
    SP_FILE_READ = 0,       // for stdin
    SP_FILE_WRITE_TRUNC,    // for stdout/stderr
    SP_FILE_WRITE_APPEND    // for stdout/stderr
} Sp_FileMode;

typedef enum {
    SP_PIPE_READ  = 1, // parent reads (child writes)
    SP_PIPE_WRITE = 2  // parent writes (child reads)
} Sp_PipeMode;

typedef struct {
    unsigned char handle[SP_NATIVE_MAX];
    unsigned char handle_size;
    Sp_PipeMode    mode;
} Sp_Pipe;

typedef struct {
    Sp_RedirKind kind;

    // file config
    Sp_String   file_path;
    Sp_FileMode file_mode;

    // pipe config
    Sp_Pipe    *out_pipe;
} Sp_Redirect;

typedef struct {
    Sp_Redirect stdin_redir;
    Sp_Redirect stdout_redir;
    Sp_Redirect stderr_redir;
} Sp_Stdio;

// Command builder
typedef struct {
    Sp_Strings args;
    size_t internal_strings_already_initted; // We reuse allocated strings after cmd_reset

    Sp_Stdio stdio;
} Sp_Cmd;

// Dynamic array
typedef struct {
    Sp_Cmd  *buffer;
    size_t  size;
    size_t  capacity;
} Sp_Cmds;

// Process in flight
typedef struct {
  // Handle is different per platform (HANDLE vs pid_t)
  unsigned char handle[SP_NATIVE_MAX];
  unsigned char handle_size;
} Sp_Proc;

// Dynamic array
typedef struct {
    Sp_Proc *buffer;
    size_t  size;
    size_t  capacity;
} Sp_Procs;

typedef struct {
    Sp_Cmds cmds;
} Sp_CmdBatch;

// Add a single arg to cmd.
SPDEF void sp_cmd_add_arg(Sp_Cmd *cmd, const char *arg) SP_NOEXCEPT;

// Add multiple args to cmd at once, passed as separate c-strings.
// It is intended the user calls the wrapper macro `sp_cmd_add_args`,
// not the `sp_cmd_add_args_impl_` directly.
//  Example:
//    sp_cmd_add_args(cmd_ptr, "foo", "bar", "baz");
#define    sp_cmd_add_args(cmd_ptr, ...) sp_cmd_add_args_impl_((cmd_ptr), __VA_ARGS__, (const char *)NULL)
SPDEF void sp_cmd_add_args_impl_(Sp_Cmd *cmd, const char *new_arg1, ...) SP_NOEXCEPT;

// Add multiple args at once, from an existing array of c-strings.
//  Example:
//    const char *some_args[] = {"foo", "bar", "baz"};
//    sp_cmd_add_args(cmd_ptr, some_args, 3);
SPDEF void sp_cmd_add_args_n(Sp_Cmd *cmd, const char **args, size_t args_len) SP_NOEXCEPT;

// *out_n == 0 means EOF (child closed its end).
SP_NODISCARD SPDEF int sp_pipe_read(Sp_Pipe *p, void *buf, size_t cap, size_t *out_n) SP_NOEXCEPT;
// Partial writes are allowed; check *out_n.
SP_NODISCARD SPDEF int sp_pipe_write(Sp_Pipe *p, const void *buf, size_t len, size_t *out_n) SP_NOEXCEPT;
// Always succeeds; safe to call multiple times.
SPDEF void sp_pipe_close(Sp_Pipe *p) SP_NOEXCEPT;

// Redirection of stdout, stderr and stdin. Call these to configure cmd *before*
// calling any exec function. Default behavior is subprocess inherits stdio
// of calling process.
SPDEF void sp_cmd_redirect_stdin_null(Sp_Cmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdin_from_file(Sp_Cmd *cmd, const char *path) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdout_null(Sp_Cmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stdout_to_file(Sp_Cmd *cmd, const char *path, Sp_FileMode mode) SP_NOEXCEPT; // mode: TRUNC/APPEND
SPDEF void sp_cmd_redirect_stderr_null(Sp_Cmd *cmd) SP_NOEXCEPT;
SPDEF void sp_cmd_redirect_stderr_to_file(Sp_Cmd *cmd, const char *path, Sp_FileMode mode) SP_NOEXCEPT; // mode: TRUNC/APPEND
SPDEF void sp_cmd_redirect_stderr_to_stdout(Sp_Cmd *cmd) SP_NOEXCEPT; // merge 2>&1
SPDEF void sp_cmd_redirect_stdin_pipe(Sp_Cmd *cmd, Sp_Pipe *out_write) SP_NOEXCEPT; // parent writes -> child stdin.  *out_write becomes valid after successful exec
SPDEF void sp_cmd_redirect_stdout_pipe(Sp_Cmd *cmd, Sp_Pipe *out_read) SP_NOEXCEPT; // parent reads  <- child stdout. *out_read  becomes valid after successful exec
SPDEF void sp_cmd_redirect_stderr_pipe(Sp_Cmd *cmd, Sp_Pipe *out_read) SP_NOEXCEPT; // parent reads  <- child stderr. *out_read  becomes valid after successful exec

// Resets to no args, but does not free underlying memory
SPDEF void sp_cmd_reset(Sp_Cmd *cmd) SP_NOEXCEPT;
// Resets cmd, and frees underlying memory
SPDEF void sp_cmd_free(Sp_Cmd *cmd) SP_NOEXCEPT;

// Run cmd asynchronously in a subprocess, returns process handle.
// Must manually sp_proc_wait() for it later.
SP_NODISCARD SPDEF Sp_Proc sp_cmd_exec_async(Sp_Cmd *cmd) SP_NOEXCEPT;
// Run cmd synchronously in a subprocess, returns exit code of subprocess
SPDEF int sp_cmd_exec_sync(Sp_Cmd *cmd) SP_NOEXCEPT;

// Detach process so it can no longer be waited on.
// On Windows: closes underlying handle.
// On POSIX: forgets pid (Note: The child may become a zombie until parent exits).
SPDEF void sp_proc_detach(Sp_Proc *proc) SP_NOEXCEPT;

// Wait for subprocess in flight to exit, returning its exit code
SPDEF int sp_proc_wait(Sp_Proc *proc) SP_NOEXCEPT;

// Add finished cmd object to batch. cmd is copied into batch, and can safely be reset/freed.
SPDEF void sp_batch_add_cmd(Sp_CmdBatch *batch, const Sp_Cmd *cmd) SP_NOEXCEPT;
// Run all processes in batch concurrently, with no more than max_parallel processes
// running at any one time. Aborts early if any process fails. Returns exit code
// of first failed process, or 0 if all succeeded.
SPDEF int sp_batch_exec_sync(Sp_CmdBatch *batch, size_t max_parallel) SP_NOEXCEPT;
// Resets batch object for reuse without deallocating internal memory
SPDEF void sp_batch_reset(Sp_CmdBatch *batch) SP_NOEXCEPT;
// Resets and frees batch object and its owned memory.
SPDEF void sp_batch_free(Sp_CmdBatch *batch) SP_NOEXCEPT;

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
#include <stdarg.h>

#if SP_WINDOWS
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#if SP_POSIX
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#  include <sys/wait.h>
#  include <sys/types.h>
#  include <time.h>
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
#define SP_DARRAY_NEW_BUFFER_TYPE(arr) decltype((arr)->buffer)
#else
#define SP_DARRAY_NEW_BUFFER_TYPE(arr) void*
#endif
#define sp_darray_grow_to_fit(arr, new_capacity)                                                                                 \
    do {                                                                                                                         \
        if ((new_capacity) <= (arr)->capacity) break;                                                                            \
        size_t sp_darray_new_capacity = (arr)->capacity ? (arr)->capacity * 2 : 16;                                              \
        while (sp_darray_new_capacity < (new_capacity)) sp_darray_new_capacity *= 2;                                             \
        const size_t sp_alloc_size = sp_darray_new_capacity * sizeof(*(arr)->buffer);                                            \
        SP_DARRAY_NEW_BUFFER_TYPE(arr) sp_new_buffer = (SP_DARRAY_NEW_BUFFER_TYPE(arr))SP_REALLOC((arr)->buffer, sp_alloc_size); \
        SP_ASSERT(sp_new_buffer);                                                                                                \
        (arr)->buffer = sp_new_buffer;                                                                                           \
        (arr)->capacity = sp_darray_new_capacity;                                                                                \
    } while (0)

#define sp_darray_append(arr, new_element)                                                                                       \
    do {                                                                                                                         \
        sp_darray_grow_to_fit((arr), (arr)->size+1);                                                                             \
        (arr)->buffer[(arr)->size++] = (new_element);                                                                            \
    } while (0)

#define cap_darray_copy(src, dest)                                                                                               \
    do {                                                                                                                         \
        cap_darray_grow_to_fit((dest), (src)->size);                                                                             \
        memcpy((dest)->buffer, (src)->buffer, (src)->size * sizeof(*(src)->buffer));                                             \
        (dest)->size = (src)->size;                                                                                              \
    } while (0)

#define sp_darray_free(arr)                                                                                                      \
    do {                                                                                                                         \
        if ((arr)->buffer) SP_FREE((arr)->buffer);                                                                               \
        (arr)->buffer = NULL; (arr)->capacity = 0; (arr)->size = 0;                                                              \
    } while (0)


static inline char *
sp_internal_strdup(const char *str)
{
    size_t len = strlen(str);
    char *buf = (char *)SP_REALLOC(NULL, len+1);
    if (!buf) return NULL;
    memcpy(buf, str, len);
    buf[len] = '\0';
    return buf;
}

#define SP_INTERNAL_STRING_FMT_STR(str) "%.*s"
#define SP_INTERNAL_STRING_FMT_ARG(str) (int)(str).size, (str).buffer

static inline void
sp_internal_string_ensure_null(Sp_String *str)
{
    sp_darray_grow_to_fit(str, str->size + 1);
    str->buffer[str->size] = '\0';
}

static inline Sp_String
sp_internal_string_make(const char *c_str)
{
    Sp_String str = SP_ZERO_INIT;
    size_t len = strlen(c_str);

    str.buffer = sp_internal_strdup(c_str);
    SP_ASSERT(str.buffer);

    str.size = len;
    str.capacity = len;

    sp_internal_string_ensure_null(&str);

    return str;
}

static inline void
sp_internal_string_replace_content(Sp_String   *str,
                                   const char *new_content)
{
    size_t new_len = strlen(new_content);

    sp_darray_grow_to_fit(str, new_len + 1);
    memcpy(str->buffer, new_content, new_len);
    str->size = new_len;
    str->buffer[str->size] = '\0';
}

static inline void
sp_internal_string_append_char(Sp_String *str,
                               char      c)
{
    sp_darray_grow_to_fit(str, str->size + 2);
    str->buffer[str->size++] = c;
    str->buffer[str->size] = '\0';
}

static inline void
sp_internal_string_append_cstr(Sp_String   *str,
                               const char *cstr)
{
    size_t len = strlen(cstr);
    sp_darray_grow_to_fit(str, str->size + len + 1);
    memcpy(str->buffer + str->size, cstr, len);
    str->size += len;
    str->buffer[str->size] = '\0';
}

static inline void
sp_internal_string_append_string(Sp_String       *str,
                                 const Sp_String *to_append)
{
    sp_darray_grow_to_fit(str, str->size + to_append->size + 1);
    memcpy(str->buffer + str->size, to_append->buffer, to_append->size);
    str->size += to_append->size;
    str->buffer[str->size] = '\0';
}

static inline int
sp_internal_string_contains_any(const Sp_String *s,
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
sp_internal_string_clear(Sp_String *str)
{
    str->size = 0;
    if (str->buffer) str->buffer[0] = '\0';
}

static inline void
sp_internal_string_free(Sp_String *str)
{
    sp_darray_free(str);
}

static inline Sp_String
sp_internal_vsprint(const char *fmt, va_list ap)
{
    Sp_String result = SP_ZERO_INIT;

    va_list ap1;
    va_copy(ap1, ap);
    int need = vsnprintf(NULL, 0, fmt, ap1);
    va_end(ap1);

    if (need < 0) {
        return result;
    }

    char *buffer = (char *)SP_REALLOC(NULL, (size_t)need + 1);
    if (!buffer) {
        return result;
    }

    va_list ap2;
    va_copy(ap2, ap);
    int written = vsnprintf(buffer, (size_t)need + 1, fmt, ap2);
    va_end(ap2);

    if (written < 0) {
        SP_FREE(buffer);
        return result;
    }

    if (written > need) {
        SP_FREE(buffer);
        return result;
    }

    buffer[(size_t)written] = '\0';

    result.buffer   = buffer;
    result.size     = (size_t)written;
    result.capacity = (size_t)need + 1;

    return result;
}

static inline Sp_String
sp_internal_sprint(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    Sp_String s = sp_internal_vsprint(fmt, ap);
    va_end(ap);
    return s;
}


static inline void
sp_internal_log_info(const char *fmt, ...)
{
    (void)fmt;
#ifdef SP_LOG_INFO
    va_list ap;
    va_start(ap, fmt);
    Sp_String s = sp_internal_vsprint(fmt, ap);
    va_end(ap);
    SP_LOG_INFO(s.buffer);
    sp_internal_string_free(&s);
#endif
}

static inline void
sp_internal_log_error(const char *fmt, ...)
{
    (void)fmt;
#ifdef SP_LOG_ERROR
    va_list ap;
    va_start(ap, fmt);
    Sp_String s = sp_internal_vsprint(fmt, ap);
    va_end(ap);
    SP_LOG_ERROR(s.buffer);
    sp_internal_string_free(&s);
#endif
}


static inline void
sp_internal_proc_handle_store_by_bytes(Sp_Proc     *proc,
                                       const void *value,
                                       size_t      value_size)
{
    SP_ASSERT(proc && value);
    SP_ASSERT(value_size <= SP_NATIVE_MAX);
    memcpy(proc->handle, value, value_size);
    proc->handle_size = (unsigned char)value_size;
}

static inline void
sp_internal_proc_handle_load_by_bytes(const Sp_Proc *proc,
                                      void         *out,
                                      size_t        out_size)
{
    SP_ASSERT(proc && out);
    SP_ASSERT((size_t)proc->handle_size == out_size);
    memcpy(out, proc->handle, out_size);
}

static inline int
sp_internal_proc_is_valid(const Sp_Proc* proc)
{
    return proc && proc->handle_size != 0;
}

static inline void
sp_internal_pipe_handle_store_by_bytes(Sp_Pipe     *p,
                                       const void *value,
                                       size_t      value_size,
                                       Sp_PipeMode  mode)
{
    SP_ASSERT(p && value);
    SP_ASSERT(value_size <= SP_NATIVE_MAX);

    memcpy(p->handle, value, value_size);
    p->handle_size = (unsigned char)value_size;
    p->mode = mode;
}

static inline void
sp_internal_pipe_handle_load_by_bytes(const Sp_Pipe *p,
                                      void         *out,
                                      size_t        out_size)
{
    SP_ASSERT(p && out);
    SP_ASSERT((size_t)p->handle_size == out_size);

    memcpy(out, p->handle, out_size);
}

static inline int
sp_internal_pipe_is_valid(const Sp_Pipe *p)
{
    return p && p->handle_size != 0;
}

static inline void
sp_internal_redirect_set_file(Sp_Redirect *r,
                              const char *path,
                              Sp_FileMode  mode)
{
    SP_ASSERT(r);
    SP_ASSERT(path);

    if (r->file_path.buffer) {
        sp_internal_string_replace_content(&r->file_path, path);
    } else {
        r->file_path = sp_internal_string_make(path);
    }

    r->file_mode = mode;
    r->kind = SP_REDIR_FILE;

}

static inline void
sp_internal_redirect_reset_keep_alloc(Sp_Redirect *r)
{
    if (r->file_path.buffer) {
        sp_internal_string_clear(&r->file_path);
    }
    r->out_pipe = NULL;
    r->kind = SP_REDIR_INHERIT;
}

static inline void
sp_internal_redirect_free_alloc(Sp_Redirect *r)
{
    if (r->file_path.buffer) {
        sp_internal_string_free(&r->file_path);
    }
    memset(r, 0, sizeof(*r));
}

static inline void
sp_internal_string_clone(Sp_String        *dst,
                         const Sp_String  *src)
{
    SP_ASSERT(dst);
    SP_ASSERT(src);

    memset(dst, 0, sizeof(Sp_String));

    if (!src->buffer || src->size == 0) {
        return;
    }

    dst->buffer = (char *)SP_REALLOC(NULL, src->size + 1);
    SP_ASSERT(dst->buffer);

    memcpy(dst->buffer, src->buffer, src->size);
    dst->buffer[src->size] = '\0';

    dst->size     = src->size;
    dst->capacity = src->size + 1;
}

static inline void
sp_internal_redirect_clone(Sp_Redirect        *dst,
                           const Sp_Redirect  *src)
{
    SP_ASSERT(dst);
    SP_ASSERT(src);

    memset(dst, 0, sizeof(Sp_Redirect));

    dst->kind = src->kind;

    SP_ASSERT(dst->kind != SP_REDIR_PIPE);

    dst->file_mode = src->file_mode;
    sp_internal_string_clone(&dst->file_path, &src->file_path);

    dst->out_pipe = NULL;
}

static inline void
sp_internal_cmd_clone(Sp_Cmd        *dst,
                      const Sp_Cmd  *src)
{
    SP_ASSERT(dst);
    SP_ASSERT(src);

    memset(dst, 0, sizeof(Sp_Cmd));

    SP_ASSERT(src->stdio.stdin_redir.kind  != SP_REDIR_PIPE);
    SP_ASSERT(src->stdio.stdout_redir.kind != SP_REDIR_PIPE);
    SP_ASSERT(src->stdio.stderr_redir.kind != SP_REDIR_PIPE);

    for (size_t i = 0; i < src->args.size; i++) {
        Sp_String s = SP_ZERO_INIT;
        sp_internal_string_clone(&s, &src->args.buffer[i]);
        sp_darray_append(&dst->args, s);
    }

    dst->internal_strings_already_initted = dst->args.size;

    sp_internal_redirect_clone(&dst->stdio.stdin_redir,  &src->stdio.stdin_redir);
    sp_internal_redirect_clone(&dst->stdio.stdout_redir, &src->stdio.stdout_redir);
    sp_internal_redirect_clone(&dst->stdio.stderr_redir, &src->stdio.stderr_redir);
}

SPDEF void
sp_cmd_add_arg(Sp_Cmd      *cmd,
               const char *arg) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    if (cmd->args.size < cmd->internal_strings_already_initted) {
        sp_internal_string_replace_content(&cmd->args.buffer[cmd->args.size++], arg);
    } else {
        Sp_String str = sp_internal_string_make(arg);
        sp_darray_append(&cmd->args, str);
        cmd->internal_strings_already_initted += 1;
    }
}

SPDEF void
sp_cmd_add_args_impl_(Sp_Cmd         *cmd,
                         const char *new_arg1,
                                     ...) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    va_list args;
    va_start(args, new_arg1);

    const char *data = new_arg1;
    while (data) {
        sp_cmd_add_arg(cmd, data);
        data = va_arg(args, const char *);
    }

    va_end(args);
}

SPDEF void
sp_cmd_add_args_n(Sp_Cmd       *cmd,
                  const char **args,
                  size_t       args_len) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    for (size_t i = 0; i < args_len; ++i) {
        sp_cmd_add_arg(cmd, args[i]);
    }
}

SPDEF void
sp_cmd_redirect_stdin_null(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stdin_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stdin_from_file(Sp_Cmd *cmd, const char *path) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    sp_internal_redirect_set_file(&cmd->stdio.stdin_redir, path, SP_FILE_READ);
}

SPDEF void
sp_cmd_redirect_stdout_null(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stdout_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stdout_to_file(Sp_Cmd *cmd, const char *path, Sp_FileMode mode) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    // stdout must be write mode
    SP_ASSERT(mode == SP_FILE_WRITE_TRUNC || mode == SP_FILE_WRITE_APPEND);

    sp_internal_redirect_set_file(&cmd->stdio.stdout_redir, path, mode);
}

SPDEF void
sp_cmd_redirect_stderr_null(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stderr_redir.kind = SP_REDIR_NULL;
}

SPDEF void
sp_cmd_redirect_stderr_to_file(Sp_Cmd *cmd, const char *path, Sp_FileMode mode) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    // stderr must be write mode
    SP_ASSERT(mode == SP_FILE_WRITE_TRUNC || mode == SP_FILE_WRITE_APPEND);

    sp_internal_redirect_set_file(&cmd->stdio.stderr_redir, path, mode);
}

SPDEF void
sp_cmd_redirect_stderr_to_stdout(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->stdio.stderr_redir.kind = SP_REDIR_TO_STDOUT;
}

SPDEF void
sp_cmd_redirect_stdin_pipe(Sp_Cmd *cmd, Sp_Pipe *out_write) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_write);

    memset(out_write, 0, sizeof(*out_write));
    cmd->stdio.stdin_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stdin_redir.out_pipe = out_write;

}

SPDEF void
sp_cmd_redirect_stdout_pipe(Sp_Cmd *cmd, Sp_Pipe *out_read) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_read);

    memset(out_read, 0, sizeof(*out_read));
    cmd->stdio.stdout_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stdout_redir.out_pipe = out_read;
}

SPDEF void
sp_cmd_redirect_stderr_pipe(Sp_Cmd *cmd, Sp_Pipe *out_read) SP_NOEXCEPT
{
    SP_ASSERT(cmd);
    SP_ASSERT(out_read);

    memset(out_read, 0, sizeof(*out_read));
    cmd->stdio.stderr_redir.kind = SP_REDIR_PIPE;
    cmd->stdio.stderr_redir.out_pipe = out_read;
}

SPDEF int
sp_cmd_exec_sync(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    Sp_Proc proc = sp_cmd_exec_async(cmd);
    int exit_code = sp_proc_wait(&proc);
    return exit_code;
}

SPDEF void
sp_cmd_reset(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    cmd->args.size = 0;

    sp_internal_redirect_reset_keep_alloc(&cmd->stdio.stdin_redir);
    sp_internal_redirect_reset_keep_alloc(&cmd->stdio.stdout_redir);
    sp_internal_redirect_reset_keep_alloc(&cmd->stdio.stderr_redir);
}

SPDEF void
sp_cmd_free(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    for (size_t i = 0; i < cmd->internal_strings_already_initted; ++i) {
        sp_internal_string_free(&cmd->args.buffer[i]);
    }
    sp_darray_free(&cmd->args);
    cmd->internal_strings_already_initted = 0;

    sp_internal_redirect_free_alloc(&cmd->stdio.stdin_redir);
    sp_internal_redirect_free_alloc(&cmd->stdio.stdout_redir);
    sp_internal_redirect_free_alloc(&cmd->stdio.stderr_redir);
}

SPDEF
void sp_batch_add_cmd(Sp_CmdBatch  *batch,
                      const Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(batch);
    SP_ASSERT(cmd);

    Sp_Cmd copy = SP_ZERO_INIT;
    sp_internal_cmd_clone(&copy, cmd);

    sp_darray_append(&batch->cmds, copy);
}

SPDEF void
sp_batch_reset(Sp_CmdBatch *batch) SP_NOEXCEPT
{
    if (!batch) return;

    for (size_t i = 0; i < batch->cmds.size; i++) {
        sp_cmd_free(&batch->cmds.buffer[i]);
    }

    batch->cmds.size = 0;
}

SPDEF void
sp_batch_free(Sp_CmdBatch *batch) SP_NOEXCEPT
{
    if (!batch) return;

    sp_batch_reset(batch);
    sp_darray_free(&batch->cmds);
    memset(batch, 0, sizeof(Sp_CmdBatch));
}

/**
 * Windows implementation follows
 */
#if SP_WINDOWS

// Compile-time checks
typedef char sp_native_fits_pipe[(SP_NATIVE_MAX >= sizeof(HANDLE)) ? 1 : -1];
typedef char sp_native_fits_handle[(SP_NATIVE_MAX >= sizeof(HANDLE)) ? 1 : -1];

static inline void
sp_internal_win32_proc_set_handle(Sp_Proc *proc,
                                  HANDLE  handle)
{
  sp_internal_proc_handle_store_by_bytes(proc, &handle, sizeof(handle));
}

static inline HANDLE
sp_internal_win32_proc_get_handle(Sp_Proc* proc)
{
  HANDLE handle = NULL;
  sp_internal_proc_handle_load_by_bytes(proc, &handle, sizeof(handle));
  return handle;
}

static inline void
sp_internal_win32_pipe_set_handle(Sp_Pipe     *p,
                                  HANDLE      h,
                                  Sp_PipeMode  mode)
{
    sp_internal_pipe_handle_store_by_bytes(p, &h, sizeof(h), mode);
}

static inline HANDLE
sp_internal_win32_pipe_get_handle(const Sp_Pipe *p)
{
    HANDLE h = NULL;
    sp_internal_pipe_handle_load_by_bytes(p, &h, sizeof(h));
    return h;
}


static inline Sp_String
sp_internal_win32_strerror(DWORD err)
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
            Sp_String result = sp_internal_sprint("Could not get error message for 0x%lX", err);
            if (result.buffer == NULL) return sp_internal_string_make("");
            return result;
        } else {
            Sp_String result = sp_internal_sprint("Invalid Windows Error code (0x%lX)", err);
            if (result.buffer == NULL) return sp_internal_string_make("");
            return result;
        }
    }

    while (error_message_size > 1 && isspace(win32_error_message[error_message_size - 1])) {
        win32_error_message[--error_message_size] = '\0';
    }

    return sp_internal_string_make(win32_error_message);
}

static inline void
sp_internal_win32_log_last_error(const char *context)
{
    DWORD err = GetLastError();
    Sp_String msg = sp_internal_win32_strerror(err);
    sp_internal_log_error("%s: %s", context, msg.buffer);
    sp_internal_string_free(&msg);
}

/**
 * Windows command-line quoting for CreateProcess / CommandLineToArgvW.
 * Caller must sp_internal_string_free() the returned string.
 */
static inline Sp_String
sp_internal_win32_quote_cmd(const Sp_Cmd *cmd)
{
    Sp_String result = SP_ZERO_INIT;

    for (size_t i = 0; i < cmd->args.size; ++i) {
        const Sp_String *argp = &cmd->args.buffer[i];
        const char *s = argp->buffer ? argp->buffer : "";
        size_t len = argp->size;

        if (i > 0) sp_internal_string_append_char(&result, ' ');

        // Need quotes if:
        //    - empty
        //    - contains whitespace (space/tab/nl/vtab) or a quote
        //    - or ends with a backslash
        int needs_quote = ((len == 0) ||
                           sp_internal_string_contains_any(argp, " \t\n\v\"") ||
                           (len > 0 && s[len - 1] == '\\'));

        if (!needs_quote) {
            sp_internal_string_append_string(&result, argp);
            continue;
        }

        sp_internal_string_append_char(&result, '\"');

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
                    sp_internal_string_append_char(&result, '\\');
                sp_internal_string_append_char(&result, '\"');
                bs = 0;
                continue;
            }

            // Normal char: emit pending backslashes as-is.
            for (size_t k = 0; k < bs; ++k)
                sp_internal_string_append_char(&result, '\\');
            bs = 0;

            sp_internal_string_append_char(&result, c);
        }

        // Before the closing quote, emit 2*bs backslashes.
        for (size_t k = 0; k < bs * 2; ++k)
            sp_internal_string_append_char(&result, '\\');

        sp_internal_string_append_char(&result, '\"');
    }

    return result;
}

static inline HANDLE
sp_internal_win32_open_inheritable_file(const char *path,
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
sp_internal_win32_open_inheritable_null(DWORD desired_access)
{
    // NUL is the Windows null device
    return sp_internal_win32_open_inheritable_file("NUL", desired_access, OPEN_EXISTING);
}

static inline int
sp_internal_win32_seek_to_end(HANDLE h)
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
sp_internal_win32_apply_redir(const Sp_Redirect *r,
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
        HANDLE h = sp_internal_win32_open_inheritable_null(access);
        if (h == INVALID_HANDLE_VALUE) return 0;
        *out_handle = h;
        *out_should_close = 1;
        return 1;
    }

    case SP_REDIR_FILE: {
        const char *path = r->file_path.buffer ? r->file_path.buffer : "";
        if (is_stdin) {
            // stdin: read from file
            HANDLE h = sp_internal_win32_open_inheritable_file(path, GENERIC_READ, OPEN_EXISTING);
            if (h == INVALID_HANDLE_VALUE) return 0;
            *out_handle = h;
            *out_should_close = 1;
            return 1;
        } else {
            // stdout/stderr: write to file
            if (r->file_mode == SP_FILE_WRITE_TRUNC) {
                HANDLE h = sp_internal_win32_open_inheritable_file(path, GENERIC_WRITE, CREATE_ALWAYS);
                if (h == INVALID_HANDLE_VALUE) return 0;
                *out_handle = h;
                *out_should_close = 1;
                return 1;
            } else if (r->file_mode == SP_FILE_WRITE_APPEND) {
                HANDLE h = sp_internal_win32_open_inheritable_file(path, FILE_APPEND_DATA, OPEN_ALWAYS);
                if (h == INVALID_HANDLE_VALUE) return 0;
                (void)sp_internal_win32_seek_to_end(h);
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

static inline int
sp_internal_win32_make_pipe(HANDLE *out_parent_end,
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

static inline int
sp_internal_win32_proc_is_done(Sp_Proc  *proc,
                               int    *out_exit_code)
{
    SP_ASSERT(proc);
    SP_ASSERT(out_exit_code);

    HANDLE h = sp_internal_win32_proc_get_handle(proc);
    if (!h) return 0;

    DWORD w = WaitForSingleObject(h, 0);
    if (w == WAIT_TIMEOUT) return 0;

    if (w != WAIT_OBJECT_0) {
        if (w == WAIT_FAILED) {
            sp_internal_win32_log_last_error("WaitForSingleObject failed");
        } else {
            sp_internal_log_error("WaitForSingleObject returned unexpected status: 0x%lX", (unsigned long)w);
        }
        *out_exit_code = -1;
        return 1;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h, &exit_code)) {
        sp_internal_win32_log_last_error("GetExitCodeProcess failed");
        *out_exit_code = -1;
        return 1;
    }

    *out_exit_code = (int)exit_code;
    return 1;
}

static inline int
sp_internal_procs_wait_any(Sp_Procs  *running,
                           size_t   *out_index,
                           int      *out_exit_code)
{
    SP_ASSERT(running);
    SP_ASSERT(out_index);
    SP_ASSERT(out_exit_code);
    SP_ASSERT(running->size > 0);

    if (running->size <= MAXIMUM_WAIT_OBJECTS) {
        HANDLE hs[MAXIMUM_WAIT_OBJECTS];

        for (size_t i = 0; i < running->size; i++) {
            hs[i] = sp_internal_win32_proc_get_handle(&running->buffer[i]);
        }

        DWORD w = WaitForMultipleObjects((DWORD)running->size, hs, FALSE, INFINITE);
        if (w == WAIT_FAILED) {
            sp_internal_win32_log_last_error("WaitForMultipleObjects failed");
            return 0;
        }

        DWORD idx = w - WAIT_OBJECT_0;
        if (idx >= (DWORD)running->size) {
            sp_internal_log_error("WaitForMultipleObjects returned unexpected status: 0x%lX", (unsigned long)w);
            return 0;
        }

        *out_index = (size_t)idx;
        *out_exit_code = sp_proc_wait(&running->buffer[*out_index]);
        return 1;
    }

    for (;;) {
        for (size_t i = 0; i < running->size; i++) {
            int code = 0;
            if (sp_internal_win32_proc_is_done(&running->buffer[i], &code)) {
                (void)sp_proc_wait(&running->buffer[i]);
                *out_index = i;
                *out_exit_code = code;
                return 1;
            }
        }
        Sleep(1);
    }
}

SPDEF void
sp_pipe_close(Sp_Pipe *p) SP_NOEXCEPT
{
    if (!sp_internal_pipe_is_valid(p)) return;
    HANDLE h = sp_internal_win32_pipe_get_handle(p);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    memset(p, 0, sizeof(*p));
}

SPDEF int
sp_pipe_read(Sp_Pipe *p,
             void   *buf,
             size_t  cap,
             size_t *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);

    *out_n = 0;

    if (!sp_internal_pipe_is_valid(p) || p->mode != SP_PIPE_READ) {
        sp_internal_log_error("sp_pipe_read: invalid pipe or wrong mode");
        return 0;
    }

    HANDLE h = sp_internal_win32_pipe_get_handle(p);
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
        Sp_String msg = sp_internal_win32_strerror(err);
        sp_internal_log_error("sp_pipe_read failed: %s", msg.buffer);
        sp_internal_string_free(&msg);
        return 0;
    }

    *out_n = (size_t)got;
    return 1;
}

SPDEF int
sp_pipe_write(Sp_Pipe     *p,
              const void *buf,
              size_t      len,
              size_t *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);
    *out_n = 0;

    if (!sp_internal_pipe_is_valid(p) || p->mode != SP_PIPE_WRITE) {
        sp_internal_log_error("sp_pipe_write: invalid pipe or wrong mode");
        return 0;
    }

    HANDLE h = sp_internal_win32_pipe_get_handle(p);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;

    DWORD wrote = 0;
    DWORD want = (len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (DWORD)len;

    BOOL ok = WriteFile(h, buf, want, &wrote, NULL);
    if (!ok) {
        sp_internal_win32_log_last_error("sp_pipe_write failed");
        return 0;
    }

    *out_n = (size_t)wrote;
    return 1;
}

SPDEF Sp_Proc
sp_cmd_exec_async(Sp_Cmd *cmd) SP_NOEXCEPT
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
    Sp_String cmd_quoted = SP_ZERO_INIT;

    // Child ends of pipes that exist in the parent prior to CreateProcess; must be closed in parent after success/fail.
    HANDLE stdin_child_end  = NULL; int close_stdin_child_end  = 0;
    HANDLE stdout_child_end = NULL; int close_stdout_child_end = 0;
    HANDLE stderr_child_end = NULL; int close_stderr_child_end = 0;

    // Out-pipe pointers (may be NULL if not requested)
    Sp_Pipe *stdin_out  = cmd->stdio.stdin_redir.out_pipe;
    Sp_Pipe *stdout_out = cmd->stdio.stdout_redir.out_pipe;
    Sp_Pipe *stderr_out = cmd->stdio.stderr_redir.out_pipe;

    // Make sure requested out pipes start invalid
    if (cmd->stdio.stdin_redir.kind  == SP_REDIR_PIPE)  { SP_ASSERT(stdin_out);  memset(stdin_out,  0, sizeof(*stdin_out)); }
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stdout_out); memset(stdout_out, 0, sizeof(*stdout_out)); }
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stderr_out); memset(stderr_out, 0, sizeof(*stderr_out)); }

    // ---- stdin ----
    if (cmd->stdio.stdin_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_internal_win32_make_pipe(&parent_end, &child_end, /*parent_reads=*/0)) {
            sp_internal_win32_log_last_error("CreatePipe(stdin) failed");
            goto fail;
        }
        // child reads:
        h_in = child_end;
        stdin_child_end = child_end;
        close_stdin_child_end = 1;

        // parent writes:
        sp_internal_win32_pipe_set_handle(stdin_out, parent_end, SP_PIPE_WRITE);
    } else {
        if (!sp_internal_win32_apply_redir(&cmd->stdio.stdin_redir, 1, &h_in, &close_in)) {
            sp_internal_win32_log_last_error("Failed to apply stdin redirection");
            goto fail;
        }
    }

    // ---- stdout ----
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_internal_win32_make_pipe(&parent_end, &child_end, /*parent_reads=*/1)) {
            sp_internal_win32_log_last_error("CreatePipe(stdout) failed");
            goto fail;
        }
        // child writes:
        h_out = child_end;
        stdout_child_end = child_end;
        close_stdout_child_end = 1;

        // parent reads:
        sp_internal_win32_pipe_set_handle(stdout_out, parent_end, SP_PIPE_READ);
    } else {
        if (!sp_internal_win32_apply_redir(&cmd->stdio.stdout_redir, 0, &h_out, &close_out)) {
            sp_internal_win32_log_last_error("Failed to apply stdout redirection");
            goto fail;
        }
    }

    // ---- stderr ----
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_TO_STDOUT) {
        h_err = h_out;   // merge into stdout (even if stdout is a pipe)
        close_err = 0;   // stdout "owns" the handle if it needs closing
    } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE) {
        HANDLE parent_end = NULL, child_end = NULL;
        if (!sp_internal_win32_make_pipe(&parent_end, &child_end, /*parent_reads=*/1)) {
            sp_internal_win32_log_last_error("CreatePipe(stderr) failed");
            goto fail;
        }
        h_err = child_end;
        stderr_child_end = child_end;
        close_stderr_child_end = 1;

        sp_internal_win32_pipe_set_handle(stderr_out, parent_end, SP_PIPE_READ);
    } else {
        if (cmd->stdio.stderr_redir.kind == SP_REDIR_INHERIT) {
            h_err = GetStdHandle(STD_ERROR_HANDLE);
            if (h_err == NULL || h_err == INVALID_HANDLE_VALUE) {
                sp_internal_win32_log_last_error("GetStdHandle(STD_ERROR_HANDLE) failed");
                goto fail;
            }
        } else {
            if (!sp_internal_win32_apply_redir(&cmd->stdio.stderr_redir, 0, &h_err, &close_err)) {
                sp_internal_win32_log_last_error("Failed to apply stderr redirection");
                goto fail;
            }
        }
    }

    startup_info.hStdInput  = h_in;
    startup_info.hStdOutput = h_out;
    startup_info.hStdError  = h_err;

    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_info, sizeof(PROCESS_INFORMATION));

    cmd_quoted = sp_internal_win32_quote_cmd(cmd);
    SP_ASSERT(cmd_quoted.size < 32768 && "sp: Windows requires command line (incl NUL) < 32767 chars");

    sp_internal_log_info(SP_INTERNAL_STRING_FMT_STR(cmd_quoted), SP_INTERNAL_STRING_FMT_ARG(cmd_quoted));

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

    sp_internal_string_free(&cmd_quoted);

    if (!success) {
        sp_internal_win32_log_last_error("CreateProcessA failed");
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
        Sp_Proc proc = SP_ZERO_INIT;
        sp_internal_win32_proc_set_handle(&proc, proc_info.hProcess);
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
        Sp_Proc proc = SP_ZERO_INIT;
        return proc;
    }
}

SPDEF void
sp_proc_detach(Sp_Proc *proc) SP_NOEXCEPT
{
    if (!sp_internal_proc_is_valid(proc)) return;

    HANDLE h = sp_internal_win32_proc_get_handle(proc);
    if (h) CloseHandle(h);

    sp_internal_win32_proc_set_handle(proc, 0);
    proc->handle_size = 0;
}

SPDEF int
sp_proc_wait(Sp_Proc *proc) SP_NOEXCEPT
{
    if (!proc)                            return -1;
    if (!sp_internal_proc_is_valid(proc)) return -1;

    HANDLE h = sp_internal_win32_proc_get_handle(proc);
    if (h == NULL) {
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    DWORD w = WaitForSingleObject(h, INFINITE);
    if (w == WAIT_FAILED) {
        sp_internal_win32_log_last_error("WaitForSingleObject failed");
        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }
    if (w != WAIT_OBJECT_0) {
        sp_internal_log_error("WaitForSingleObject returned unexpected status: 0x%lX", (unsigned long)w);
        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h, &exit_code)) {
        sp_internal_win32_log_last_error("GetExitCodeProcess failed");
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

typedef char sp_native_fits_pipe[(SP_NATIVE_MAX >= sizeof(int)) ? 1 : -1];
typedef char sp_native_fits_handle[(SP_NATIVE_MAX >= sizeof(pid_t)) ? 1 : -1];


static inline void
sp_internal_posix_proc_set_handle(Sp_Proc *proc,
                                  pid_t   pid)
{
    sp_internal_proc_handle_store_by_bytes(proc, &pid, sizeof(pid));
}

static inline pid_t
sp_internal_posix_proc_get_handle(Sp_Proc *proc)
{
    pid_t pid = (pid_t)0;
    sp_internal_proc_handle_load_by_bytes(proc, &pid, sizeof(pid));
    return pid;
}

static inline void
sp_internal_posix_pipe_set_handle(Sp_Pipe     *p,
                                  int         fd,
                                  Sp_PipeMode  mode)
{
    sp_internal_pipe_handle_store_by_bytes(p, &fd, sizeof(fd), mode);
}

static inline int
sp_internal_posix_pipe_get_handle(const Sp_Pipe *p)
{
    int fd = -1;
    sp_internal_pipe_handle_load_by_bytes(p, &fd, sizeof(fd));
    return fd;
}

static inline void
sp_internal_posix_log_errno(const char *context)
{
    (void)context; // Unused if error logging is disabled
    sp_internal_log_info("%s: errno=%d", context, errno);
}

static inline int
sp_internal_posix_set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return 0;
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return 0;
    return 1;
}

// Create a pipe where:
// - if parent_reads: parent gets read end, child gets write end
// - else: parent gets write end, child gets read end
static inline int
sp_internal_posix_make_pipe(int *out_parent_end,
                            int *out_child_end,
                            int  parent_reads)
{
    int fds[2] = {-1, -1};

    if (pipe(fds) != 0) return 0;

    int r = fds[0];
    int w = fds[1];

    // Ensure parent ends don't leak across exec in the child (and vice versa).
    // Also close unused ends.
    (void)sp_internal_posix_set_cloexec(r);
    (void)sp_internal_posix_set_cloexec(w);

    if (parent_reads) {
        *out_parent_end = r;
        *out_child_end  = w;
    } else {
        *out_parent_end = w;
        *out_child_end  = r;
    }
    return 1;
}

static inline int
sp_internal_posix_open_null(int is_stdin)
{
    return open("/dev/null", is_stdin ? O_RDONLY : O_WRONLY);
}

static inline int
sp_internal_posix_open_file(const Sp_Redirect *r,
                            int               is_stdin)
{
    const char *path = r->file_path.buffer ? r->file_path.buffer : "";

    if (is_stdin) {
        return open(path, O_RDONLY);
    }

    if (r->file_mode == SP_FILE_WRITE_TRUNC) {
        return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    }

    if (r->file_mode == SP_FILE_WRITE_APPEND) {
        return open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    }

    errno = EINVAL;
    return -1;
}

// Build argv for execvp: must be NULL-terminated.
// Returns malloc'd array; elements point into cmd->args strings (owned by cmd).
static inline char **
sp_internal_posix_build_argv(const Sp_Cmd *cmd)
{
    size_t n = cmd->args.size;
    char **argv = (char **)SP_REALLOC(NULL, sizeof(char*) * (n + 1));
    if (!argv) return NULL;
    for (size_t i = 0; i < n; ++i) {
        argv[i] = cmd->args.buffer[i].buffer ? cmd->args.buffer[i].buffer : (char*)"";
    }
    argv[n] = NULL;
    return argv;
}

static inline int
sp_internal_posix_shell_is_safe_char(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return 1;

    switch (c) {
        case '_': case '@': case '%': case '+': case '=':
        case ':': case ',': case '.': case '/': case '-':
            return 1;
        default:
            return 0;
    }
}

static inline void
sp_internal_posix_shell_append_escaped_arg(Sp_String   *out,
                                           const char *arg)
{
    if (!arg) arg = "";

    // Empty string must be quoted
    if (arg[0] == '\0') {
        sp_internal_string_append_cstr(out, "''");
        return;
    }

    // Check if we can print unquoted
    int safe = 1;
    for (const unsigned char *p = (const unsigned char *)arg; *p; ++p) {
        if (!sp_internal_posix_shell_is_safe_char(*p)) { safe = 0; break; }
    }

    if (safe) {
        sp_internal_string_append_cstr(out, arg);
        return;
    }

    // Single-quote style: '...'\''...'
    sp_internal_string_append_char(out, '\'');
    for (const char *p = arg; *p; ++p) {
        if (*p == '\'') {
            sp_internal_string_append_cstr(out, "'\\''"); // end quote, escaped quote, reopen
        } else {
            sp_internal_string_append_char(out, *p);
        }
    }
    sp_internal_string_append_char(out, '\'');
}

static inline Sp_String
sp_internal_posix_quote_cmd(const Sp_Cmd *cmd)
{
    Sp_String out = SP_ZERO_INIT;
    for (size_t i = 0; i < cmd->args.size; ++i) {
        const char *arg = cmd->args.buffer[i].buffer ? cmd->args.buffer[i].buffer : "";
        if (i) sp_internal_string_append_char(&out, ' ');
        sp_internal_posix_shell_append_escaped_arg(&out, arg);
    }
    return out;
}


static inline int
sp_internal_posix_status_to_exit_code(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static inline int
sp_internal_posix_wait_status_to_exit_code(int status)
{
    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static inline void
sp_internal_posix_sleep_1ms(void)
{
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = 1000000L;
    (void)nanosleep(&ts, NULL);
}

static inline int
sp_internal_procs_wait_any(Sp_Procs  *running,
                           size_t   *out_index,
                           int      *out_exit_code)
{
    SP_ASSERT(running);
    SP_ASSERT(out_index);
    SP_ASSERT(out_exit_code);
    SP_ASSERT(running->size > 0);

    for (;;) {
        for (size_t i = 0; i < running->size; i++) {
            pid_t pid = sp_internal_posix_proc_get_handle(&running->buffer[i]);
            if (pid <= 0) continue;

            int status = 0;
            pid_t r;
            do {
                r = waitpid(pid, &status, WNOHANG);
            } while (r < 0 && errno == EINTR);

            if (r == 0) continue;

            if (r < 0) {
                sp_internal_posix_log_errno("sp_batch_exec_sync: waitpid failed");
                *out_index = i;
                *out_exit_code = -1;
                memset(&running->buffer[i], 0, sizeof(running->buffer[i]));
                return 1;
            }

            *out_index = i;

            *out_exit_code = sp_internal_posix_wait_status_to_exit_code(status);

            memset(&running->buffer[i], 0, sizeof(running->buffer[i]));
            return 1;
        }

        sp_internal_posix_sleep_1ms();
    }
}

SPDEF void
sp_pipe_close(Sp_Pipe *p) SP_NOEXCEPT
{
    if (!sp_internal_pipe_is_valid(p)) return;
    int fd = sp_internal_posix_pipe_get_handle(p);
    if (fd >= 0) (void)close(fd);
    memset(p, 0, sizeof(*p));
}

SPDEF int
sp_pipe_read(Sp_Pipe *p,
             void   *buf,
             size_t  cap,
             size_t *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);
    *out_n = 0;

    if (!sp_internal_pipe_is_valid(p) || p->mode != SP_PIPE_READ) {
        sp_internal_log_info("%s", "sp_pipe_read: invalid pipe or wrong mode");
        return 0;
    }

    int fd = sp_internal_posix_pipe_get_handle(p);
    if (fd < 0) return 0;

    // POSIX read returns 0 on EOF.
    ssize_t got;
    do {
        got = read(fd, buf, cap);
    } while (got < 0 && errno == EINTR);

    if (got < 0) {
        sp_internal_posix_log_errno("sp_pipe_read failed");
        return 0;
    }

    *out_n = (size_t)got;
    return 1;
}

SPDEF int
sp_pipe_write(Sp_Pipe     *p,
              const void *buf,
              size_t      len,
              size_t     *out_n) SP_NOEXCEPT
{
    SP_ASSERT(out_n);
    *out_n = 0;

    if (!sp_internal_pipe_is_valid(p) || p->mode != SP_PIPE_WRITE) {
        sp_internal_log_info("%s", "sp_pipe_write: invalid pipe or wrong mode");
        return 0;
    }

    int fd = sp_internal_posix_pipe_get_handle(p);
    if (fd < 0) return 0;

    ssize_t wrote;
    do {
        wrote = write(fd, buf, len);
    } while (wrote < 0 && errno == EINTR);

    if (wrote < 0) {
        sp_internal_posix_log_errno("sp_pipe_write failed");
        return 0;
    }

    *out_n = (size_t)wrote;
    return 1;
}


SPDEF Sp_Proc
sp_cmd_exec_async(Sp_Cmd *cmd) SP_NOEXCEPT
{
    SP_ASSERT(cmd);

    // Out pipes
    Sp_Pipe *stdin_out  = cmd->stdio.stdin_redir.out_pipe;
    Sp_Pipe *stdout_out = cmd->stdio.stdout_redir.out_pipe;
    Sp_Pipe *stderr_out = cmd->stdio.stderr_redir.out_pipe;

    if (cmd->stdio.stdin_redir.kind  == SP_REDIR_PIPE)  { SP_ASSERT(stdin_out);  memset(stdin_out,  0, sizeof(*stdin_out)); }
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stdout_out); memset(stdout_out, 0, sizeof(*stdout_out)); }
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE)  { SP_ASSERT(stderr_out); memset(stderr_out, 0, sizeof(*stderr_out)); }

    int stdin_parent_end  = -1, stdin_child_end  = -1;
    int stdout_parent_end = -1, stdout_child_end = -1;
    int stderr_parent_end = -1, stderr_child_end = -1;

    int in_fd  = -1;
    int out_fd = -1;
    int err_fd = -1;

    int close_in_fd  = 0;
    int close_out_fd = 0;
    int close_err_fd = 0;

    // Declared here to satisfy C++ goto quirks
    pid_t pid = -1;
    char **argv = NULL;
    Sp_String quoted = SP_ZERO_INIT;

    // stdin
    if (cmd->stdio.stdin_redir.kind == SP_REDIR_PIPE) {
        if (!sp_internal_posix_make_pipe(&stdin_parent_end, &stdin_child_end, /*parent_reads=*/0)) {
            sp_internal_posix_log_errno("pipe(stdin) failed");
            goto fail;
        }
        sp_internal_posix_pipe_set_handle(stdin_out, stdin_parent_end, SP_PIPE_WRITE);
    } else if (cmd->stdio.stdin_redir.kind == SP_REDIR_NULL) {
        in_fd = sp_internal_posix_open_null(/*is_stdin=*/1);
        if (in_fd < 0) { sp_internal_posix_log_errno("open(/dev/null for stdin) failed"); goto fail; }
        close_in_fd = 1;
    } else if (cmd->stdio.stdin_redir.kind == SP_REDIR_FILE) {
        in_fd = sp_internal_posix_open_file(&cmd->stdio.stdin_redir, /*is_stdin=*/1);
        if (in_fd < 0) { sp_internal_posix_log_errno("open(stdin file) failed"); goto fail; }
        close_in_fd = 1;
    }

    // stdout
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE) {
        if (!sp_internal_posix_make_pipe(&stdout_parent_end, &stdout_child_end, /*parent_reads=*/1)) {
            sp_internal_posix_log_errno("pipe(stdout) failed");
            goto fail;
        }
        sp_internal_posix_pipe_set_handle(stdout_out, stdout_parent_end, SP_PIPE_READ);
    } else if (cmd->stdio.stdout_redir.kind == SP_REDIR_NULL) {
        out_fd = sp_internal_posix_open_null(/*is_stdin=*/0);
        if (out_fd < 0) { sp_internal_posix_log_errno("open(/dev/null for stdout) failed"); goto fail; }
        close_out_fd = 1;
    } else if (cmd->stdio.stdout_redir.kind == SP_REDIR_FILE) {
        out_fd = sp_internal_posix_open_file(&cmd->stdio.stdout_redir, /*is_stdin=*/0);
        if (out_fd < 0) { sp_internal_posix_log_errno("open(stdout file) failed"); goto fail; }
        close_out_fd = 1;
    }

    // stderr
    // Note: SP_REDIR_TO_STDOUT handled in child after stdout is set up.
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE) {
        if (!sp_internal_posix_make_pipe(&stderr_parent_end, &stderr_child_end, /*parent_reads=*/1)) {
            sp_internal_posix_log_errno("pipe(stderr) failed");
            goto fail;
        }
        sp_internal_posix_pipe_set_handle(stderr_out, stderr_parent_end, SP_PIPE_READ);
    } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_NULL) {
        err_fd = sp_internal_posix_open_null(/*is_stdin=*/0);
        if (err_fd < 0) { sp_internal_posix_log_errno("open(/dev/null for stderr) failed"); goto fail; }
        close_err_fd = 1;
    } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_FILE) {
        err_fd = sp_internal_posix_open_file(&cmd->stdio.stderr_redir, /*is_stdin=*/0);
        if (err_fd < 0) { sp_internal_posix_log_errno("open(stderr file) failed"); goto fail; }
        close_err_fd = 1;
    }

    argv = sp_internal_posix_build_argv(cmd);
    if (!argv) {
        sp_internal_posix_log_errno("alloc argv failed");
        goto fail;
    }
    if (!argv[0] || argv[0][0] == '\0') {
        sp_internal_log_info("%s", "sp: empty argv[0]");
        SP_FREE(argv);
        goto fail;
    }

    quoted = sp_internal_posix_quote_cmd(cmd);
    sp_internal_log_info(SP_INTERNAL_STRING_FMT_STR(quoted), SP_INTERNAL_STRING_FMT_ARG(quoted));
    sp_internal_string_free(&quoted);

    pid = fork();
    if (pid < 0) {
        sp_internal_posix_log_errno("fork failed");
        SP_FREE(argv);
        goto fail;
    }

    if (pid == 0) {
        // I am the child

        // stdin
        if (cmd->stdio.stdin_redir.kind == SP_REDIR_PIPE) {
            (void)close(stdin_parent_end);
            if (dup2(stdin_child_end, STDIN_FILENO) < 0) _exit(127);
            (void)close(stdin_child_end);
        } else if (cmd->stdio.stdin_redir.kind == SP_REDIR_NULL || cmd->stdio.stdin_redir.kind == SP_REDIR_FILE) {
            if (dup2(in_fd, STDIN_FILENO) < 0) _exit(127);
            if (close_in_fd) (void)close(in_fd);
        }

        // stdout
        if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE) {
            (void)close(stdout_parent_end);
            if (dup2(stdout_child_end, STDOUT_FILENO) < 0) _exit(127);
            (void)close(stdout_child_end);
        } else if (cmd->stdio.stdout_redir.kind == SP_REDIR_NULL || cmd->stdio.stdout_redir.kind == SP_REDIR_FILE) {
            if (dup2(out_fd, STDOUT_FILENO) < 0) _exit(127);
            if (close_out_fd) (void)close(out_fd);
        }

        // stderr
        if (cmd->stdio.stderr_redir.kind == SP_REDIR_TO_STDOUT) {
            if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) _exit(127);
        } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE) {
            (void)close(stderr_parent_end);
            if (dup2(stderr_child_end, STDERR_FILENO) < 0) _exit(127);
            (void)close(stderr_child_end);
        } else if (cmd->stdio.stderr_redir.kind == SP_REDIR_NULL || cmd->stdio.stderr_redir.kind == SP_REDIR_FILE) {
            if (dup2(err_fd, STDERR_FILENO) < 0) _exit(127);
            if (close_err_fd) (void)close(err_fd);
        }

        // Close any leftover pipe fds (defensive)
        if (stdin_child_end  >= 0) (void)close(stdin_child_end);
        if (stdout_child_end >= 0) (void)close(stdout_child_end);
        if (stderr_child_end >= 0) (void)close(stderr_child_end);

        // exec
        execvp(argv[0], argv);
        _exit(127);
    }

    // I am the parent
    SP_FREE(argv);

    // Close child ends in parent
    if (stdin_child_end  >= 0) (void)close(stdin_child_end);
    if (stdout_child_end >= 0) (void)close(stdout_child_end);
    if (stderr_child_end >= 0) (void)close(stderr_child_end);

    // Close file/null fds opened in parent
    if (close_in_fd  && in_fd  >= 0) (void)close(in_fd);
    if (close_out_fd && out_fd >= 0) (void)close(out_fd);
    if (close_err_fd && err_fd >= 0) (void)close(err_fd);

    {
        Sp_Proc proc = SP_ZERO_INIT;
        sp_internal_posix_proc_set_handle(&proc, pid);
        return proc;
    }

fail:
    // Close any created pipe fds and invalidate out pipes
    if (stdin_child_end  >= 0) (void)close(stdin_child_end);
    if (stdout_child_end >= 0) (void)close(stdout_child_end);
    if (stderr_child_end >= 0) (void)close(stderr_child_end);

    if (cmd->stdio.stdin_redir.kind  == SP_REDIR_PIPE && stdin_out)  sp_pipe_close(stdin_out);
    if (cmd->stdio.stdout_redir.kind == SP_REDIR_PIPE && stdout_out) sp_pipe_close(stdout_out);
    if (cmd->stdio.stderr_redir.kind == SP_REDIR_PIPE && stderr_out) sp_pipe_close(stderr_out);

    if (close_in_fd  && in_fd  >= 0) (void)close(in_fd);
    if (close_out_fd && out_fd >= 0) (void)close(out_fd);
    if (close_err_fd && err_fd >= 0) (void)close(err_fd);

    {
        Sp_Proc proc = SP_ZERO_INIT;
        return proc;
    }
}

SPDEF void
sp_proc_detach(Sp_Proc *proc) SP_NOEXCEPT
{
    if (!sp_internal_proc_is_valid(proc)) return;

    pid_t pid = sp_internal_posix_proc_get_handle(proc);
    SP_ASSERT(proc->handle_size == sizeof(pid_t));
    (void)pid;

    sp_internal_posix_proc_set_handle(proc, 0);
    proc->handle_size = 0;
}

SPDEF int
sp_proc_wait(Sp_Proc *proc) SP_NOEXCEPT
{
    if (!proc)                            return -1;
    if (!sp_internal_proc_is_valid(proc)) return -1;

    pid_t pid = sp_internal_posix_proc_get_handle(proc);
    if (pid <= 0) {
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    int status = 0;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        sp_internal_posix_log_errno("sp_proc_wait: waitpid failed");
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    memset(proc, 0, sizeof(*proc));
    return sp_internal_posix_wait_status_to_exit_code(status);
}

#endif // SP_POSIX


SPDEF int
sp_batch_exec_sync(Sp_CmdBatch  *batch,
                   size_t        max_parallel) SP_NOEXCEPT
{
    if (!batch) return -1;

    const size_t total = batch->cmds.size;
    if (total == 0) return 0;

    if (max_parallel == 0 || max_parallel > total) {
        max_parallel = total;
    }

    Sp_Procs running   = SP_ZERO_INIT;
    size_t   next      = 0;
    int      fail_code = 0;

    while (running.size < max_parallel && next < total) {
        Sp_Proc p = sp_cmd_exec_async(&batch->cmds.buffer[next]);
        sp_darray_append(&running, p);
        next++;
    }

    while (running.size > 0) {
        size_t idx = 0;
        int exit_code = -1;

        if (!sp_internal_procs_wait_any(&running, &idx, &exit_code)) {
            fail_code = -1;
            break;
        }

        if (!sp_internal_proc_is_valid(&running.buffer[idx])) {
            running.buffer[idx] = running.buffer[running.size - 1];
            running.size--;
        } else {
#if SP_WINDOWS
            exit_code = sp_proc_wait(&running.buffer[idx]);
            running.buffer[idx] = running.buffer[running.size - 1];
            running.size--;
#endif
        }

        if (fail_code == 0 && exit_code != 0) {
            fail_code = exit_code;
        }

        if (fail_code == 0) {
            while (running.size < max_parallel && next < total) {
                Sp_Proc p = sp_cmd_exec_async(&batch->cmds.buffer[next]);
                sp_darray_append(&running, p);
                next++;
            }
        }
    }

    sp_darray_free(&running);
    return fail_code;
}


#if defined(SP_EMBED_LICENSE)
/**
 * LICENSE EMBEDDING
 * If SP_EMBED_LICENSE is defined in the same translation unit as
 * SP_IMPLEMENTATION, sp.h embeds its BSD-3-Clause license text into the
 * final program binary (as a static string).
 *
 * This can make it easier to satisfy license notice requirements for
 * binary distributions. You are still responsible for complying with the
 * BSD-3-Clause terms for your distribution.
 *
 * The author of this library considers embedding this notice in the
 * binary to be an acceptable way of reproducing the license text.
 */


// Must be implementation TU
#  if !defined(SP_IMPLEMENTATION)
#    error "SP_EMBED_LICENSE must be defined in the same translation unit as SP_IMPLEMENTATION."
#  endif

// Toolchain check
#  if !defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
#    error "SP_EMBED_LICENSE is not supported on this toolchain (supported: MSVC, clang, GCC)."
#  endif


// toolchain / platform attributes
#  if defined(_MSC_VER)
#    pragma section(".sp_lic", read)
#    define SP_INTERNAL_ALLOCATE_LICENSE __declspec(allocate(".sp_lic"))
#    define SP_INTERNAL_USED
#    ifdef __cplusplus
#      define SP_INTERNAL_DEF extern "C"
#    else
#      define SP_INTERNAL_DEF extern
#    endif
#    if defined(_M_IX86)
#      pragma comment(linker, "/INCLUDE:_sp_embedded_license")
#      pragma comment(linker, "/INCLUDE:_sp_embedded_license_ptr")
#    else
#      pragma comment(linker, "/INCLUDE:sp_embedded_license")
#      pragma comment(linker, "/INCLUDE:sp_embedded_license_ptr")
#    endif
#  else /* GCC / Clang */
#    if defined(__APPLE__) || defined(__MACH__)
#      define SP_INTERNAL_ALLOCATE_LICENSE __attribute__((section("__DATA,__sp_lic"), used))
#    else
#      define SP_INTERNAL_ALLOCATE_LICENSE __attribute__((section(".sp_lic"), used))
#    endif
#    define SP_INTERNAL_USED __attribute__((used))
#    define SP_INTERNAL_DEF
#  endif

#  ifdef __cplusplus
extern "C" {
#  endif

SP_INTERNAL_DEF SP_INTERNAL_ALLOCATE_LICENSE
const char sp_embedded_license[] =
    "sp.h\n"
    "\n"
    "BSD-3-CLAUSE LICENSE\n"
    "\n"
    "Copyright 2025 rsore\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n"
    "\n"
    "1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n"
    "\n"
    "3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n";

SP_INTERNAL_DEF SP_INTERNAL_USED
const char *sp_embedded_license_ptr = sp_embedded_license;

#  ifdef __cplusplus
} /* extern "C" */
#  endif

#endif // SP_EMBED_LICENSE

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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
