/**
 * sp.h — Cross-platform API for subprocess management,
 *        targeting Windows and POSIX.
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
 *                                                  Example: `#define SPDEF static inline`
 *                                                  Default: Nothing
 *  - SP_ASSERT(cond) ............................ Assertion function for `sp.h` to use.
 *                                                  Default: libc assert.
 *  - SP_LOG_INFO(fmt, ...) ...................... Used to print commands as they are run.
 *                                                 Uses printf-style formatting.
 *                                                  Default: Nothing.
 *  - SP_LOG_ERROR(fmt, ...) ..................... Used to print error messages as they occur.
 *                                                 Uses printf-style formatting.
 *                                                  Default: Nothing.
 *  - SP_REALLOC(ptr, new_size) && SP_FREE(ptr) .. Define custom allocators for `sp.h`.
 *                                                 Must match the semantics of libc realloc and free.
 *                                                  Default: `libc realloc` and `libc free`.
 *
 * ~~ LICENSE ~~
 * `sp.h` is licenses under the MIT license. Full license text is
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

// Dynamic array
typedef struct {
    char *buffer;
    size_t size;
    size_t capacity;
} SpString;

// Dynamic array
typedef struct {
    SpString *buffer;
    size_t    size;
    size_t    capacity;
} SpStrings;

// Command builder
typedef struct {
    SpStrings args;
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


#if SP_WINDOWS
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#if SP_POSIX
#  include <sys/types.h>
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
    char *buf = SP_REALLOC(NULL, len+1);
    if (!buf) return NULL;
    memcpy(buf, str, len);
    buf[len] = '\0';
    return buf;
}

static inline void
sp_string_ensure_null_(SpString *str)
{
    sp_darray_grow_to_fit_(str, str->size + 1);
    str->buffer[str->size] = '\0';
}

static inline SpString
sp_string_make_(const char *c_str)
{
    SpString str = {0};
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


SPDEF void
sp_cmd_add_arg(SpCmd      *cmd,
               const char *arg) SP_NOEXCEPT
{
    (void)cmd;
    (void)arg;
    if (cmd->args.size+1 < cmd->args.capacity) {
        printf("Hello\n");
        sp_string_replace_content_(cmd->args.buffer + cmd->args.size, arg);
    } else {
        SpString str = sp_string_make_(arg);
        sp_darray_append_(&cmd->args, str);
    }
}

SPDEF int
sp_cmd_exec_sync(SpCmd *cmd) SP_NOEXCEPT
{
    SpProc proc = sp_cmd_exec_async(cmd);
    int exit_code = sp_proc_wait(&proc);
    return exit_code;
}

SPDEF void
sp_cmd_reset(SpCmd *cmd) SP_NOEXCEPT
{
    cmd->args.size = 0;
}

SPDEF void
sp_cmd_free(SpCmd *cmd) SP_NOEXCEPT
{
    sp_darray_free_(&cmd->args);
}

SPDEF int
sp_proc_wait(SpProc *proc) SP_NOEXCEPT
{
    (void)proc;
    // TODO: implement

    return 0;
}


/**
 * Windows implementation follows
 */
#if SP_WINDOWS

// Compile-time check that SP_NATIVE_MAX is large enough
typedef char sp_native_fits_handle_[(SP_NATIVE_MAX >= sizeof(HANDLE)) ? 1 : -1];

static inline void
sp_proc_set_handle_(SpProc* proc, HANDLE handle)
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

/* // https://learn.microsoft.com/en-gb/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way */
/* static inline char * */
/* sp_win32_quote_cmd_(const SpCmd *cmd) */
/* { */
/*     for (size_t i = 0; i < cmd->args.size; ++i) { */
/*         const char *arg = cmd->args.buffer[i]; */
/*         if (arg == NULL) break; */
/*         size_t len = strlen(arg); */
/*         if (i > 0) nob_da_append(quoted, ' '); */
/*         if (len != 0 && NULL == strpbrk(arg, " \t\n\v\"")) { */
/*             // no need to quote */
/*             nob_da_append_many(quoted, arg, len); */
/*         } else { */
/*             // we need to escape: */
/*             // 1. double quotes in the original arg */
/*             // 2. consequent backslashes before a double quote */
/*             size_t backslashes = 0; */
/*             nob_da_append(quoted, '\"'); */
/*             for (size_t j = 0; j < len; ++j) { */
/*                 char x = arg[j]; */
/*                 if (x == '\\') { */
/*                     backslashes += 1; */
/*                 } else { */
/*                     if (x == '\"') { */
/*                         // escape backslashes (if any) and the double quote */
/*                         for (size_t k = 0; k < 1+backslashes; ++k) { */
/*                             nob_da_append(quoted, '\\'); */
/*                         } */
/*                     } */
/*                     backslashes = 0; */
/*                 } */
/*                 nob_da_append(quoted, x); */
/*             } */
/*             // escape backslashes (if any) */
/*             for (size_t k = 0; k < backslashes; ++k) { */
/*                 nob_da_append(quoted, '\\'); */
/*             } */
/*             nob_da_append(quoted, '\"'); */
/*         } */
/*     } */
/* } */

SPDEF SpProc
sp_cmd_exec_async(SpCmd *cmd) SP_NOEXCEPT
{
    (void)cmd;
    // TODO: Implement shell-escape string function (taking into accound windows vs posix shell specifics) to stringify command run
    SP_LOG_INFO("Running cmd\n");


    /* BOOL CreateProcessA(NULL, // lpApplicationName, */
    /*                     [in, out, optional] LPSTR                 lpCommandLine, */
    /*                     [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes, */
    /*                     [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes, */
    /*                     [in]                BOOL                  bInheritHandles, */
    /*                     [in]                DWORD                 dwCreationFlags, */
    /*                     [in, optional]      LPVOID                lpEnvironment, */
    /*                     [in, optional]      LPCSTR                lpCurrentDirectory, */
    /*                     [in]                LPSTARTUPINFOA        lpStartupInfo, */
    /*                     [out]               LPPROCESS_INFORMATION lpProcessInformation); */

    // TODO: Implement
    SpProc proc = {0};
    return proc;
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
 * MIT License
 *
 * Copyright (c) 2025 Ruben Sørensen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
