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

    // We reuse allocated strings after cmd_reset
    size_t internal_strings_already_initted;
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
    if (cmd->args.size < cmd->internal_strings_already_initted) {
        sp_string_replace_content_(&cmd->args.buffer[cmd->args.size++], arg);
    } else {
        SpString str = sp_string_make_(arg);
        sp_darray_append_(&cmd->args, str);
        cmd->internal_strings_already_initted += 1;
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
    for (size_t i = 0; i < cmd->internal_strings_already_initted; ++i) {
        sp_string_free_(&cmd->args.buffer[i]);
    }
    sp_darray_free_(&cmd->args);
    cmd->internal_strings_already_initted = 0;
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

SPDEF SpProc
sp_cmd_exec_async(SpCmd *cmd) SP_NOEXCEPT
{
    STARTUPINFO startup_info;
    ZeroMemory(&startup_info, sizeof(STARTUPINFO));
    startup_info.cb          = sizeof(STARTUPINFO);
    startup_info.hStdError   = GetStdHandle(STD_ERROR_HANDLE);  // TODO: Support custom file handles
    startup_info.hStdOutput  = GetStdHandle(STD_OUTPUT_HANDLE); // TODO: Support custom file handles
    startup_info.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);  // TODO: Support custom file handles
    startup_info.dwFlags    |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_info, sizeof(PROCESS_INFORMATION));

    SpString cmd_quoted = sp_win32_quote_cmd_(cmd);
    SP_ASSERT(cmd_quoted.size < 32768 && "sp: Windows sets the requirement that the command to be executed, including NUL-terminator, be less than 32767 long");

    SP_LOG_INFO(SP_STRING_FMT_STR(cmd_quoted), SP_STRING_FMT_ARG(cmd_quoted));

    BOOL success = CreateProcessA(NULL,              // lpApplicationName,
                                  cmd_quoted.buffer, // lpCommandLine (SpString is NUL-terminated for cstr compatibility)
                                  NULL,              // lpProcessAttributes,
                                  NULL,              // lpThreadAttributes,
                                  TRUE,              // bInheritHandles,
                                  0,                 // dwCreationFlags,
                                  NULL,              // lpEnvironment,
                                  NULL,              // lpCurrentDirectory,
                                  &startup_info,     // lpStartupInfo,
                                  &proc_info);       //lpProcessInformation
    if (!success) {
        SpString error_message = sp_win32_strerror(GetLastError());
        SP_LOG_ERROR("Failed to create child process for %s: %s",
                     cmd->args.buffer[0].buffer,
                     error_message.buffer);
        sp_string_free_(&error_message);
        SpProc proc = SP_ZERO_INIT;
        SP_ASSERT(sp_proc_is_valid_(&proc) == 0 && "sp implementation error, empty SpProc should be invalid");
        return proc;
    }

    CloseHandle(proc_info.hThread);

    SpProc proc = SP_ZERO_INIT;
    sp_proc_set_handle_(&proc, proc_info.hProcess);
    return proc;
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
    if (w != WAIT_OBJECT_0) {
        DWORD err = GetLastError();
        SpString msg = sp_win32_strerror(err);
        SP_LOG_ERROR("WaitForSingleObject failed: %s", msg.buffer);
        sp_string_free_(&msg);

        CloseHandle(h);
        memset(proc, 0, sizeof(*proc));
        return -1;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h, &exit_code)) {
        DWORD err = GetLastError();
        SpString msg = sp_win32_strerror(err);
        SP_LOG_ERROR("GetExitCodeProcess failed: %s", msg.buffer);
        sp_string_free_(&msg);

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
