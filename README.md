# sp.h

[![CI](https://github.com/rsore/sp/actions/workflows/test.yml/badge.svg)](https://github.com/rsore/sp/actions/workflows/test.yml)

`sp.h` is a single-header C and C++ library implementing a thin,
cross-platform API for subprocess management, with no external dependencies,
targeting Windows and POSIX systems.

The library focuses on direct process execution and I/O redirection without relying
on shells, external tools, or platform-specific wrappers.

---

## Project integration

`sp.h` is a single-header library, so integrating it into your project is
straight-forward. Drop the header file into your project tree and, in exactly
**one** of your translation units, define `SP_IMPLEMENTATION` before including it:

```c
#define SP_IMPLEMENTATION
#include "sp.h"
```

This causes `sp.h` to emit its function definitions into that translation unit.
In all other files that include `sp.h`, only the public API declarations are visible.

This works for both C and C++ translation units.

---

## Example

```c
#define SP_IMPLEMENTATION
#include "sp.h"

int main(void)
{
    SpCmd cmd = {0}; // In C++, use {} for initialization

    sp_cmd_add_arg(&cmd, "echo");
    sp_cmd_add_arg(&cmd, "hello");

    int exit_code = sp_cmd_exec_sync(&cmd);

    sp_cmd_free(&cmd);

	return exit_code;
}
```

---

## Logging and diagnostics

By default, `sp.h` performs **no logging and produces no stdout/stderr output** of its own.
All informational and error messages are disabled unless explicitly enabled by the user.

Logging can be enabled by defining the following macros **before** including `sp.h`, in the **same** translation unit as you define `SP_IMPLEMENTATION`:

```c
#define SP_LOG_INFO(msg)  printf("%s\n", (msg)) // Or your logging function of choice
#define SP_LOG_ERROR(msg) fprintf(stderr, "Error: %s\n", (msg)) // Or your logging function of choice
```
These macros are invoked by `sp.h` when commands are executed or when errors occur.
`msg` is a NUL-terminated C-string.

---

## Non-goals

`sp.h` intentionally keeps its scope small. It does **not** aim to provide:

- Shell parsing or command-line interpretation
- Job control, terminal emulation, or signal forwarding
- High-level process orchestration or pipelines
- Environment-variable management beyond inheritance

The goal is to expose a minimal, predictable subprocess API that maps closely to
native platform behavior.

---

## Tested platforms and compilers

### Linux
- **Compilers:** GCC 14, Clang 20
- **C standards:** C99, C11, C17, C23
- **C++ standards:** C++11, C++14, C++17, C++20, C++23, C++26
- **Flags:** `-Wall -Wextra -Werror -pedantic-errors`

### Windows
- **Compiler:** MSVC 2022 (cl)
- **C standards:** C11, C17
- **C++ standards:** C++14, C++17, C++20, C++latest
- **Flags:** `/W4 /WX`

### macOS
- **Compiler:** Apple Clang (latest)
- **C standards:** C99, C11, C17, C2x
- **C++ standards:** C++11, C++14, C++17, C++20, C++2b
- **Flags:** `-Wall -Wextra -Werror -pedantic-errors`

---

## License

`sp.h` is licensed under the 3-Clause BSD license.
See the `LICENSE` file for details.
