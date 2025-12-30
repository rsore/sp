@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

REM Fail on first error
set CL_FLAGS=/nologo /W4 /WX /Z7 /std:c11

REM Get directory of this script
set THIS_DIR=%~dp0
pushd "%THIS_DIR%"

echo Building examples with cl.exe

cl %CL_FLAGS% /Fe01_sync.exe               01_sync.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe10_async_wait.exe         10_async_wait.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe20_stdout_to_pipe.exe     20_stdout_to_pipe.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe30_redirect_to_file.exe   30_redirect_to_file.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe40_stdin_from_pipe.exe    40_stdin_from_pipe.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe50_request_response.exe   50_request_response.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe60_stdin_from_file.exe    60_stdin_from_file.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe70_batch.exe              70_batch.c
if errorlevel 1 goto :fail

echo.
echo All examples built successfully.
goto :eof

:fail
echo.
echo Build failed.
exit /b 1
