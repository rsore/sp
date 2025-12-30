#!/bin/bash

set -xe

THIS_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
pushd "$THIS_DIR"

CC="cc"
CFLAGS="-Wall -Wextra -pedantic -ggdb"

$CC $CFLAGS -o 01_sync 01_sync.c
$CC $CFLAGS -o 10_async_wait 10_async_wait.c
$CC $CFLAGS -o 20_stdout_to_pipe 20_stdout_to_pipe.c
$CC $CFLAGS -o 30_redirect_to_file 30_redirect_to_file.c
$CC $CFLAGS -o 40_stdin_from_pipe 40_stdin_from_pipe.c
$CC $CFLAGS -o 50_request_response 50_request_response.c
$CC $CFLAGS -o 60_stdin_from_file 60_stdin_from_file.c
$CC $CFLAGS -o 70_batch 70_batch.c

popd
