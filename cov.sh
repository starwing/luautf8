#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Clean previous build/coverage artifacts so lcov only sees this run.
rm -f lutf8lib.o lua-utf8.so lutf8lib.c.gcov \
      coverage.info lutf8lib.info
find . -type f \( -name '*.gcda' -o -name '*.gcno' \) -delete

# luarocks make accepts VAR=VALUE overrides on the command line.
# We override CFLAGS to add --coverage (plus -fPIC because overriding
# CFLAGS replaces the default that normally contains -fPIC), and LDFLAGS
# to add --coverage at link time: the builtin backend links with
# LD + LDFLAGS, so CFLAGS alone is not enough for the coverage runtime.
luarocks make --no-install --deps-mode=none \
    rockspecs/luautf8-scm-1.rockspec \
    CFLAGS="-O1 -g --coverage -fPIC -DNDEBUG" \
    LDFLAGS="--coverage"

# Run all requested tests.  LUA_CPATH is set so the freshly built
# ./lua-utf8.so is found even on systems whose default cpath omits ".".
LUA_CPATH="./?.so;;" lua test.lua
LUA_CPATH="./?.so;;" lua test_compat.lua
LUA_CPATH="./?.so;;" lua test_pm.lua

# Capture coverage, keep only lutf8lib.c, and print its coverage summary.
lcov --capture --directory . --output-file coverage.info --rc branch_coverage=1 --ignore-errors unsupported
lcov --extract coverage.info '*/lutf8lib.c' --output-file lutf8lib.info --rc branch_coverage=1 
lcov --list lutf8lib.info --rc branch_coverage=1 
