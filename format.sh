#!/bin/sh

#
# use clang-format to format code
#

# clang-format version must >= 13
MIN_VERSION=13

check_clang_format() {
    if [ -z $(command -v clang-format) ];then
        echo "can't find command clang-format !!" >&2
        exit 1
    fi

    v=$(clang-format --version |grep -Eo "version [0-9]+" |grep -Eo "[0-9]+")
    if [ $v -lt $MIN_VERSION ];then
        echo $(clang-format --version | head -2) >&2
        echo "version must >= $MIN_VERSION !!" >&2
        exit 2
    fi
}

# main
check_clang_format
clang-format --style=file -i websock/*.[ch] main.c

