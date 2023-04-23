#!/usr/bin/env bash

BASEDIR=$(dirname "$0")
path=$BASEDIR/../pwn
if [ ! -d "$path/core" ];then
    echo "error: $path/core directory not found"
    exit 1
fi

if [ $# -ne 1 ]; then 
    echo "zip / unzip required"
    exit 1
fi

cd $path/core

if [[ $1 == "zip" ]]; then
    find . -print0 | cpio --null -ov --format=newc | gzip -9 -n > ../core_modified.cpio
else
    find . -print0 | cpio --null -ov --format=newc> ../core_modified.cpio
fi

