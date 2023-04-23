#!/usr/bin/env bash
# run this script as root

BASEDIR=$(dirname "$0")
path=$BASEDIR/../pwn
if [ -d "$path/core" ]; then
  rm -rf $path/core
fi
mkdir -p $path/core
cd $path/core

if file ../core.cpio | grep "zip"; then
    cp ../core.cpio core.cpio.gz
    gunzip ./core.cpio.gz
else
    cp ../core.cpio core.cpio
fi

cpio -idm < ./core.cpio
rm ./core.cpio

# chown -R ${UID}:${GID} .
