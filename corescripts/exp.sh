#!/usr/bin/env bash
# run it as root

set -e

BASEDIR=$(dirname "$0")
path=$BASEDIR/../pwn
exp_path=$BASEDIR/../exp
$BASEDIR/uncpio.sh 
gcc $exp_path/exp.c $exp_path/banzi.c $exp_path/cred.c $exp_path/io_uring.c -static -lpthread -g -o $exp_path/exp 
cp $exp_path/exp $path/core 
cp $path/init $path/core 
# cp $path/corescript/tools/* $path/core 
$BASEDIR/cpio.sh zip 
cd $path && $path/run.sh -s
