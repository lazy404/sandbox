#!/bin/sh

set -x

echo /tmp/core >  /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
echo 1 > /proc/sys/kernel/core_uses_pid

sh