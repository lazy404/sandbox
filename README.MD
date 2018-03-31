echo /tmp/core >  /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable



docker exec -u test -ti sandbox_sandbox_1 sh
