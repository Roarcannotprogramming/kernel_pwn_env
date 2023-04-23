lsmod
cat /proc/kallsyms | grep "startup_64"
cat /proc/kallsyms | grep "prepare_kernel_cred"
cat /proc/kallsyms | grep "commit_creds"

