# DEBUG_PATH="/sys/kernel/debug"
DEBUG_PATH="/debug"
if [ $# -eq 1 ]; then 
  DEBUG_PATH=$1
fi

echo "[-] DEBUG_PATH="$DEBUG_PATH

ln -s $DEBUG_PATH"/tracing/trace" /trace
echo "1111111"

# echo "function" > $DEBUG_PATH"/tracing/current_tracer"
# echo "mod:piehook" > $DEBUG_PATH"/tracing/set_ftrace_filter"
# cat $DEBUG_PATH"/tracing/set_ftrace_filter"
echo 0 > $DEBUG_PATH"/tracing/events/enable"
echo 0 > $DEBUG_PATH"/tracing/events/kprobes/enable"
echo > $DEBUG_PATH"/tracing/kprobe_events"

# rmmod ss

# echo "p:trace1 ctf:ctf_ioctl+0x47" >> $DEBUG_PATH"/tracing/kprobe_events"
echo "p:fk 0xffffffff810986b9 rax=%ax:x64 rsp=%sp:x64 mem=-0(%sp)" >> $DEBUG_PATH"/tracing/kprobe_events"
# echo 1 > $DEBUG_PATH"/tracing/events/kprobes/int_overflow/enable"
echo 1 > $DEBUG_PATH"/tracing/events/kprobes/fk/enable"
echo > $DEBUG_PATH"/tracing/trace"
# insmod /challenge/ss.ko
./exp


# root@ubuntu:~# echo 0 > /sys/kernel/debug/tracing/events/kprobes/int_overflow/enable 
# root@ubuntu:~# echo "p:int_overflow 0xffffffffc079c350 rax=%ax:x64" > /sys/kernel/debug/tracing/kprobe_events
# root@ubuntu:~# echo 1 > /sys/kernel/debug/tracing/events/kprobes/int_overflow/enable 
# root@ubuntu:~# echo > /sys/kernel/debug/tracing/trace
# root@ubuntu:~# cat /sys/kernel/debug/tracing/trace
# 
