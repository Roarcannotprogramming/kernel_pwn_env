# DEBUG_PATH="/sys/kernel/debug"
DEBUG_PATH="/debug"
if [ $# -eq 1 ]; then 
  DEBUG_PATH=$1
fi

echo "[-] DEBUG_PATH="$DEBUG_PATH

ln -s $DEBUG_PATH"/tracing/trace" /trace

echo 0 > $DEBUG_PATH"/tracing/events/uprobes/enable"
echo "p:malloc_returned /challenge/ss_agent:0x9D8E rax=%ax:x64 mem_rax=+0(%ax) rdi=%di:u64 rsi=%si:u64 rdx=%dx:u64 rcx=%cx:u64 r8=%r8:u64 r9=%r9:u64" > $DEBUG_PATH"/tracing/uprobe_events"
echo "p:read_n_ret /challenge/ss_agent:0x99D9 rsp=%sp:x64 ret_addr=+0(%sp) ret_addr_8=+8(%sp)" >> $DEBUG_PATH"/tracing/uprobe_events"
echo "p:rop_start /challenge/ss_agent:0x94c6" >> $DEBUG_PATH"/tracing/uprobe_events"
echo 1 > $DEBUG_PATH"/tracing/events/uprobes/enable"
echo > $DEBUG_PATH"/tracing/trace"
./exp