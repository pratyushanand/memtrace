# memtrace
Trace peak memory allocation of task and kernel module

There are several scenarios where we land into oom-killer in the early boot
process, specially in a memory constrained environment. It becomes very
difficult to identify the user space task or a kernel module who
required more memory compared to their previous released versions. This
tool is an attempt to debug such issues, which will help us to identify
peak memory usage of each task and a kernel module inserted from user
space.
mm_page_alloc() and mm_page_free() are lowest level of kernel APIs which
allocates and frees memory from buddy. This tool enables tracepoint of
these two functions and then keeps track of peak memory usage of each
task. Additionally, it also enabled tracepoint of module_load and
module_put. These two tracepoints helps to identify kernel module if the
user space task was insmod or modprobe etc. If a task was already
running before this tool was started then, it initializes peak memory of
that task with corresponding vmRSS component from /proc/$tid/statm

After launching this tool, an user can send signal SIGUSR1(`killall -s
SIGUSR1 memtrace`, where memtrace is the name of compiled binary output
of this code) to print statistics on STDOUT. A signal SIGUSR2 can be
sent to print stats in a file /tmp/mem_debug_log. Last statistics is
also save in that file when this tool is terminated.

There could still be some cma and memblock allocations which may not be
tracked using this tool.
Need to find a better way to define MAX_TASK_TO_MONITOR,
MAX_NUMBER_OF_CPUS and DEFAULT_LOG_PATH.

usage:
# gcc -o memtrace memtrace.c
# ./memtrace &
(if tracing directory is not mounted at /sys/kernel/debug/tracing/ then
pass path of tracing directory as argument like following)
# ./memtrace /sys/kernel/tracing/ &
(to get current stats on screen)
# killall -s SIGUSR1 memtrace
(to save current stats in file /tmp/mem_debug_log)
# killall -s SIGUSR2 memtrace
(to terminate the spplication and to save current stats in file)
# killall -s SIGTERM memtrace
