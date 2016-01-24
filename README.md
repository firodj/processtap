ProcessTap is a dynamic tracing framework for analyzing closed source-applications. ProcessTap is inspired by [DTrace](http://opensolaris.org/os/community/dtrace/) and [SystemTap](http://sourceware.org/systemtap/), but it is specific for analyzing closed-source user-space applications. ProcessTap leverages dynamic binary instrumentation to intercept the events of interest (e.g., function calls, system call, memory accesses, and conditional control transfers). Although the current implementation relies on [PinTool](http://www.pintool.org), alternative back-ends for instrumentation (e.g., [Valgrind](http://www.valgrind.org), [Qemu](http://www.qemu.org), or [DynamoRIO](http://code.google.com/p/dynamorio/)) can be used. The language used in ProcessTap for writing scripts to instrument applications is [Python](http://www.python.org).

ProcessTap currently runs on:

  * Debian (sid) x86
  * Ubuntu (Lucid) x86 and x86\_64
  * Ubuntu (Karmic) x86

ProcessTap is currently under heavy development; the interface might change a little bit in the future.


```
$ cat malloctrace.ptap
#!/usr/bin/env processtap
# -*- python -*-

include("stdlib.h")

@function_entry(function_name == "malloc")
def malloc_entry(ctx):
    print ">>> %s called from %.8x with argument %u" % (ctx.function_name, ctx.caller, ctx.args[0])

$ ./malloctrace.ptap -- /bin/ls
[*] Executable file: /bin/ls
[*] PTAP file: malloctrace.ptap
[*] Loaded 299 system calls
[*] Parsing 'stdlib.h' (123 functions)
[*] Loaded probes:
    [*] function.entry
        [+] (function.name == @malloc) malloc_entry
[*] Parsing '/bin/ls' [0000000000400238-000000000061c280]
[*] Parsing '/lib/ld-2.11.1.so' [00007f012f042000-00007f012f264128]
[*] Parsing '/lib/librt-2.11.1.so' [00007f012dd63000-00007f012df6abd0]
[*] Parsing '/lib/libselinux.so.1' [00007f012dd00000-00007f012df1d608]
[*] Parsing '/lib/libacl.so.1.1.0' [00007f012dc24000-00007f012de2b1d0]
[*] Parsing '/lib/libc-2.11.1.so' [00007f012da86000-00007f012de07828]
[*] Parsing '/lib/libpthread-2.11.1.so' [00007f012d0ae000-00007f012d2ca380]
[*] Parsing '/lib/libdl-2.11.1.so' [00007f012cf7f000-00007f012d182100]
[*] Parsing '/lib/libattr.so.1.1.0' [00007f012cf70000-00007f012d1740d0]
>>> malloc called from 0x4100c4 with argument 30
...
```