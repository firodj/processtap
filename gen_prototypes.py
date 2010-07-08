import os, sys, re, platform, subprocess

BLACKLIST = ["eventfd2", "fstatfs64", "rt_sigqueueinfo", "signalfd4", "statfs64", "olduname", "stat64", "readlinkat"]

# For these syscalls, we don't have the headers on a standard installation of Linux
BLACKLIST.extend(["capget", "capset", "add_key", "request_key"])

HEADER = """
#define __builtin_va_arg_pack_len() 0

#include <sys/inotify.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/aio_abi.h>
#include <aio.h>
#include <mqueue.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/utsname.h>


typedef uint64_t u64;
 
"""


filename = "/usr/include/asm/unistd_%d.h"

mac = platform.machine()
if mac == 'i686':
    filename = filename % 32
elif mac == 'x86_64':
    filename = filename % 64
else:
    assert False

if not os.path.isfile(filename):
    print "[W] File '%s' is not available: no syscall names" % filename
    exit(0)

f = open(filename, 'r')
data = []
for l in f.readlines():
    l = l.strip()
    if not l.startswith("#define __NR_"):
        continue
    l = l.replace("#define __NR_", "")
    tmp = l.split()
    data.append(tmp[0])
f.close()

data.sort()

print HEADER

for s in data:
    if s in BLACKLIST:
        # Blacklisted
        continue

    cmdline = "man 2 %s" % s
    p = subprocess.Popen(cmdline.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        print >> sys.stderr, "[W] Missing man page for '%s'" % s
        continue

    if "Unimplemented system calls." in out:
        # Not implemented
        continue

    data = ""
    for l in out.split("\n"):
        l = l.strip()

        if "%s(" % s in l or len(data) > 0:
            data += " " + l
            if ";" in l:
                break

    if len(data) == 0:
        print >> sys.stderr, "[W] Missing prototype for '%s'" % s
        continue

    print data


