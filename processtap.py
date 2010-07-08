#!/usr/bin/python

"""
  Copyright notice
  ================
  
  Copyright (C) 2010
      Lorenzo  Martignoni <martignlo@gmail.com>
      Roberto  Paleari    <roberto.paleari@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""

import threading
import platform

__envlock   = threading.Lock()
__envs      = {}

class Execfail(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

import sys, os
import env
import event
import symbol
import probe
import probeexp
sys.path.append("./cparser")
import prototype

class UnsupportedPlatform(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

def resolve(s):
    r = symbol.get_symbol(s)
    return set(r)

def init(exe, tap, m):
    if not os.path.isfile(exe):
        raise Execfile("[!] Invalid executable (%s)" % exe)

    # init env, syms, and prototypes
    symbol.init(exe)
    env.init(m.read_reg, m.write_reg, m.read_mem, m.write_mem)

    mac = platform.machine()
    if mac == 'i686':
        ptr_size = 4
    elif mac == 'x86_64':
        ptr_size = 8
    else:
        assert False, "[!] Unknown machine '%s'" % mac

    prototype.init(["/usr/include"], ptr_size)

    if not os.path.isfile(tap):
        raise Execfail("[!] Invalid tap (%s)" % tap)

    # run the scripts
    execfile(tap, {
            "exe"  : exe,
            "tap"  : tap,
            "argv" : [exe],

            # probes
            "function_entry" : probe.function_entry,
            "function_exit"  : probe.function_exit,
            "syscall_entry"  : probe.syscall_entry,
            "syscall_exit"   : probe.syscall_exit,
            "memory_read"    : probe.memory_read,
            "memory_write"   : probe.memory_write,
            "memory_execute" : probe.memory_execute,

            # expressions
            "process_id"       : probeexp.process_id,
            "process_name"     : probeexp.process_name,
            "thread_id"        : probeexp.thread_id,
            "module_name"      : probeexp.module_name,
            "function_address" : probeexp.function_address,
            "function_name"    : probeexp.function_name,
            "memory_address"   : probeexp.memory_address,
            "memory_size"      : probeexp.memory_size,
            "memory_value"     : probeexp.memory_value,
            "syscall_num"      : probeexp.syscall_num,
            "syscall_name"     : probeexp.syscall_name,

            # symbols
            "module"  : symbol.get_module,
            "symbol"  : resolve,
            "syscall" : symbol.get_syscall,

            # prototypes
            "include"   : prototype.parse_header, 
            "prototype" : prototype.get_prototype, 
            "declare"   : prototype.set_prototype, 

            # exceptions
            "MissingPrototype": prototype.MissingPrototype
            })

    probe.show_probes()

    return probe.enabled_probes()

def dispatch(ev):
    global __envs, __envlock, __callbacks

    __envlock.acquire()
    if ev.tid not in __envs:
        # Instantiate an environment object for this thread
        __envs[ev.tid] = env.build()
    e = __envs[ev.tid]
    __envlock.release()

    probe.run_probes(ev, e)
