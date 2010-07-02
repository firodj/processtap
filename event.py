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

FUNCTION_ENTRY = 1
FUNCTION_EXIT  = 2
SYSCALL_ENTRY  = 4
SYSCALL_EXIT   = 8
MEMORY_READ    = 16
MEMORY_WRITE   = 32
MEMORY_EXECUTE = 64

event2str = { FUNCTION_ENTRY : "function.entry", FUNCTION_EXIT : "function.exit", 
              SYSCALL_ENTRY : "syscall.entry", SYSCALL_EXIT : "syscall.exit",
              MEMORY_READ : "memory.read", MEMORY_WRITE : "memory.write", MEMORY_EXECUTE : "memory.execute"}

class event:
    def __init__(self, etype, pid, tid, inst, stack):
        assert etype in event2str
        self.type = etype
        self.pid = pid
        self.tid = tid
        self.module = None
	self.instruction = inst
	self.stack = stack

    def __str__(self):
        s = event2str[self.type] + ": "
        s += "pid=%d, " % self.pid
        s += "tid=%d, " % self.tid
        s += "module=%s, " % self.module
        s += "instruction=%s, " % hex(self.instruction)
        s += "stack=%s" % hex(self.stack)
        return s

    def __repr__(self):
        return event2str[self.type]

class function_entry(event):
    def __init__(self, pid, tid, inst, stack, funcaddr):
        event.__init__(self, FUNCTION_ENTRY, pid, tid, inst, stack)
	self.function = funcaddr

    def __str__(self):
        if isinstance(self.function, (int, long)):
            v = hex(self.function)
        else:
            v = self.function
        s = event.__str__(self) + ", function=%s" % v
        return s

class function_exit(event):
    def __init__(self, pid, tid, inst, stack, funcaddr, retaddr, retval):
        event.__init__(self, FUNCTION_EXIT, pid, tid, inst, stack)
	self.function = funcaddr
	self.returnaddr = retaddr
	self.returnvalue = retval

    def __str__(self):
        if isinstance(self.function, (int, long)):
            fun = hex(self.function)
        else:
            fun = self.function

        s = event.__str__(self) + ", funcaddr=%s, returnaddr=%s, returnvalue=%s" % \
            (fun, hex(self.returnaddr), hex(self.returnvalue))
        return s

class syscall_entry(event):
    def __init__(self, pid, tid, inst, stack, sysno):
        event.__init__(self, SYSCALL_ENTRY, pid, tid, inst, stack)
	self.sysno = sysno

    def __str__(self):
        s = event.__str__(self) + ", sysno=%d" % self.sysno
        return s

class syscall_exit(event):
    def __init__(self, pid, tid, inst, stack, sysno, retval):
        event.__init__(self, SYSCALL_EXIT, pid, tid, inst, stack)
	self.sysno   = sysno
	self.returnval = retval

class memory_read(event):
    def __init__(self, pid, tid, inst, stack, sysno, address, value):
        event.__init__(self, MEMORY_READ, pid, tid, inst, stack)
        self.memaddr  = addr
        self.memsize  = len(value)
        self.memvalue = value

class memory_write(event):
    def __init__(self, pid, tid, inst, stack, sysno, address, value):
        event.__init__(self, MEMORY_WRITE, pid, tid, inst, stack)
        self.memaddr  = addr
        self.memsize  = len(value)
        self.memvalue = value

class memory_execute(event):
    def __init__(self, pid, tid, inst, stack, sysno, address,  value):
        event.__init__(self, MEMORY_EXECUTE, pid, tid, inst, stack)
        self.memaddr  = addr
        self.memsize  = len(value)
        self.memvalue = value
