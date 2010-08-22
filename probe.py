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
  
  ProcessTap is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""

import event
import probeexp

_probes = {
    event.FUNCTION_ENTRY : [], 
    event.FUNCTION_EXIT : [],
    event.SYSCALL_ENTRY : [], 
    event.SYSCALL_EXIT : [],
    event.MEMORY_READ : [], 
    event.MEMORY_WRITE : [], 
    event.MEMORY_EXECUTE : [], 
    }

def probe_not_callable():
    raise Exception("[!] Probe is not callable")

class probe:
    def __init__(self, event, cond = None):
        if cond is None: 
            cond = probeexp.ProbeConstant(True)
        elif not isinstance(cond, probeexp.ProbeExpression):
            raise Exception("[!] Invalid function specification %s" % str(cond))

        self.event     = event
        self.condition = cond
        self.callback  = None
        self.enabled   = True

    def __call__(self, callback = None):
        self.callback = callback
        _probes[self.event] += [self]
        return probe_not_callable

    def __str__(self):
        return "%s %s" % (self.condition, self.callback.__name__)

    def eval_condition(self, ev, env):
        return eval(self.condition.actualize(ev, env))

    def gen_filter(self, t):
        return self.condition.generateFilter(t)

    def run_callback(self, ev, env):
        if self.eval_condition(ev, env):
            env.event = ev
            return self.callback(env)
        else:
            return

class function_entry(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.FUNCTION_ENTRY, cond)

class function_exit(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.FUNCTION_EXIT, cond)

class syscall_entry(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.SYSCALL_ENTRY, cond)

class syscall_exit(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.SYSCALL_EXIT, cond)

class memory_read(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.MEMORY_READ, cond)

class memory_write(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.MEMORY_WRITE, cond)

class memory_execute(probe):
    def __init__(self, cond = None):
        probe.__init__(self, event.MEMORY_EXECUTE, cond)

def show_probes():
    print "[*] Loaded probes:"
    for ev, pp in _probes.iteritems():
        if not pp: continue
        print "    [*] %s" % event.event2str[ev]
        for p in pp:
            if p.enabled:
                print "        [+] %s" % p
            else:
                print "        [-] %s" % p

def run_probes(ev, env):
    for probe in _probes[ev.type]:
        probe.run_callback(ev, env)

def enabled_probes():
    ee = 0
    for e, pp in _probes.iteritems():
        if pp:
            ee |= e
    return ee

def filters(t):
    f = []
    for e, pp in _probes.iteritems():
        for p in pp:
            f += p.gen_filter(t)
    return f

if __name__ == "__main__":
    import symbol
    from probeexp import function_name, syscall_num, syscall_name, memory_size, process_id

    symbol.init("")

    @function_entry(function_name == "xxx")
    @function_entry(function_name == "fopen")
    def wrap_function_entry(env):
        print "Calling wrap_function_entry()"

    @function_exit()
    def wrap_function_exit(env):
        print "Calling wrap_function_exit()"

    @syscall_entry(syscall_name >> ["open", "close"])
    def wrap_syscall_entry(env):
        print "Calling wrap_syscall_entry()"

    @syscall_exit()
    def wrap_syscall_exit(env):
        print "Calling wrap_syscall_exit()"

    @memory_read()
    def wrap_mem_read(env):
        print "Calling wrap_mem_read()"

    @memory_write(memory_size == 1)
    def wrap_mem_write(env):
        print "Calling wrap_mem_write()"

    @function_exit((process_id == 20) & (function_name == "malloc"))
    def wrap_function_exit2(env):
        print "Calling wrap_function_exit2()"

    show_probes()

    e = event.function_entry(pid = 20, tid = 15, inst = 0xbadbabe, stack = 0xdeadbeef, funcaddr = 0xcafebabe)    
    print "[*] Dispatching event %s" % e
    run_probes(e, None)

    e = event.syscall_entry(pid = 20, tid = 15, inst = 0xbadbabe, stack = 0xdeadbeef, sysno = 18)    
    print "[*] Dispatching event %s" % e
    run_probes(e, None)
