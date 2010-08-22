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
import singleton
import symbol

COMPARISON_OPERANDS = ["==", "!=", ">", "<", ">=", "<="]
LOGICAL_OPERANDS    = ["&", "|"]

class ProbeExpression:
    def __init__(self):
        pass

    def generateFilter(self, t):
        f = []
        if isinstance(self, ProbeComparisonExpression):
            if isinstance(self.operands[1], ProbeConstant):
                t = (self.operands[0].name, self.operands[1].value)
                f.append(t)
        elif isinstance(self, ProbeCompoundExpression):
            for op in self.operands:
                f.extend(op.generateFilter())
        return f

    def actualize(self, ev, env):
        abstract()

class ProbeCompoundExpression(ProbeExpression):
    def __init__(self, operands, operator):
        self.operands = operands
        self.operator = operator

    def __str__(self):
        n = len(self.operands)
        assert 1 <= n <= 2
        if n == 1:
            # Unary expression
            s = "(%s %s)" % (self.operator, self.operands[0])
        else:
            # Binary expression
            s = "(%s %s %s)" % (self.operands[0], self.operator, self.operands[1])
        return s

    def __and__(self, other):
        assert isinstance(other, ProbeCompoundExpression)
        return ProbeLogicalExpression(self, ProbeLogicalOperand("&"), other)

    def __or__(self, other):
        assert isinstance(other, ProbeCompoundExpression)
        return ProbeLogicalExpression(self, ProbeLogicalOperand("|"), other)

class ProbeComparisonExpression(ProbeCompoundExpression):
    def __init__(self, lhs, op, rhs):
        assert isinstance(op, ProbeComparisonOperand) and \
            (isinstance(lhs, ProbeConstant) or isinstance(lhs, ProbeVariable)) and \
            (isinstance(rhs, ProbeConstant) or isinstance(rhs, ProbeVariable))

        ProbeCompoundExpression.__init__(self, [lhs, rhs], op)

    def actualize(self, ev, env):
        lhs = self.operands[0].actualize(ev, env)
        rhs = self.operands[1].actualize(ev, env)
        if lhs is None or rhs is None:
            return 'True'

        if isinstance(lhs, list):
            # Keep lists on the right
            assert not isinstance(rhs, list)
            tmp = lhs
            lhs = rhs
            rhs = lhs

        if not isinstance(rhs, list):
            rhs = [rhs]

        if len(rhs) == 0:
            r = 'False'
        else:
            r = "|".join(["(%s %s %s)" % (lhs, self.operator, x) for x in rhs])
            r = "(" + r + ")"

        return r

class ProbeLogicalExpression(ProbeCompoundExpression):
    def __init__(self, lhs, op, rhs):
        assert isinstance(op, ProbeLogicalOperand), "[!] Invalid logical operand '%s'" % op
        ProbeCompoundExpression.__init__(self, [lhs, rhs], op)

    def actualize(self, ev, env):
        return "(%s %s %s)" % (self.operands[0].actualize(ev, env), self.operator, self.operands[1].actualize(ev, env))

class ProbeOperand:
    def __init__(self, op):
        self.op = op

    def __str__(self):
        return str(self.op)

class ProbeComparisonOperand(ProbeOperand):
    def __init__(self, op):
        assert op in COMPARISON_OPERANDS
        ProbeOperand.__init__(self, op)

class ProbeLogicalOperand(ProbeOperand):
    def __init__(self, op):
        assert op in LOGICAL_OPERANDS
        ProbeOperand.__init__(self, op)

class ProbeVariable(ProbeExpression):
    def __init__(self, name = None):
        ProbeExpression.__init__(self)
        self.name = name

    def __str__(self):
        return self.name

    def actualize(self, ev, env):
        """
        Actualize the this variable according to the dispatched event and to the environment.
        """
        abstract()

    def parse_rhs(self, op):
        if isinstance(op, (int, long, str)):
            v = ProbeConstant(op)
        else:
            v = op
        return v

    def __rshift__(self, other):
        assert isinstance(other, (list, set, tuple))

        ll = []
        for o in other:
            o = self.parse_rhs(o)
            if o is None:
                continue
            ll.append(ProbeComparisonExpression(self, ProbeComparisonOperand("=="), o))

        if len(ll) == 0:
            return ProbeConstant(False)


        r = ll[0]
        for o in ll[1:]:
            r = ProbeLogicalExpression(r, ProbeLogicalOperand("|"), o)
        return r

    def __eq__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand("=="), other)

    def __ne__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand("!="), other)

    def __gt__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand(">"), other)

    def __ge__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand(">="), other)

    def __lt__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand("<"), other)

    def __le__(self, other):
        other = self.parse_rhs(other)
        return ProbeComparisonExpression(self, ProbeComparisonOperand("<="), other)

class ProbeConstant(ProbeVariable):
    def __init__(self, v):
        ProbeVariable.__init__(self)
        self.value = v

    def actualize(self, ev, env):
        """
        Return the constant value. The dispatched event is simply ignored.
        """
        return str(self.value)

    def __str__(self):
        return repr(self.value)

class ProbeSymbol(ProbeVariable):
    def __init__(self, v):
        ProbeVariable.__init__(self)
        self.name = v

    def actualize(self, ev, env):
        """
        Return the constant value. The dispatched event is simply ignored.
        """
        ll = [s for s in symbol.get_symbol(self.name)]
        return ll

    def __str__(self):
        return "@%s" % self.name

###########################################################################

class probe_property(singleton.singleton, ProbeVariable):
    def __init__(self):
        self.name = self.__class__.__name__
        ProbeVariable.__init__(self, self.name)

    def __str__(self):
        return self.name

class process_id(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'pid', None)

class process_name(probe_property):
    def actualize(self, ev, env):
        return None

class thread_id(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'tid', None)

class module_name(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'module', None)

class function_address(probe_property):
    def actualize(self, ev, env):
        if isinstance(event, (event.function_entry, event.function_exit)):
            return None
        return ev.function

class function_name(probe_property):
    def parse_rhs(self, rhs):
        assert isinstance(rhs, str)
        return ProbeSymbol(rhs)

    def actualize(self, ev, env):
        if isinstance(event, (event.function_entry, event.function_exit)):
            return None
        return ev.function

class function_retaddr(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'returnaddr', None)

class function_retval(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'returnvalue', None)

class memory_address(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'memaddr', None)

class memory_size(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'memsize', None)

class memory_value(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'memvalue', None)

class syscall_num(probe_property):
    def actualize(self, ev, env):
        return getattr(ev, 'sysno', None)

class syscall_name(probe_property):
    def parse_rhs(self, rhs):
        assert isinstance(rhs, str)
        return ProbeConstant(symbol.get_syscall(rhs))

    def actualize(self, ev, env):
        return getattr(ev, 'sysno', None)

process_id     = process_id()
process_name   = process_name()
thread_id      = thread_id()
module_name    = module_name()
function_name  = function_name()
function_address  = function_address()
memory_address = memory_address()
memory_size    = memory_size()
memory_value   = memory_value()
syscall_num    = syscall_num()
syscall_name   = syscall_name()

if __name__ == "__main__":
    import event

    symbol.init("")

    v = (process_id == 20) | (thread_id >= 50) & (process_name == "emacs") | (syscall_num == 2) | (syscall_name == "open")
    print "[*] Condition:", v
    print "[*] Filter:", v.generateFilter([])

    ####

    e = event.function_entry(pid = 20, tid = 76, module = None, inst = None, stack = None, callee = None)
    print "[*] Event:", e

    a = v.actualize(e, None)
    print "[*] Actualize:", a, "=>", eval(a)

    ####

    e = event.function_entry(pid = 18, tid = 15, module = None, inst = None, stack = None, callee = None)
    print "[*] Event:", e

    a = v.actualize(e, None)
    print "[*] Actualize:", a, "=>", eval(a)

    ####

    v = (process.id == 20) | (function.name == "malloc")
    print "[*] Condition:", v

    e = event.syscall_entry(pid = 18, tid = 15, module = None, inst = None, stack = None, sysno = 31337)
    print "[*] Event:", e

    a = v.actualize(e, None)
    print "[*] Actualize:", a, "=>", eval(a)

