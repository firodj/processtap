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

import os, sys
import tempfile
import pickle
import warnings
import struct
warnings.filterwarnings('ignore', category=DeprecationWarning)
import xmlrpclib
from cparser import type as ctype

__includepath = []
__prototypes = {}
__parser_proxy = None
__ptr_size = 4  

class InvalidArgument(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

class MissingPrototype(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

def parse_header(h):
    ff = __parser_proxy.parse(h, [], __includepath, __ptr_size)
    ff = pickle.loads(ff)
    print "[*] Parsing '%s' (%d functions)" % (h, len(ff))

    for f, p in ff.iteritems():
        __prototypes[f] = p


def set_prototype(p):
    tmp = tempfile.NamedTemporaryFile()
    tmp.write(p)
    tmp.flush()
    ff = __parser_proxy.parse(tmp.name, [], __includepath, __ptr_size)
    ff = pickle.loads(ff)
    print "[*] Parsing '%s' (%d functions)" % (p, len(ff))

    for f, p in ff.iteritems():
        __prototypes[f] = p

def get_prototype(f):
    if f in __prototypes:
        return __prototypes[f]
    else:
        return None

# XXX: unused??
def prototype(f, s = None):
    if f in __prototypes:
        return __prototypes(f)
    else:
        return None

# XXX: unused??
def argument(func, arg):
    if func in __prototypes:
        func = __prototypes[func]
        for a in func.getArguments():
            if a.getName() == a:
                return a
    return None

def __peek(ctx, fmt, base, size):
    assert len(fmt) == 1
    if base == None:
        pass
    else:
        if ctx.isLittleEndian():
            fmt = "<" + fmt
        else:
            fmt = ">" + fmt
        return struct.unpack(fmt, ctx.mem[base, base+size])[0]


def __poke(ctx, fmt, base, size, value):
    assert len(fmt) == 1
    if ctx.isLittleEndian():
        fmt = "<" + fmt
    else:
        fmt = ">" + fmt
    ctx.mem[base:base+size] = struct.pack(fmt,value)


def __peek_argument(ctx, arg, addr):
    if arg.isInt():
        if arg.getSize() == 1:
            fmt = "b"
        elif arg.getSize() == 2:
            fmt = "h"
        elif arg.getSize() == 4:
            fmt = "i"
        elif arg.getSize() == 8:
            fmt = "l"
        else:
            assert 0
        if not arg.isSigned():
            fmt = fmt.upper()
        return __peek(ctx, fmt, addr, arg.getSize())

    elif arg.isChar():
        fmt = "b"
        if not arg.isSigned():
            fmt = "B"
        return __peek(ctx, fmt, addr, 1)

    elif arg.isPtr():
        arg_ = arg.getMember()
        if addr:
            addr_ = __peek(ctx, "I", addr, arg.getSize())
            if addr_:
                if arg_.isVoid() or arg.isFuncPtr():
                    return __peek(ctx, "I", addr_, arg.getSize())
                elif arg.isString():
                    r = ""
                    s = __peek(ctx, "s", addr_, 1)
                    while ord(s) != 0:
                        r += s
                        s = __peek(ctx, "s", addr_ + len(r), 1)
                    return r
                else:
                    return __peek_argument(ctx, arg_, addr_)
        else:
            return None

    elif arg.isFloat():
        return float(0)

    elif arg.isStruct():
        pass

    elif arg.isUnion():
        pass

    elif arg.isArray():
        arg_ = arg.getMember()
        len_ = arg.getLength()
        r = []
        for i in range(len_):
            r += __peek_argument(ctx, arg_, addr + i*arg_.getSize())
        return r

    elif arg.isVoid():
        return None

    elif arg.isFunction():
        assert 0

    return None


def __poke_argument(ctx, arg, addr, value):
    if arg.isInt():
        if arg.getSize() == 1:
            fmt = "b"
        elif arg.getSize() == 2:
            fmt = "h"
        elif arg.getSize() == 4:
            fmt = "i"
        elif arg.getSize() == 8:
            fmt = "l"
        else:
            assert 0
        if not arg.isSigned():
            fmt = fmt.upper()
        return __peek(ctx, fmt, addr, arg.getSize())

    elif arg.isChr():
        fmt = "b"
        if not arg.isSigned():
            fmt = "B"
        return __peek(fm, fmt, addr, 1)

    elif arg.isPtr():
        arg_ = arg.getMember()
        if addr:
            addr_ = ctx.mem[addr:addr+arg.getSize()]
            if addr_:
                if arg_.isVoid() or arg.isFuncPtr():
                    # return the address
                    return __peek(ctx, "P", addr_, arg.getSize())
                elif arg.isString():
                    r = ""
                    s = __peek(ctx, "s", addr_, 1)
                    while s:
                        r += s
                        s = __peek(ctx, "s", addr_ + len(r), 1)
                    return s
                else:
                    return __peek_argument(ctx, arg_, addr_)

    elif arg.isFloat():
        return 0

    elif arg.isStruct():
        pass

    elif arg.isUnion():
        pass

    elif arg.isArray():
        arg_ = arg.getMember()
        len_ = arg.getLength()
        r = []
        for i in range(len_):
            r += __peek_argument(ctx, arg_, addr + i*arg_.getSize())
        return r

    elif arg.isVoid():
        return None

    elif arg.isFunction():
        assert 0

    return None


def peek_argument(ctx, func, arg, stackptr = None):
    if stackptr is None:
        stackptr = ctx.regs.STACKPTR

    if func in __prototypes:
        func = __prototypes[func]
        i = 0
        for a in func.getArguments():
            if (isinstance(arg, str) and a.getName() == arg) or (isinstance(arg, int) and arg == i):
                return __peek_argument(ctx, a, stackptr + i*ctx.PTR_SIZE)
            i += 1

        return InvalidArgument("Invalid argument '%s' for '%s'" % (str(arg), func))
    else:
        return MissingPrototype("Missing prototype for '%s'" % (func))


def poke_argument(ctx, func, arg, value):
    if func in __prototypes:
        func = __prototypes[func]
        i = 0
        for a in func.getArguments():
            if a.getName() == a:
                poke_argument(ctx, arg, ctx.regs.STACKPTR + (i+1)*ctx.PTR_SIZE, value)
                return 
            i += 1
    return None

def init(path = ["/usr/include"], ptrsize = 4):
    global __includepath, __parser_proxy, __ptr_size
    __parser_proxy = xmlrpclib.ServerProxy("http://localhost:45352/", allow_none = True)
    __includepath = path
    __ptr_size = ptrsize
