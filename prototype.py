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

def __cast(ctx, fmt, buf, size = None):
    assert len(fmt) == 1
    if fmt == "P":
        # P can be used only in native mode (use I/L instead according to pointer size)
        if ctx.PTR_SIZE == 4:
            fmt = "I"
        elif ctx.PTR_SIZE == 8:
            fmt = "Q"
        else:
            assert 0
    if ctx.isLittleEndian():
        fmt = "<" + fmt
    else:
        fmt = ">" + fmt

    if size:
        return struct.unpack(fmt, buf[:size])[0]
    else:
        return struct.unpack(fmt, buf)[0]


def __peek(ctx, fmt, base, size):
    if base == None or size == 0:
        return None
    else:
        return __cast(ctx, fmt, ctx.mem[base, base+size])


def __peek_argument(ctx, arg, value):
    # print "__peek_argument", arg, repr(value)
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

        return __cast(ctx, fmt, value, arg.getSize())

    elif arg.isChar():
        fmt = "c"
        if not arg.isSigned():
            fmt = "B"
        return __cast(ctx, fmt, value, 1)

    elif arg.isPtr():
        arg_ = arg.getMember()
        ptr = __cast(ctx, "P", value)
        if ptr:
            if arg_.isVoid() or arg.isFuncPtr():
                return ptr
            elif arg.isString():
                r = ""
                s = __peek(ctx, "c", ptr, 1)
                while s and ord(s) != 0:
                    r += s
                    s = __peek(ctx, "c", ptr + len(r), 1)
                return r
            else:
                ptr_ = ctx.mem[ptr, ptr+ctx.PTR_SIZE]
                return __peek_argument(ctx, arg_, ptr_)
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
        ptr = __cast(ctx, "P", value)
        for i in range(len_):
            r += [__peek_argument(ctx, arg_, ptr + i*arg_.getSize())]
        return r

    elif arg.isVoid():
        return None

    elif arg.isFunction():
        assert 0

    return None


def peek_argument(ctx, f, arg):
    if f in __prototypes:
        proto = __prototypes[f]
        i = 0
        if arg != -1:
            for a in proto.getArguments():
                if (isinstance(arg, str) and a.getName() == arg) or (isinstance(arg, int) and arg == i):
                    return __peek_argument(ctx, a, ctx.abi.argument(i))
                i += 1
        else:
            return __peek_argument(ctx, proto.getReturnType(), ctx.abi.returnval())

        return InvalidArgument("Invalid argument '%s' for '%s'" % (str(arg), f))
    else:
        return MissingPrototype("Missing prototype for '%s'" % (f))


def poke_argument(ctx, func, arg, value):
    assert 0

def init(path = ["/usr/include"], ptrsize = 4):
    global __includepath, __parser_proxy, __ptr_size
    __parser_proxy = xmlrpclib.ServerProxy("http://localhost:45352/", allow_none = True)
    __includepath = path
    __ptr_size = ptrsize
