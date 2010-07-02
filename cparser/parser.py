"""
C/C++ header parser
===================

Parse a .h file and translate function definition into an intermediate form
suitable for static analysis.


Copyright notice
================

Copyright (C) 2006-2010
    Lorenzo Martignoni <martignlo@gmail.com>
    Roberto Paleari    <roberto.paleari@gmail.com>

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.  

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51
Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


Todo
====

* Handle recursive data structure such as _IO_markers (libio.h)
"""

import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=UserWarning)

from pygccxml import parser
from pygccxml import declarations

from type import *
import sys
import os
import pickle

indent = 0
ptr_size = 4

# setDebugLevel(DEBUG_PARSER)

DEBUG_PARSER = 0

def debug(lvl, fmt, *args):
    return

# map between types and allocators
typeAssociation = {
    declarations.cpptypes.array_t : lambda x,y,z : compoundType(x, y, z),    
    declarations.cpptypes.bool_t : lambda x,y,z : CharType(name = y, parent = z),
    declarations.cpptypes.char_t : lambda x,y,z : CharType(name = y, parent = z),
    declarations.cpptypes.signed_char_t : lambda x,y,z : CharType(name = y, parent = z),
    declarations.cpptypes.complex_double_t : lambda x,y,z : FloatType(name = y, parent = z),
    declarations.cpptypes.complex_float_t : lambda x,y,z : FloatType(name = y, parent = z),
    declarations.cpptypes.complex_long_double_t : lambda x,y,z : FloatType(name = y, parent = z),
    # Compound
    declarations.cpptypes.const_t : lambda x,y,z : compoundType(x, y, z),
    # Declarated by the user, Compound
    declarations.cpptypes.declarated_t : lambda x,y,z : declaratedType(x, y, z),
    declarations.cpptypes.double_t : lambda x,y,z : FloatType(name = y, parent = z),
    declarations.cpptypes.float_t : lambda x,y,z : FloatType(name = y, parent = z),
    declarations.cpptypes.int_t : lambda x,y,z : IntType(name = y, parent = z),
    declarations.cpptypes.long_double_t : lambda x,y,z : IntType(name = y, parent = z),
    declarations.cpptypes.long_int_t : lambda x,y,z : IntType(name = y, parent = z),
    declarations.cpptypes.long_long_int_t : lambda x,y,z : IntType(name = y, size = 8, parent = z),
    declarations.cpptypes.long_long_unsigned_int_t : lambda x,y,z : IntType(name = y, size = 8, signed = False, parent = z),
    declarations.cpptypes.long_unsigned_int_t : lambda x,y,z : IntType(name = y, signed = False, parent = z),
    # Compound
    declarations.cpptypes.member_variable_type_t : lambda x,y,z : compoundType(x, y, z),
    # Compound
    declarations.cpptypes.pointer_t : lambda x,y,z : compoundType(x, y, z),
    # Compound
    declarations.cpptypes.reference_t : lambda x,y,z : compoundType(x, y, z),
    declarations.cpptypes.short_int_t : lambda x,y,z : IntType(name = y, size = 2, parent = z),
    declarations.cpptypes.short_unsigned_int_t : lambda x,y,z : IntType(name = y, size = 2, signed = False, parent = z),
    declarations.cpptypes.unknown_t : lambda x,y,z : UnknownType(x, y, z),
    declarations.cpptypes.unsigned_char_t : lambda x,y,z : CharType(name = y, signed = False, parent = z),
    declarations.cpptypes.unsigned_int_t : lambda x,y,z : IntType(name = y, signed = False, parent = z),
    declarations.cpptypes.void_t : lambda x,y,z : VoidType(name = y, parent = z),
    # Compound
    declarations.cpptypes.volatile_t : lambda x,y,z : compoundType(x, y, z),
    # Broken
    declarations.cpptypes.wchar_t : lambda x,y,z : IntType(name = y, parent = z),
    declarations.cpptypes.free_function_type_t : lambda x,y,z : funcType(x, y, z),
    declarations.cpptypes.restrict_t : lambda x,y,z : compoundType(x, y, z),
    declarations.cpptypes.ellipsis_t : lambda x,y,z : EllipsisType(name = y, parent = z),
}

def makeindent():
    global indent
    r = ""
    for i in range(indent):
        r += "  "
    return r


def funcType(ft, name = None, parent = None):
    f = Function("NONAME")
    for a in ft.arguments_types:
        assert type(a) in typeAssociation, a.declaration.class_type
        f.addArgument(typeAssociation[type(a)](a, None, parent))

    assert type(ft.return_type) in typeAssociation, ft.declaration.class_type
    f.return_type = typeAssociation[type(ft.return_type)](ft.return_type, None, parent)

    nf = FunctionType(name = f.getName())
    nf.addMember(f)

    return nf


def declaratedType(dt, name = None, parent = None):
    global indent 
    indent += 1

    if type(dt.declaration) == declarations.class_declaration.class_t:
        debug(DEBUG_PARSER, "%sParsing declatared type (%s) %s - %s *\n", makeindent(), dt.declaration.class_type, dt, "") #parent)
    else:
        debug(DEBUG_PARSER, "%sParsing declatared type (%s) %s - %s \n", makeindent(), "", dt, "") #parent)
        

    # typedef: return the associated type directly
    if type(dt.declaration) == declarations.typedef.typedef_t:
        #debug(True, "%s%s is a typedef, parsing %s (%s)\n", makeindent(), dt, dt.declaration.type, type(dt.declaration.type))
        r = typeAssociation[type(dt.declaration.type)](dt.declaration.type, name, parent)
        indent -= 1
        return r

    if type(dt.declaration) == declarations.class_declaration.class_t:
        if dt.declaration.class_type == "struct":
            debug(DEBUG_PARSER, "%s%s (%s) is a struct, parsing members\n", makeindent(), dt, dt.declaration.name)
            
            ss = StructType(name = dt.declaration.name, parent = parent)
            rr = ss
            loop = False
            while rr.getParent() is not None:
                if rr.getParent().getName() == ss.getName():
                    loop = True
                    break
                rr = rr.getParent()
            if not loop:
                for p in dt.declaration.public_members:
                    if type(p) == declarations.variable.variable_t:
                        r = typeAssociation[type(p.type)](p.type, p.name, ss)
                        ss.addMember(r)
                        ss.setMemberName(r, p.name)
            else:
                debug(DEBUG_PARSER, "%sloop detected\n" % makeindent())
                ss.addMember(ss)

            indent -= 1
            return ss
        elif dt.declaration.class_type == "union":
            debug(DEBUG_PARSER, "%s%s (%s) is a union, parsing members\n", makeindent(), dt, dt.declaration.name)
            uu = UnionType(name = dt.declaration.name, parent = parent)
            rr = uu
            if not isRecursiveDefinition(uu):
                for p in dt.declaration.public_members:
                    if type(p) == declarations.variable.variable_t:
                        r = typeAssociation[type(p.type)](p.type, p.name, uu)
                        uu.addMember(r)
                        uu.setMemberName(r, p.name)
            else:
                uu.addMember(uu)
            indent -= 1

            return uu
        

    if type(dt.declaration) == declarations.enumeration.enumeration_t:
        en = EnumType(name = dt.declaration.name)
        name2value = dt.declaration.get_name2value_dict()
        for k in name2value:
            en.addMember(k, name2value[k])
        return en

    if type(dt.declaration) == declarations.class_declaration.class_declaration_t:
        return None

    assert None, "%s %s" % (str(dt), type(dt.declaration))


def compoundType(ct, name = None, parent = None):
    if type(ct) == declarations.cpptypes.pointer_t:
        r = PtrType(name = name, parent = parent, size = ptr_size)
        r.addMember(typeAssociation[type(ct.base)](ct.base, None, r))
    
    elif type(ct) == declarations.cpptypes.volatile_t:
        r = typeAssociation[type(ct.base)](ct.base, name, parent)

    elif type(ct) == declarations.cpptypes.restrict_t:
        r = typeAssociation[type(ct.base)](ct.base, name, parent)

    elif type(ct) == declarations.cpptypes.const_t:
        r = typeAssociation[type(ct.base)](ct.base, name, parent)

    elif type(ct) == declarations.cpptypes.array_t:
        r = ArrayType(name = name, parent = parent)
        r.addMember(typeAssociation[type(ct.base)](ct.base, None, r))
        r.setLength(ct.size)

    else:
        assert None, ct


    return r


def parseFunction(f):
    debug(DEBUG_PARSER, "Parsing function: %s\n", f)
    ft = Function(f.name)
    
    ff = ""

    for a in f.arguments:
	if ff != "":
	    ff += ", "
	ff += str(a.type)
        debug(DEBUG_PARSER, "   Parsing argument: %s (%s)\n\n", a, type(a.type))
        if type(a.type) in typeAssociation:
            ft.addArgument(typeAssociation[type(a.type)](a.type, a.name, None))
        else:
	    print type(a.type)
            assert None, a.declaration.class_type
            # ft.addArgument(None)
            
    debug(DEBUG_PARSER, "   Parsing return value: %s (%s)\n", f.return_type, type(f.return_type))
    if type(f.return_type) in typeAssociation:
        ft.setReturnType(typeAssociation[type(f.return_type)](f.return_type, None, None))
    else:
        assert None, a.declaration.class_type
        # ft.return_type = None
        
    # ff = str(f.return_type)  + " " + f.name + "(" + ff + ")"
    # print ff

    return ft

def parseIncludeFile(f, define = [], includes = [], ps = 4):
    global ptr_size
    ptr_size = ps

    gccxmlexe = os.getenv("GCCXML", "gccxml")
    config = parser.config_t(gccxml_path = gccxmlexe, define_symbols = define, include_paths = includes)

    functions = {}

    if isinstance(f, list):
        global_ns = parser.parse(f, config)
    else:
        global_ns = parser.parse([f], config)
        
    all_decls = declarations.make_flatten(global_ns)

    all_functions = filter(lambda decl: isinstance(decl, declarations.free_function_t), \
                           all_decls)

    for f in all_functions:   
        if not f.name.startswith("__"):
            # if f.name == "ReadFileEx":
            functions[f.name] = parseFunction(f)
        
    return functions

def parseIncludeFile_xmlrpc(f, define = [], includes = [], ptrsize = 4):
    r = parseIncludeFile(f, define, includes, ptrsize)
    return pickle.dumps(r)

def xmlrpc(p = 45352):
    from SimpleXMLRPCServer import SimpleXMLRPCServer
    server = SimpleXMLRPCServer(("localhost", p), allow_none = True, logRequests = False)
    server.register_introspection_functions()
    server.register_function(parseIncludeFile_xmlrpc, "parse")
    print "[*] Started parser (listening on %d)" % p
    server.serve_forever()

if __name__ == "__main__":
    ff = parseIncludeFile(sys.argv[1:], includes = ["/usr/include"])
    for f in ff.itervalues():
        print f
