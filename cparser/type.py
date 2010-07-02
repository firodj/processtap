"""
Library function prototypes
===========================

The class Function is used to abstract the prototype of a library function.

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
"""

def isRecursiveDefinition(ss):
    dd = ss
    while dd.getParent() is not None:
        if ss.getName() != "" and dd.getParent().getName() == ss.getName():
            return True
        dd = dd.getParent()
    return False

def printParent(s):
    while s is not None:
        s = s.getParent()

class Function:
    def __init__(self, name, return_type = None, arguments = None, attribute = None):
        self.__name = name
        if return_type == None:
            self.__return_type = VoidType()
        else:
            self.__return_type = return_type

        if arguments == None:
            self.__arguments = []
        else:
            for i in len(arguments):
                a = arguments[i]
                if a.getName() == "":
                    arguments[i].setName("arg%d" % i)

            self.__arguments = arguments

        self.__attribute = attribute

    def __str__(self):
        rt = ""
        if self.__return_type:
            rt = " -> " + str(self.__return_type)
        args = ""
        for a in self.__arguments:
            if args != "":
                args += ", "
            args += "%s %s" % (a.getName(), str(a))
        attr = ""
        if self.__attribute:
            attr += "[%s]" % self.__attribute
        
        return "%s(%s)%s%s" % (self.__name, args, rt, attr)


    def getArguments(self):
        return self.__arguments

    def getReturnType(self):
        return self.__return_type

    def setReturnType(self, rt):
        self.__return_type = rt

    def getAttribute(self):
        return self.__attribute

    def addArgument(self, arg):
        if not arg.getName():
            arg.setName("arg%d" % len(self.__arguments))
        self.__arguments.append(arg)

    def getName(self):
        return self.__name

class Type:
    def __init__(self, name, size, parent):
        self.__size = size
        self.__parent = parent
        if name == None or name == "":
            self.__name = ""
        else:
            name = name.strip("__").strip("_")
            self.__name = name

    def __str__(self):
        abstract()

    def isInt(self):
        return False

    def isFloat(self):
        return False

    def isChar(self):
        return False

    def isPtr(self):
        return False

    def isStruct(self):
        return False

    def isUnion(self):
        return False

    def isUnknown(self):
        return False

    def isVoid(self):
        return False

    def isArray(self):
        return False

    def isBaseType(self):
        return True

    def isString(self):
        return False

    def isFunction(self):
        return False

    def isEnum(self):
        return False

    def isString(self):
        return False
    
    def isFuncPtr(self):
        return False

    def isEllipsis(self):
        return False

    def getSize(self):
        return self.__size

    def setSize(self, s):
        self.__size = s

    def getParent(self):
        return self.__parent

    def setParent(self, parent):
        self.__parent = parent

    def setName(self, name):
        self.__name = name

    def getName(self):
        if self.__name is not None:
            return self.__name
        else:
            return ""

    def getName2(self):
        if self.__name is not None:
            return " " + self.__name
        else:
            return ""

 
class IntType(Type):
    def __init__(self, name = None, size = 4, signed = True, parent = None):
        self.__signed = signed
        Type.__init__(self, name, size, parent)

    def __str__(self):
        if self.__signed:
            # return "Int%d%s" % (self.getSize() * 8, self.getName2())
            return "Int%d" % (self.getSize() * 8)
        else:
            # return "Uint%d%s" % (self.getSize() * 8, self.getName2())
            return "UInt%d" % (self.getSize() * 8)

    def isInt(self):
        return True

    def isSigned(self):
        return self.__signed


class FloatType(Type):
    def __init__(self, name = None, size = 4, parent = None):
        Type.__init__(self, name, size, parent)

    def __str__(self):
        # return "Float%s" % self.getName2()
        return "Float"

    def isFloat(self):
        return True


class CharType(Type):
    def __init__(self, name = None, size = 1, signed = True, parent = None):
        Type.__init__(self, name, size, parent)
        self.__signed = signed

    def __str__(self):
        if self.__signed:
            # return "Char%s" % self.getName2()
            return "Char"
        else:
            # return "Uchar%s" % self.getName2()
            return "UChar"

    def isChar(self):
        return True

    def isSigned(self):
        return self.__signed


class PtrType(Type):
    def __init__(self, name = None, size = 4, parent = None):
        Type.__init__(self, name, size, parent)
        self.__member = None

    def __str__(self):
        # return "Ptr(%s)%s" % (str(self.__member), self.getName2())
        return "Ptr(%s)" % (str(self.__member))

    def isPtr(self):
        return True

    def getMember(self):
        return self.__member

    def addMember(self, m):
        self.__member = m

    def isString(self):
        return self.__member.isChar()

    def isFuncPtr(self):
        return self.__member.isFunction()

class StructType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)
        self.__members = []
        self.__members_name = {}

    def __str__(self):
#         p = self
#         loop = False
#         while p.getParent() is not None:
#             if p.getParent().getName() == self.getName2():
#                 loop = True
#                 break
#             p = p.getParent()
        
        if not isRecursiveDefinition(self):
            r = ""
            for s in self.__members:
                if r != "":
                    r += ", "
                    
                r += "%s %s" % (s.getName(), str(s))
        
            # return "Struct(%s)%s" % (r, self.getName2())
            return "Struct(%s)" % (r)
        else:
            # return "Struct(...)%s" % (self.getName2())
            return "Struct(...)"

    def isStruct(self):
        return True

    def isBaseType(self):
        return False

    def getMembers(self):
        return self.__members

    def addMember(self, m):
        self.__members.append(m)
        self.setSize(self.getSize() + m.getSize())

    def setMemberName(self, m, n):
        self.__members_name[m] = n

    def getMemberName(self, m):
        return self.__members_name[m]


class UnionType(Type):
    def __init__(self, name = None, size = 4, parent = None):
        Type.__init__(self, name, size, parent)
        self.__members = []
        self.__size = 0    
        self.__members_name = {}
        
    def __str__(self):
        if not isRecursiveDefinition(self):
            r = ""
            for s in self.__members:
                if r != "":
                    r += ", "
                r += "%s %s" % (s.getName(), str(s))
        
            # return "Union(%s)%s" % (r, self.getName2())
            return "Union(%s)" % (r)
        else:
            # return "Union(...)%s" % (self.getName2())
            return "Union(...)"

#         r = ""
#         for s in self.__members:
#             if r != "":
#                 r += ", "
#             r += str(s)
        
#         return "Union(%s)%s" % (r, self.getName2())

    def isUnion(self):
        return True

    def isBaseType(self):
        return False

    def getMembers(self):
        return self.__members

    def addMember(self, m):
        self.__members.append(m)
        if m.getSize() > self.getSize():
            self.setSize(m.getSize())

    def setMemberName(self, m, n):
        self.__members_name[m] = n

    def getMemberName(self, m):
        return self.__members_name[m]
    
class UnknownType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)

    def __str__(self):
        # return "Unknown" % self.getName2()
        return "Unknown"

    def isUnknown(self):
        return True

    
class VoidType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)

    def __str__(self):
        # return "Void%s" % self.getName2()
        return "Void"

    def isVoid(self):
        return True

class ArrayType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)
        self.__length = 0
        self.__member = None

    def __str__(self):
        # return "Array(%s, %d)%s" % (self.__member, self.__length, self.getName2())
        return "Array(%s, %d)" % (self.__member, self.__length)

    def isArray(self):
        return True

    def isBaseType(self):
        return False

    def getMember(self):
        return self.__member

    def addMember(self, m):
        self.__member = m

    def getLength(self):
        return self.__length

    def setLength(self, l):
        self.__length = l
        self.setSize(l * self.getMember().getSize())


class FunctionType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)

    def isFunction(self):
        return True

    def getMember(self):
        return self.__func

    def addMember(self, f):
        self.__func = f

    def __str__(self):
        return str(self.__func)

    def isBaseType(self):
        return False

class EnumType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)
        self.__map = {}

    def __str__(self):
        r = "Enum("
        for k in self.__map:
            if r != "Enum(":
                r += ", "
            r += "%s : %d" % (self.__map[k], k)
        return r + ")"

    def isEnum(self):
        return True

    def addMember(self, k, v):
        self.__map[v] = k

    def getMember(self, mem = None):
        if mem is not None:
            return self.__map[mem]
        else:
            return self.__map

    def isBaseType(self):
        return False

class EllipsisType(Type):
    def __init__(self, name = None, size = 0, parent = None):
        Type.__init__(self, name, size, parent)

    def __str__(self):
        return "..."

    def isEllipsis(self):
        return True
