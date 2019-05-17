import gdb

class FuncPrinter(object):
    def __init__(self, val, ptr):
        self.val, self.ptr = val, ptr

    def to_string(self):
        return self.ptr + "plyF(" + self.val["name"].string() + ")"

    def display_hint(self):
        return "func"

def nodeStr(n, stop=False):
    out = ""

    if str(n["ntype"]) == "N_EXPR":
        out += n["expr"]["func"].string()

        if not stop:
            arg = n["expr"]["args"]
            while arg != 0:
                out += " " + nodeStr(arg, stop=True)
                arg = arg["next"]
    elif str(n["ntype"]) == "N_STRING":
        out += "\"" + n["string"]["data"].string() + "\""
    elif str(n["ntype"]) == "N_NUM":
        if n["num"]["unsignd"]:
            out += "<" + str(n["num"]["u64"]) + ">"
        else:
            out += "<" + str(n["num"]["s64"]) + ">"
    else:
        out += "???"

    return out
    

class NodePrinter(object):
    def __init__(self, val, ptr):
        self.val, self.ptr = val, ptr

    def to_string(self):
        return self.ptr + "plyN(" + nodeStr(self.val) + ")"

    def display_hint(self):
        return "node"

class SymPrinter(object):
    def __init__(self, val, ptr):
        self.val, self.ptr = val, ptr

    def to_string(self):
        if self.val["name"]:
            name = self.val["name"].string()
        else:
            name = "<anonymous>"

        return self.ptr + "plyS(" + name + ")"

    def display_hint(self):
        return "sym"


ttypeStrs = {
    "T_VOID": lambda t: "void",
    "T_TYPEDEF": lambda t: t["tdef"]["name"].string(),
    "T_SCALAR": lambda t: t["scalar"]["name"].string(),
    "T_POINTER": lambda t: "*" + typeStr(t["ptr"]["type"].dereference()),
    "T_ARRAY": lambda t: typeStr(t["array"]["type"].dereference()) +
        "[" + str(t["array"]["len"]) + "]",
    "T_STRUCT": lambda t: "struct " + t["struct"]["name"].string(),
    "T_FUNC": lambda t: typeStr(t["func"]["type"].dereference()) + " (*)()",
    "T_MAP": lambda t: typeStr(t["func"]["vtype"].dereference()) +
        "{" + typeStr(t["func"]["vtype"].dereference()) + "}",
}

def typeStr(t):
    ttype = str(t["ttype"])

    if ttype in ttypeStrs:
        return ttypeStrs[ttype](t)

    return "???"

class TypePrinter(object):
    def __init__(self, val, ptr):
        self.val, self.ptr = val, ptr

    def to_string(self):
        return self.ptr + "plyT(" + typeStr(self.val) + ")"

    def display_hint(self):
        return "type"

plyPrinters = {
    "func": FuncPrinter,
    "node": NodePrinter,
    "sym" : SymPrinter,
    "type": TypePrinter,
}

def plyPrinterGet(v):
    ptr = ""
    if v.type.code == gdb.TYPE_CODE_PTR:
        try:
            v = v.dereference()
        except gdb.error:
            return None

        ptr = "*"

    if v.type.code != gdb.TYPE_CODE_STRUCT:
        return None

    if v.type.tag in plyPrinters:
        return plyPrinters[v.type.tag](v, ptr)

    return None

gdb.pretty_printers.append(plyPrinterGet)
