import idaapi
import idc
import idautils
import os
import inspect

global BinaryName
BinaryName = None

ICON_SEARCH = "search"
ICON_SEARCHMULTI = "searchs"
ICON_INDEX = "upload"
ICON_INDEXS = "uploads"
ICON_CONN = "setting-cnn"
ICON_SETT = "setting"


def GetCurrentFunction():
    func = idaapi.get_func(idc.ScreenEA())
    if not func:
        return 0
    else:
        return func

def IsLibFunc(func):
    flags = func.flags
    if (flags & 4) != 0:
        return True
    else:
        return False


def getLibIndex(ofuncs):
    funcs = []
    for ind,func in enumerate(ofuncs):
        if IsLibFunc(func):
            funcs.append(ind)
    return funcs

def getNotLibIndex(ofuncs):
    funcs = []
    for ind, func in enumerate(ofuncs):
        if not IsLibFunc(func):
            funcs.append(ind)
    return funcs

def GetFunction(startEA):
    func = idaapi.get_func(startEA)
    if not func:
        return 0
    else:
        return func

def GetContentStr(func):
    fcode = ''
    funcfc = idaapi.FlowChart(func)
    for bblock in funcfc:
        fcode += 'loc_' + hex(bblock.startEA).replace('0x', '').replace('L', ':') + '\r\n'
        for head in idautils.Heads(bblock.startEA, bblock.endEA):
            fcode += '%s \r\n' % (unicode(idc.GetDisasm(head), errors='replace'))
    return fcode


def GetBinaryName():
    global BinaryName
    if BinaryName is None:
        BinaryName = idaapi.get_input_file_path()
    return BinaryName


def SetBinaryName(name):
    global BinaryName
    BinaryName = name

def GetFuncInputSurrogate(func, binaryName):
    data = dict()
    data['name'] = binaryName
    data['functions'] = list()

    function_ea = func.startEA
    f_name = GetFunctionName(func)
    function = dict()
    data['functions'].append(function)
    function['name'] = f_name
    function['id'] = function_ea
    # ignore call-graph at this moment
    function['call'] = list()
    function['sea'] = function_ea
    function['see'] = idc.FindFuncEnd(function_ea)
    function['blocks'] = list()
    # basic bloc content
    for bblock in idaapi.FlowChart(idaapi.get_func(function_ea)):

        sblock = dict()
        sblock['id'] = bblock.id
        sblock['sea'] = bblock.startEA
        sblock['eea'] = bblock.endEA

        fcode = ''
        for head in idautils.Heads(bblock.startEA, bblock.endEA):
            fcode += '%s %s \r\n' % (str(head), unicode(idc.GetDisasm(head), errors='replace'))

        sblock['src'] = fcode

        # flow chart
        bcalls = list()
        for succ_block in bblock.succs():
            bcalls.append(succ_block.id)
        sblock['call'] = bcalls
        function['blocks'].append(sblock)

    return data


def GetFunctionName(func):
    if func is long:
        return idc.GetFunctionName(func)
    else:
        return idc.GetFunctionName(func.startEA)


def GetFunctions():
    return idautils.Functions()


def GetFunctionLength(func):
    return sum(1 for _ in idautils.FuncItems(func.startEA))

def loadIcon(name):
    scriptPath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    return idaapi.load_custom_icon(
        scriptPath + "/imgs/" + name + ".png"
    )

