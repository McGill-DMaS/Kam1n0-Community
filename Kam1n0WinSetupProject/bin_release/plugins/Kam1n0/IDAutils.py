# *******************************************************************************
#  * Copyright 2017 McGill University All rights reserved.
#  *
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  *     http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
#  *******************************************************************************/

import idaapi
import _idaapi
import idc
import idautils
import os
import inspect
import binascii
import struct

ICON_SEARCH = "search"
ICON_SEARCHMULTI = "searchs"
ICON_INDEX = "upload"
ICON_INDEXS = "uploads"
ICON_CONN = "setting-cnn"
ICON_SETT = "setting"
ICON_COMP = "components"
ICON_FRAG = "page_edit"


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
    return  idaapi.get_input_file_path()

def GetFuncInputSurrogateBatch(funcs, binaryName):
    data = dict()
    data['name'] = GetBinaryName()
    data['architecture'] = {}
    info = idaapi.get_inf_structure()
    data['architecture']['type'] = info.procName.lower();
    data['architecture']['size'] = "b32"
    if info.is_32bit():
        data['architecture']['size'] = "b32" 
    if info.is_64bit(): 
        data['architecture']['size'] = "b64";
    data['architecture']['endian'] = "be" if _idaapi.cvar.inf.mf else "le";
    if info.procName.lower().startswith('mips'):
        data['architecture']['type'] = 'mips'
		
    data['name'] = binaryName
    data['functions'] = list()
    for func in funcs:
        data['functions'].append(GetFuncInputSurrogate(func))
    return data
	
def GetBinarySurrogate():
    data = dict()
    data['name'] = GetBinaryName()
    data['architecture'] = {}
    info = idaapi.get_inf_structure()
    data['architecture']['type'] = info.procName.lower();
    data['architecture']['size'] = "b32"
    if info.is_32bit():
        data['architecture']['size'] = "b32" 
    if info.is_64bit(): 
        data['architecture']['size'] = "b64";
    data['architecture']['endian'] = "be" if _idaapi.cvar.inf.mf else "le";
    if info.procName.lower().startswith('mips'):
        data['architecture']['type'] = 'mips'
    
    
    data['functions'] = list()
    for func in GetFunctions():
        data['functions'].append(GetFuncInputSurrogate(GetFunction(func)))
    return data

def GetSelectedCode(startEA, endEA):
    fcode = ""
    for head in idautils.Heads(startEA, endEA):
        fcode +=  ' %s \r\n' % (unicode(idc.GetDisasm(head), errors='replace'))
    return fcode

def GetFuncInputSurrogate(func):

    info = idaapi.get_inf_structure();
    arch = info.procName.lower();

    function_ea = func.startEA
    f_name = GetFunctionName(func)
    function = dict()
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
        if(arch == 'arm'):
               sblock['sea'] += idc.GetReg(bblock.startEA, 'T')
        sblock['eea'] = bblock.endEA
        sblock['name'] = 'loc_' + format(bblock.startEA, 'x').upper()
        dat = {}
        sblock['dat'] = dat
        s = idc.GetManyBytes(bblock.startEA, bblock.endEA - bblock.startEA)
        if(s != None):
            sblock['bytes'] = "".join("{:02x}".format(ord(c)) for c in s)

        tlines = []
        for head in idautils.Heads(bblock.startEA, bblock.endEA):
            tline = []
            tline.append(str(hex(head)).rstrip("L").upper().replace("0X", "0x"))
            mnem = idc.GetMnem(head)
            if mnem == "":
                continue
            tline.append(mnem)
            for i in range(5):
                opd = idc.GetOpnd(head, i)
                if opd == "":
                      continue
                tline.append(opd)
            tlines.append(tline)

            refdata = list(idautils.DataRefsFrom(head))
            if(len(refdata)>0):
                for ref in refdata:
                    dat[head] = binascii.hexlify(struct.pack("<Q", idc.Qword(ref)))

        sblock['src'] = tlines

        # flow chart
        bcalls = list()
        for succ_block in bblock.succs():
            bcalls.append(succ_block.id)
        sblock['call'] = bcalls
        function['blocks'].append(sblock)

    return function


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

def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]
