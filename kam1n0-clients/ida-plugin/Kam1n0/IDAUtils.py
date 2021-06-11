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

import binascii
import inspect
import os
import struct
import sys
from collections import namedtuple, defaultdict
import operator

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import idaapi
import idautils
import idc
from ida_name import calc_gtn_flags

ALL_ICONS = {'ICON_SEARCH': "search",
             'ICON_SEARCH_MULTIPLE': "search_multiple",
             'ICON_INDEX': "upload",
             'ICON_INDEX_MULTIPLE': "upload_multiple",
             'ICON_CONN': "setting-cnn",
             'ICON_SETT': "setting",
             'ICON_COMP': "components",
             'ICON_FRAG': "page_edit"}

ICONS = namedtuple("Icons", list(ALL_ICONS.keys()))


def is_hexrays_v7():
    return idaapi.IDA_SDK_VERSION >= 700


def _is_lib_func(func):
    flags = func.flags
    if (flags & 4) != 0:
        return True
    else:
        return False


def _load_icon(name):
    script_path = os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe())))
    return idaapi.load_custom_icon(
        script_path + "/img/" + name + ".png"
    )


def execute(cmd=''):
    if isinstance(cmd, bytes):
        cmd = cmd.decode('utf-8')
    cmd = cmd.replace('<br>', '\r\n')
    print(cmd)
    func = cmd[0:cmd.index('(')]
    if func in globals():
        exec(cmd)


def sync_wrap(func):
    def wrapper(*args, **kwargs):
        rvs = []

        def run():
            rv = func(*args, **kwargs)
            rvs.append(rv)

        flag = idaapi.MFF_WRITE
        idaapi.execute_sync(run, flag)
        if len(rvs) > 0:
            return rvs[0]
        else:
            return
    return wrapper


def set_cmt(ea, msg, rp):
    sync_wrap(idaapi.set_cmt)(ea, msg, rp)


def jumpto(ea):
    if is_hexrays_v7():
        sync_wrap(idc.jumpto)(ea)
    else:
        idaapi.jumpto(ea)


def load_icons_as_dict():
    icons = ICONS(
        **{key: _load_icon(ALL_ICONS[key]) for key in list(ALL_ICONS.keys())})
    return icons


def get_lib_ida_func_indexes(funcs):
    return [ind for ind, func in enumerate(funcs) if _is_lib_func(func)]


def get_not_lib_ida_func_indexes(funcs):
    return [ind for ind, func in enumerate(funcs) if not _is_lib_func(func)]


def get_ida_func(ea=None):
    if ea is None:
        func = idaapi.get_func(idc.get_screen_ea())
        if not func:
            return None
        else:
            return func
    func = idaapi.get_func(ea)
    if not func:
        return None
    else:
        return func


def get_all_ida_funcs():
    return [get_ida_func(ea) for ea in idautils.Functions()]


def _get_bin_name():
    return idaapi.get_input_file_path()


def _get_arch():
    arch = dict()
    info = idaapi.get_inf_structure()
    arch['type'] = info.procName.lower()
    arch['size'] = "b32"
    if info.is_32bit():
        arch['size'] = "b32"
    if info.is_64bit():
        arch['size'] = "b64"
    if idaapi.cvar.inf.version >= 700:
        arch['endian'] = "be" if idaapi.cvar.inf.is_be() else "le"
    else:
        arch['endian'] = "be" if idaapi.cvar.inf.mf else "le"
    if info.procName.lower().startswith('mips'):
        arch['type'] = 'mips'
    if info.procName.lower().startswith('68330'):
        arch['type'] = 'mc68'
    return arch


def _get_api(sea):
    calls = 0
    api = []
    flags = idc.get_func_attr(sea, idc.FUNCATTR_FLAGS)
    # ignore library functions
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:
        return calls, api
    # list of addresses
    addresses = list(idautils.FuncItems(sea))
    for instr in addresses:
        tmp_api_address = ""
        if idaapi.is_call_insn(instr):
            for xref in idautils.XrefsFrom(instr, idaapi.XREF_FAR):
                if xref.to is None:
                    calls += 1
                    continue
                tmp_api_address = xref.to
                break
            if tmp_api_address == "":
                calls += 1
                continue
            api_flags = idc.get_func_attr(tmp_api_address, idc.FUNCATTR_FLAGS)
            if api_flags & idaapi.FUNC_LIB is True \
                    or api_flags & idaapi.FUNC_THUNK:
                tmp_api_name = idc.get_name(
                    tmp_api_address, ida_name.GN_VISIBLE | calc_gtn_flags(0, tmp_api_address))
                if tmp_api_name:
                    api.append(tmp_api_name)
            else:
                calls += 1
    return calls, api


def _get_ida_func_surrogate(func, arch):
    func_surrogate = dict()
    func_surrogate['name'] = idc.get_func_name(func.start_ea)
    func_surrogate['id'] = func.start_ea
    # ignore call-graph at this moment
    func_surrogate['call'] = list()
    func_surrogate['sea'] = func.start_ea
    func_surrogate['see'] = idc.find_func_end(func.start_ea)
    # api is optional
    func_surrogate['api'] = _get_api(func.start_ea)[1]
    func_surrogate['blocks'] = list()

    # comments
    func_surrogate['comments'] = []
    func_surrogate['comments'].extend(get_comments(func.start_ea))

    for bb in idaapi.FlowChart(idaapi.get_func(func.start_ea)):

        block = dict()
        block['id'] = bb.id
        block['sea'] = bb.start_ea
        if arch is 'arm':
            # for arm; the last bit indicates thumb mode.
            block['sea'] += idc.GetReg(bb.start_ea, 'T')
        block['eea'] = bb.end_ea
        block['name'] = 'loc_' + format(bb.start_ea, 'x').upper()
        dat = {}
        block['dat'] = dat
        s = idc.get_bytes(bb.start_ea, bb.end_ea - bb.start_ea)
        if s is not None:
            block['bytes'] = "".join("{:02x}".format(c) for c in s)

        instructions = list()
        oprTypes = list()
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            func_surrogate['comments'].extend(get_comments(head))
            ins = list()
            oprType = list()
            ins.append(
                str(hex(head)).rstrip("L").upper().replace("0X", "0x"))
            opr = idc.print_insn_mnem(head)
            if opr == "":
                continue
            ins.append(opr)
            for i in range(5):
                opd = idc.print_operand(head, i)
                tp = idc.get_operand_type(head, i)
                if opd == "" or tp is None:
                    continue
                ins.append(opd)
                oprType.append(tp)
            instructions.append(ins)
            oprTypes.append(oprType)

            refs = list(idautils.DataRefsFrom(head))
            for ref in refs:
                dat[head] = binascii.hexlify(
                    struct.pack("<Q", idc.get_qword(ref))).decode('utf-8')

        block['src'] = instructions
        block['oprTypes'] = oprTypes

        # flow chart
        block_calls = list()
        for success_block in bb.succs():
            block_calls.append(success_block.id)
        block['call'] = block_calls
        func_surrogate['blocks'].append(block)
    return func_surrogate


def get_as_single_surrogate(funcs=None):
    data = dict()
    data['name'] = _get_bin_name()
    data['architecture'] = _get_arch()
    data['md5'] = idautils.GetInputFileMD5().hex().upper()

    if funcs is None:
        funcs = get_all_ida_funcs()
    if not isinstance(funcs, list):
        funcs = [funcs]
    data['functions'] = [
        _get_ida_func_surrogate(func, data['architecture']['type']) for func
        in funcs]
    return data


def get_as_multiple_surrogate(funcs=None):
    if funcs is None:
        funcs = get_all_ida_funcs()
    if not isinstance(funcs, list):
        funcs = [funcs]
    return [get_as_single_surrogate(func) for func in funcs]


def get_selected_code(sea, eea):
    code = [idc.GetDisasm(head) for head in
            idautils.Heads(sea, eea)]
    surrogate = get_as_single_surrogate(get_ida_func(sea))
    block_number = 0
    blocks = []
    block_id_map = {}
    for block in surrogate['functions'][0]['blocks']:
        if block['sea'] >= eea or block['eea'] <= sea:
            continue
        else:
            block_id_map[block['id']] = block_number
            block['id'] = block_number
            block_number += 1
            blocks.append(block)
    for block in blocks:
        block['call'] = [block_id_map[c]
                         for c in block['call'] if c in block_id_map]
    surrogate['functions'][0]['blocks'] = blocks

    if surrogate['functions'][0]['see'] < eea:
        endsea = surrogate['functions'][0]['see'] + 1
        previous_endsea = surrogate['functions'][0]['see']
        while endsea < eea:
            new_surrogate = get_as_single_surrogate(get_ida_func(endsea))
            if new_surrogate['functions'][0]['see'] == previous_endsea:
                endsea += 1
                continue
            block_id_map = {}
            blocks = []
            for block in new_surrogate['functions'][0]['blocks']:
                if block['sea'] > eea or block['eea'] < sea:
                    continue
                else:
                    block_id_map[block['id']] = block_number
                    block['id'] = block_number
                    block_number += 1
                    blocks.append(block)
            for block in blocks:
                block['call'] = [block_id_map[c]
                                 for c in block['call'] if c in block_id_map]
            surrogate['functions'][0]['blocks'].extend(blocks)
            endsea = new_surrogate['functions'][0]['see'] + 1
            previous_endsea = new_surrogate['functions'][0]['see']
    func = surrogate['functions'][0]
    func['sea'] = sea
    func['see'] = eea

    for block in func['blocks']:
        changed = False
        if block['sea'] < sea:
            block['sea'] = sea
            changed = True
        if block['eea'] > eea:
            block['eea'] = eea
            changed = True
        if changed:
            s = idc.get_bytes(block['sea'], block['eea'] - block['sea'])
            if s is not None:
                block['bytes'] = "".join("{:02x}".format(c) for c in s)
            if surrogate['architecture']['type'] is 'arm':
                # for arm; the last bit indicates thumb mode.
                block['sea'] += idc.GetReg(block['sea'], 'T')
            block['name'] = 'loc_' + format(block['sea'], 'x').upper()
            dat = {}
            #block['dat'] = dat
            instructions = list()
            oprTypes = list()
            for head in idautils.Heads(block['sea'], block['eea']):
                func['comments'].extend(get_comments(head))
                ins = list()
                oprType = list()
                ins.append(
                    str(hex(head)).rstrip("L").upper().replace("0X", "0x"))
                opr = idc.print_insn_mnem(head)
                if opr == "":
                    continue
                ins.append(opr)
                for i in range(5):
                    opd = idc.print_operand(head, i)
                    tp = idc.get_operand_type(head, i)
                    if opd == "" or tp is None:
                        continue
                    ins.append(opd)
                    oprType.append(tp)
                instructions.append(ins)
                oprTypes.append(oprType)

                refs = list(idautils.DataRefsFrom(head))
                for ref in refs:
                    dat[head] = binascii.hexlify(
                        struct.pack("<Q", idc.get_qword(ref))).decode('utf-8')
            block['src'] = instructions
            block['oprType'] = oprTypes
    return surrogate


def _iter_extra_comments(ea, start):
    end = idaapi.get_first_free_extra_cmtidx(ea, start)
    lines = [idaapi.get_extra_cmt(ea, idx) for idx in
             range(start, end)]
    lines = [line if line else '' for line in lines]
    return "\n".join(lines)


def _append_comments(ea, comments, type, text):
    if text and len(text) > 0:
        comments.append({'type': type, 'comment': text, 'offset': str(
            hex(ea)).rstrip("L").upper().replace("0X", "0x")})

# anterior comment with offset is equal to first_segment_address will be exclude


def get_comments(ea):
    first_segment_address = idc.get_segm_start(ea)

    comments = []
    _append_comments(ea, comments, 'repeatable',
                     idc.get_cmt(ea, 1))  # RptCmt(ea)
    _append_comments(ea, comments, 'regular',
                     idc.get_cmt(ea, 0))  # Comment(ea)

    anteriorComment = _iter_extra_comments(ea, idaapi.E_PREV)
    if ea != first_segment_address:
        _append_comments(ea, comments, 'anterior', anteriorComment)

    _append_comments(ea, comments, 'posterior',
                     _iter_extra_comments(ea, idaapi.E_NEXT))
    return comments


def get_range():
    '''Return the range of the selection.

    If there is no selection the range is set to start and end of the current
    function.
    To get the comments for a single line, part of the line must be selected.
    '''
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(
        None)
    if has_selection:
        return start_ea, end_ea, False
    else:
        ea = ida_kernwin.get_screen_ea()

        if ida_kernwin.get_highlight(ida_kernwin.get_current_viewer()):
            return ea, ea+1, False
        else:
            f = ida_funcs.get_func(ea)
            if f:
                return f.start_ea, f.end_ea, True
            else:
                return None, None, None


def get_comments_in_selected_range():
    """ return comments in the selected region
        - Get the range for which to copy comments
        - Get the function comments if the the start of the range is a function
        - Get every type of comments for each address in the range
        - Put the comments in the clipboard as a JSON string
    """
    cmts = defaultdict(list)
    start, end, is_func = get_range()
    cmts['is_func'] = is_func

    if start is None:
        print("PowerClipboard Error: No selection or cursor not inside a function.")
        return 0

    # Get function comments if the first address is the start of a function
    if start == idc.get_func_attr(start, idc.FUNCATTR_START):
        # 0: Regular comments, 1: Repeatable comments
        for repeatable in range(2):
            cmt = idc.get_func_cmt(start, repeatable)
            if cmt != "":
                cmts['function'].append((0, cmt, repeatable))

    for head in idautils.Heads(start, end):
        # Get regular comments, repeatable or not
        # 0: Regular comments, 1: Repeatable comments
        for repeatable in range(2):
            cmt = idc.GetCommentEx(head, repeatable)
            if cmt:
                cmts['regular'].append((head - start, cmt, repeatable))

        # Get Anterior lines
        # Skipped if the address is the beginning of the segment because
        # there's a lot of junk
        if head != idc.get_segm_attr(head, idc.SEGATTR_START):
            for i in range(ida_lines.get_first_free_extra_cmtidx(head, ida_lines.E_PREV) - ida_lines.E_PREV):
                cmt = ida_lines.get_extra_cmt(head, ida_lines.E_PREV + i)
                if cmt:
                    cmts['anterior'].append((head - start, cmt, i))

        # Get Posterior lines
        for i in range(ida_lines.get_first_free_extra_cmtidx(head, ida_lines.E_NEXT) - ida_lines.E_NEXT):
            cmt = ida_lines.get_extra_cmt(head, ida_lines.E_NEXT + i)
            if cmt:
                cmts['posterior'].append((head - start, cmt, i))
    return cmts


def ctx_in_disassembly_view(ctx):
    return ctx.form_type == ida_kernwin.BWN_DISASM


def set_comments(cmts, ignore_offset_error=False):
    """[summary] 
    Args:
        cmts ([type]): [description]
    """
    offset = operator.itemgetter(0)
    comment = operator.itemgetter(1)
    repeatable = operator.itemgetter(2)
    index = operator.itemgetter(2)

    # get starting addr:
    start = idc.get_func_attr(idc.get_screen_ea(
    ), idc.FUNCATTR_START) if cmts['is_func'] else idc.get_screen_ea()

    # Verify that all comments offsets match the beginning of an instruction.
    if not ignore_offset_error:
        for values in cmts.values():
            if isinstance(values, list):
                for cmt in values:
                    if not idc.is_head(
                            idc.get_full_flags(start + offset(cmt))):
                        return False

    # Set function comments if present
    for cmt in cmts['function']:
        ida_funcs.set_func_cmt(ida_funcs.get_func(
            start), comment(cmt), repeatable(cmt))

    # Set regular comment if present
    for cmt in cmts['regular']:
        ida_bytes.set_cmt(start + offset(cmt),
                          comment(cmt), repeatable(cmt))

    # Set anterior lines if present
    for cmt in cmts['anterior']:
        ida_lines.update_extra_cmt(
            start + offset(cmt), ida_lines.E_PREV + index(cmt), comment(cmt))

    # Set posterior lines if present
    for cmt in cmts['posterior']:
        ida_lines.update_extra_cmt(
            start + offset(cmt), ida_lines.E_NEXT + index(cmt), comment(cmt))

    return True
