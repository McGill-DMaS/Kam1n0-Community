from idautils import *
from idaapi import *
from idc import *
from collections import defaultdict
import xml.etree.cElementTree as ET

info = get_inf_structure()
registers = set(GetRegisterList())
instructions = set(GetInstructionList())
suffix_groups = set()
instructions_branching = set()
instruction_to_groups = defaultdict(set)
registers_size = defaultdict(lambda : 64 if info.is_64bit() else 32)

def size_of_operand(op):
    tbyte = 8
    dt_ldbl = 8
    n_bytes = [ 1, 2, 4, 4, 8,
            tbyte, -1, 8, 16, -1,
            -1, 6, -1, 4, 4,
            dt_ldbl, 32, 64 ]
    return n_bytes[op.dtype]

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        functionName = get_func_name(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                instr = DecodeInstruction(head)
                ins_normalized = instr.get_canon_mnem()
                ins = print_insn_mnem(head)
                suffix = ins.replace(ins_normalized, '')

                refs = list(CodeRefsFrom(head, 0))
                if len(refs) > 0:
                    instructions_branching.add(ins_normalized)
                if len(suffix) > 0:
                    suffix_groups.add(suffix)
                    instruction_to_groups[ins_normalized].add(suffix)
                    if ins in instructions:
                        instructions.remove(ins)
                for i in range(5):
                    opd = print_operand(head, i)
                    tp = get_operand_type(head, i)
                    if opd == "" or tp is None:
                        continue
                    size = size_of_operand(instr.ops[i])
                    if size > 0:
                        size = size * 8
                    if opd in registers:
                        registers_size[opd] = max(registers_size[opd], size)



root = ET.Element("Kam1n0-Architecture")
ET.SubElement(root, "processor").text = info.procName.lower()
operations = ET.SubElement(root, "operations")
operationJmps = ET.SubElement(root, "operationJmps")
suffixGroups = ET.SubElement(root, "suffixGroups")
registers_node = ET.SubElement(root, "registers")
for ins in instruction_to_groups:
    if ins in instructions_branching:
        parent = operationJmps
    else:
        parent = operations
    ins_ode = ET.SubElement(parent, "operation", identifier=ins)
    ET.SubElement(ins_ode, "suffixGroup").text = 'G_'+ins
    group = ET.SubElement(suffixGroups, "suffixGroup", identifier='G_'+ins)
    for g in instruction_to_groups[ins]:
        ET.SubElement(group, "suffix").text = g
for ins in instructions:
    if ins in instructions_branching:
        parent = operationJmps
    else:
        parent = operations
    ins_ode = ET.SubElement(parent, "operation", identifier=ins)

for r in registers:
    ET.SubElement(registers_node, "register", identifier=r, category="GEN", length=str(registers_size[r]))

lengthKeywords = ET.SubElement(root, "lengthKeywords")
ET.SubElement(lengthKeywords, "lengthKeyWord", identifier="BYTE", length="8")
ET.SubElement(lengthKeywords, "lengthKeyWord", identifier="WORD", length="16")
ET.SubElement(lengthKeywords, "lengthKeyWord", identifier="DWORD", length="32")
ET.SubElement(lengthKeywords, "lengthKeyWord", identifier="QWORD", length="64")
ET.SubElement(lengthKeywords, "lengthKeyWord", identifier="XMMWORD", length="128")

jmpKeywords = ET.SubElement(root, "jmpKeywords")
ET.SubElement(jmpKeywords, "string").text = "large"
ET.SubElement(jmpKeywords, "string").text = "short"
ET.SubElement(jmpKeywords, "string").text = "far"

lineFormats = ET.SubElement(root, "lineFormats")
e=ET.SubElement(lineFormats, "syntax", numberOfOperand='3')
ET.SubElement(e, "lineRegex").text = r'(?&lt;OPT&gt;[\S]+)[\s]+(?&lt;OPN1&gt;[\S\s]+)[\s]*,[\s]*(?&lt;OPN2&gt;[\S\s]+),[\s]*(?&lt;OPN3&gt;[\S\s]+)'
e=ET.SubElement(lineFormats, "syntax", numberOfOperand='2')
ET.SubElement(e, "lineRegex").text = r'(?&lt;OPT&gt;[\S]+)[\s]+(?&lt;OPN1&gt;[\S\s]+)[\s]*,[\s]*(?&lt;OPN2&gt;[\S\s]+)'
e=ET.SubElement(lineFormats, "syntax", numberOfOperand='1')
ET.SubElement(e, "lineRegex").text = r'(?&lt;OPT&gt;[\S]+)[\s]+(?&lt;OPN1&gt;[\S\s]+)'
e=ET.SubElement(lineFormats, "syntax", numberOfOperand='0')
ET.SubElement(e, "lineRegex").text = r'(?&lt;OPT&gt;[\S]+)[\s]+)'

ET.SubElement(root, "constantVariableRegex").text = r'([0-9A-Fa-f]{3,10}(h|H)$)'
ET.SubElement(root, "memoryVariableRegex").text = r'(^DS:)|(^ds:)|([\s\S]*\[[\s\S]+\])'


tree = ET.ElementTree(root)
ET.indent(tree)
tree.write(f"{info.procName.lower()}.xml")