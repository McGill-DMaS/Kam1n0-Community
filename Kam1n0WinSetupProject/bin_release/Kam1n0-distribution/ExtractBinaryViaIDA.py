from sets import Set
import json
import idaapi
import idc

print('My Script is now running...')
print('Waiting for idapro...')
idaapi.autoWait()
print('start persisting...')

idaapi.rebase_program(-1*idaapi.get_imagebase(), 0)

ss = idaapi.get_input_file_path()
pn = os.path.splitext(ss)[0]
callees = dict()
funcmap = dict()
data = dict()
data['name'] = pn

for seg_ea in Segments():
    for function_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
        #fill call graph
        # For each of the incoming references
        for ref_ea in CodeRefsTo(function_ea, 0):
             # Get the name of the referring function
             caller_name = GetFunctionName(ref_ea)
             # Add the current function to the list of functions called by the referring function
             callees[caller_name] = callees.get(caller_name, Set())
             callees[caller_name].add(function_ea)

data['functions'] = list()
for seg_ea in Segments():
    for function_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
        f_name = GetFunctionName(function_ea)
        function = dict();
        data['functions'].append(function)
        function['name'] = f_name
        function['id'] = function_ea
        function['call'] = list()
        function['sea'] = function_ea
        function['see'] = FindFuncEnd(function_ea)
        if callees.has_key(f_name):
            for calling in callees[f_name]:
                function['call'].append(calling)
        
        function['blocks'] = list()      
        funcfc = idaapi.FlowChart(idaapi.get_func(function_ea))
        #basic bloc content
        for bblock in funcfc:

            sblock = dict();
            sblock['id'] = bblock.id;
            sblock['sea'] = bblock.startEA
            sblock['eea'] = bblock.endEA

            fcode = ''
            for head in Heads(bblock.startEA, bblock.endEA):
                fcode +=  '%s %s \r\n' % (str(head), unicode(GetDisasm(head), errors='replace'))

            sblock['src'] = fcode
            
            # flow chart
            bcalls = list()
            for succ_block in bblock.succs():
                bcalls.append(succ_block.id)
            sblock['call'] = bcalls
            function['blocks'].append(sblock)
            

with open('%s.tmp' % ss, 'w') as outfile:
  json.dump(data, outfile)

idc.Exit(0)
