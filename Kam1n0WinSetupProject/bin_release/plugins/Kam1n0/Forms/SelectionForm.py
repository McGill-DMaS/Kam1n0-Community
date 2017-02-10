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

from subprocess import PIPE, Popen
import threading
import time

from idaapi import Form, Choose2, plugin_t

from IDAutils import *
from Connector import ERROR_LOGIN, ERROR_CONNECTION, ERROR_HTTP, OK, Connector

import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/' + '..'))
import json


class FunctionListView(Choose2):
    def __init__(self, title, flags=0):
        Choose2.__init__(self,
                         title,
                         [ ["Address", 12 | Choose2.CHCOL_DEC],
                           ["Function Name", 20 | Choose2.CHCOL_PLAIN] ],
                         embedded=True, width=35, height=10,  flags=flags)
        self.PopulateItems()

    def PopulateItems(self):
        global allFuncs
        allFuncs = [ GetFunction(x) for x in GetFunctions()]
        self.items = [ [hex(x.startEA), GetFunctionName(x) ] for x in allFuncs ]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        print n

    def OnGetSize(self):
        return len(self.items)


class SelectionForm(Form):
    def __init__(self, manager):
        global funcListG
        self.funcList = FunctionListView("asm", flags=Choose2.CH_MULTI)
        self.funcs = []

        self.cnn = manager.connector

        self.Kconf = manager.Kconf
        dpItems = self.Kconf['cnns'].keys()
        if self.Kconf['default-cnn'] is not None:
            defaultIndex = self.Kconf['cnns'].keys().index(
                                     self.Kconf['default-cnn']
                                 )

        else:
            defaultIndex = 0

        self.threshold = self.Kconf['default-threshold']
        self.topk = self.Kconf['default-topk']


        Form.__init__(self,
r"""BUTTON YES* Search
BUTTON CANCEL Cancel
Kam1n0
{FormChangeCb}
Select Function to be searched
<(Use ctrl/shift + click to select multiple functions):{fvChooser}>
<Select all functions:{chkSearchAll}><Skip library functions:{chkSkipLib}>{adSearchGroup}>
Search configuration
<Threshold:{txtSim}>
<TopK     :{txtTopK}>
<Server   :{dpServer}>

""", {
                          'adSearchGroup': Form.ChkGroupControl(["chkSearchAll", "chkSkipLib"]),
                          'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                          'txtSim': Form.StringInput(swidth=25,tp=Form.FT_ASCII, value=str(self.threshold)),
                          'txtTopK': Form.StringInput(swidth=25,tp=Form.FT_ASCII, value=str(self.topk)),
                          'dpServer':Form.DropdownListControl(swidth=45, width=45, selval=defaultIndex, items=dpItems, readonly=True),
                          'fvChooser': Form.EmbeddedChooserControl(self.funcList)
                      })
        self.Compile()

    def OnFormChange(self, fid):

        if fid == self.fvChooser.id:
            return 1

        if fid == self.chkSkipLib.id:
            if self.GetControlValue(self.chkSkipLib) == 1:
                self.SetControlValue(self.chkSearchAll, 0)
                self.SetControlValue(self.fvChooser, getNotLibIndex(allFuncs))
                self.activated = True

        if fid == self.chkSearchAll.id:
            if self.GetControlValue(self.chkSearchAll) == 1:
                self.SetControlValue(self.chkSkipLib, 0)
                self.SetControlValue(self.fvChooser, range(len(allFuncs)))
                self.activated = True

        if fid == self.dpServer:
            if len(self.Kconf['cnns'].keys()) > 0:
                # update self.cnn
                selectedInd = self.GetControlValue(self.dpServer)
                key = self.Kconf['cnns'].keys()[selectedInd]
                cnnInfo = self.Kconf['cnns'][key]
                self.cnn = Connector.Connector(
                    protocol=cnnInfo['protocol'],
                    server=cnnInfo['server'],
                    port=cnnInfo['port'],
                    un=cnnInfo['un'],
                    pw=cnnInfo['pw']
                )

        if fid == self.txtSim:
            self.threshold = float(self.GetControlValue(self.txtSim))

        if fid == self.txtTopK:
            self.topk = int(self.GetControlValue(self.txtTopK))


        if fid == -2:
            funcInds = self.GetControlValue(self.fvChooser)
            global allFuncs
            if allFuncs is not None:
                funcs = [allFuncs[x] for x in funcInds]
                if len(funcs) < 1:
                    print "number of selected functions is less than 1"
                else:
                    self.funcs += funcs


        return 1
