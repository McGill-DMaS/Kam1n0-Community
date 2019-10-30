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

import sys
import os
import idc
from idaapi import Form, plugin_t
from Kam1n0 import IDAUtils
if IDAUtils.is_hexrays_v7():
    from idaapi import Choose as Choose
else:
    from idaapi import Choose2 as Choose



class FunctionListView(Choose):
    def __init__(self, title, all_funcs, flags=0):
        Choose.__init__(self,
                         title,
                         [["Address", 12 | Choose.CHCOL_DEC],
                          ["Function Name", 20 | Choose.CHCOL_PLAIN]],
                         embedded=True, width=80, height=6, flags=flags
                         )
        self.all_funcs = all_funcs
        self.PopulateItems()

    def PopulateItems(self):
        self.items = [[hex(x.start_ea), idc.get_func_name(x.start_ea)] for x
                      in self.all_funcs]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        print n

    def OnGetSize(self):
        return len(self.items)


class SelectionForm(Form):
    def __init__(self, manager, disable_param=False):

        self.disable_param = disable_param

        self.all_funcs = IDAUtils.get_all_ida_funcs()
        self.funcList = FunctionListView("asm", flags=Choose.CH_MULTI,
                                         all_funcs=self.all_funcs)
        self.selected_funcs = []

        self.configuration = manager.configuration
        apps = self.configuration['apps'].keys()
        default_app = self.configuration['default-app']
        if self.configuration['default-app'] is not None:
            default_index = apps.index(default_app)
        else:
            default_index = 0
        self.selected_app_key = default_app

        self.threshold = self.configuration['default-threshold']
        self.topk = self.configuration['default-topk']
        self.avoidSameBinary = self.configuration['default-avoidSameBinary']

        Form.__init__(self,
r"""BUTTON YES* Continue
BUTTON CANCEL Cancel
Kam1n0
{FormChangeCb}
Select Function:
<(Use ctrl/shift + click to select multiple functions):{fvChooser}>
<Select all functions:{chkSearchAll}><Skip library functions:{chkSkipLib}>{adSearchGroup}>
Configuration
<Threshold:{txtSim}>
<TopK     :{txtTopK}>
<Avoid Same Binary  :{chkSameBin}>{chkGroup}>
<App   :{dpServer}>
""", {
                          'adSearchGroup': Form.ChkGroupControl(
                              ["chkSearchAll", "chkSkipLib"]),
                          'FormChangeCb': Form.FormChangeCb(
                              self.OnFormChange),
                          'txtSim': Form.StringInput(
                              swidth=25,
                              tp=Form.FT_ASCII,
                              value=str(
                                  self.threshold)),
                          'txtTopK': Form.StringInput(
                              swidth=25,
                              tp=Form.FT_ASCII,
                              value=str(self.topk)),
                          'chkGroup': Form.ChkGroupControl(
                              ("chkSameBin", "")),
                          'dpServer': Form.DropdownListControl(
                              swidth=45,
                              width=45,
                              selval=default_index,
                              items=apps,
                              readonly=True),
                          'fvChooser': Form.EmbeddedChooserControl(
                              self.funcList)
                      })
        self.Compile()

    def OnFormChange(self, fid):

        if fid == -1:
            # self.EnableField(self.txtProtocol, False)
            # select the default connection
            self.SetControlValue(self.chkSameBin, self.avoidSameBinary)

        if fid == self.fvChooser.id:
            return 1

        if fid == self.chkSkipLib.id:
            if self.GetControlValue(self.chkSkipLib) == 1:
                self.SetControlValue(self.chkSearchAll, 0)
                self.SetControlValue(self.fvChooser,
                                     IDAUtils.get_not_lib_ida_func_indexes(
                                         self.all_funcs))
                self.activated = True

        if fid == self.chkSearchAll.id:
            if self.GetControlValue(self.chkSearchAll) == 1:
                self.SetControlValue(self.chkSkipLib, 0)
                self.SetControlValue(self.fvChooser,
                                     range(len(self.all_funcs)))
                self.activated = True

        if fid == self.dpServer:
            if len(self.configuration['apps'].keys()) > 0:
                # update self.cnn
                selected_ind = self.GetControlValue(self.dpServer)
                self.selected_app_key = \
                    self.configuration['apps'].keys()[selected_ind]

        if fid == self.txtSim:
            self.threshold = float(self.GetControlValue(self.txtSim))

        if fid == self.txtTopK:
            self.topk = int(self.GetControlValue(self.txtTopK))

        if fid == self.chkSameBin:
            self.avoidSameBinary = bool(
                self.GetControlValue(self.chkSameBin)
            )


        if fid == -2:
            func_indexes = self.GetControlValue(self.fvChooser)
            if self.all_funcs is not None:
                funcs = [self.all_funcs[x] for x in func_indexes]
                if len(funcs) < 1:
                    print "number of selected functions is less than 1"
                else:
                    self.selected_funcs = funcs

        return 1
