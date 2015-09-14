#******************************************************************************
# Copyright 2015 McGill University									
#																					
# Licensed under the Creative Commons CC BY-NC-ND 3.0 (the "License");				
# you may not use this file except in compliance with the License.				
# You may obtain a copy of the License at										
#																				
#    https://creativecommons.org/licenses/by-nc-nd/3.0/								
#																				
# Unless required by applicable law or agreed to in writing, software			
# distributed under the License is distributed on an "AS IS" BASIS,			
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		
# See the License for the specific language governing permissions and			
# limitations under the License.												
#******************************************************************************//

from subprocess import PIPE, Popen
import threading
import time

from idaapi import Form, Choose2, plugin_t

import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/' + '..'))
import IDAutils
from Connector import ERROR_LOGIN, ERROR_CONNECTION, ERROR_HTTP, OK
import json

class ActionView(Choose2):
    def __init__(self, form, funcs, embedded = False):

        Choose2.__init__(self,
                         "Progress",
                         [ ["Function",     10 | Choose2.CHCOL_PLAIN],
                           ["Status", 10 | Choose2.CHCOL_PLAIN],
                           ["Progress", 20 | Choose2.CHCOL_PLAIN],
                         ],
                         embedded = embedded)
        self.icon = 47
        self.items = []
        self.items.append(["%s funcs" % len(funcs), "in progress", "see console"])
        self.form = form
        self.query = Query(form=self.form, funcs=funcs)
        self.query.start()

    def OnClose(self):
        self.query.cont = False
        pass

    def show(self):
        if self.Show() < 0: return False
        print "showing"
        return True

    def refreshList(self):
        self.items = []

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):
        if not len(self.items) > 0:
            return -1
        return 60

    def OnGetSize(self):
        return len(self.items)


class IndexProgressForm(Form):

    def __init__(self, cnn, funcs):
        self.cnn = cnn
        self.actionView = ActionView(form=self, funcs=funcs, embedded=True)
        self.initialized = False
        Form.__init__(self,
r"""BUTTON YES* OK
BUTTON NO NONE
BUTTON CANCEL NONE
Indexing job
{FormChangeCb}
<Index progress:{cEChooser}>
""", {
                 'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                'cEChooser': Form.EmbeddedChooserControl(self.actionView, swidth=0),
            })
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -1:
            self.initialized = True
        return 1

class Query(threading.Thread):

    def __init__(self, form, funcs):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.cont = True
        self.funcs = funcs
        self.form = form
        self.form.ErrorCode = OK
        self.form.Content = ""

    def run(self):


        cnn = self.form.cnn
        total = len(self.funcs)
        pro = 1

        for func in self.funcs:

            if self.cont == False:
                return 0

            surrogate = IDAutils.GetFuncInputSurrogate(
                func=func,
                binaryName=IDAutils.GetBinaryName()
            )

            if cnn is None:
                self.form.ErrorCode = 10
                self.form.Content = "No connection is available."
                self.form.actionView.items.append( [IDAutils.GetFunctionName(func), "Failed. Code [10]", "100%"])
                if self.form.initialized:
                    self.form.RefreshField(self.form.cEChooser)
                return 1

            code, content = cnn.tryLoginAndExecute(
                queryFunction=cnn.indexFunc,
                params=surrogate
            )

            if code != OK:
                self.form.ErrorCode = code
                self.form.Content = content
                self.form.actionView.items.append( [IDAutils.GetFunctionName(func), "Failed. Code ["+str(code)+"]", "100%"])
                if self.form.initialized:
                    self.form.RefreshField(self.form.cEChooser)
                return 1


            if "O:" in content:
                msg = "| %-20.20s | %-20.20s | %-10.10s" % (IDAutils.GetFunctionName(func), "Completed", str(pro * 100 / total)+"%")
            else:
                msg = "| %-20.20s | %-20.20s | %-10.10s" % (IDAutils.GetFunctionName(func), content, str(pro * 100 / total)+"%")

            if self.cont == False:
                return 0
            print msg

            pro+=1

        self.form.actionView.items.append(["%s funcs" % len(self.funcs), "Completed", "100%"])
        if self.form.initialized:
            self.form.RefreshField(self.form.cEChooser)


