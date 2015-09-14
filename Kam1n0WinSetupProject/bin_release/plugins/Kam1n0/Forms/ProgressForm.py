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
                           ["Time taken (ms)",  10 | Choose2.CHCOL_PLAIN],
                           ["Progress", 20 | Choose2.CHCOL_PLAIN],
                         ],
                         embedded = embedded,  height=6)
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

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):
        if not len(self.items) > 0:
            return -1
        return 60

    def OnGetSize(self):
        return len(self.items)


class SearchProgressForm(Form):

    def __init__(self, cnn, funcs):
        self.cnn = cnn
        self.actionView = ActionView(form=self, funcs=funcs, embedded=True)
        self.ErrorCode = OK
        self.Content = ""
        self.initialized = False
        Form.__init__(self,
r"""BUTTON YES* OK
BUTTON NO NONE
BUTTON CANCEL NONE
Searching job
{FormChangeCb}
<Searching progress:{cEChooser}>
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

    def run(self):

        cnn = self.form.cnn
        dps = []

        total = len(self.funcs)
        pro = 1

        for func in self.funcs:

            if self.cont == False:
                return 0

            surrogate = IDAutils.GetFuncInputSurrogate(func, IDAutils.GetBinaryName())

            if cnn is None:
                self.form.ErrorCode = 10
                self.form.Content = "No connection is available."
                self.form.actionView.items.append( [IDAutils.GetFunctionName(func), "Failed. Code [10]", "100%"])
                if self.form.initialized:
                    self.form.RefreshField(self.form.cEChooser)
                return 0

            code, content = cnn.tryLoginAndExecute(
                queryFunction=cnn.querySurrogate,
                params=surrogate
            )

            if code != OK:
                self.form.ErrorCode = code
                self.form.Content = content
                self.form.actionView.items.append( [IDAutils.GetFunctionName(func), "Failed. Code ["+str(code)+"]", "100%"])
                if self.form.initialized:
                    self.form.RefreshField(self.form.cEChooser)
                return 0


            response = json.loads(content)

            if len(response['results']) > 0:
                response['results'][0]['function']['surrogate'] = surrogate
            response['cnn'] = {}
            response['cnn']['server'] = cnn.server
            response['cnn']['protocol'] = cnn.protocol
            response['cnn']['port'] = cnn.port
            response['cnn']['ssid'] = cnn.getSessionID()

            msg = "| %-20.20s | %-20.20s | %-10.10s" % (IDAutils.GetFunctionName(func), str(response['takenTime']), str(pro * 100 / total)+"%")
            if self.cont == False:
                return 0

            print msg

            dps.append(response)

            pro+=1

        dp = cnn.mergeFuncs(dps)

        self.form.actionView.items.append(["%s funcs" % len(self.funcs), "Completed", "100%"])
        if self.form.initialized:
            self.form.RefreshField(self.form.cEChooser)

        cmd = [cnn.getPythonExePath(),
                os.path.dirname(os.path.realpath(__file__)) + "/CloneSearchRenderForm.py"]

        p = Popen(cmd,
              shell=True,
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE)

        stdout, stderr = p.communicate(json.dumps(dp))

        return 0