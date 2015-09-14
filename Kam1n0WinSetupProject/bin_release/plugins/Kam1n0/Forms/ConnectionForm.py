from subprocess import PIPE, Popen
import threading
import time

from idaapi import Form, Choose2, plugin_t

from IDAutils import *

import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/' + '..'))
import json


class ConfirmConnection(Form):
    def __init__(self, manager, message = "Search Configuration:"):
        self.cnn = manager.connector
        Form.__init__(self,
r"""BUTTON YES* Apply
BUTTON CANCEL Cancel
Kam1n0
{FormChangeCb}
%s
<Protocol :{txtProtocol}>
<Server   :{txtServer}>
<Port     :{txtPort}>
Login Info:
<User     :{txtUser}>
<Password :{txtPw}>
<  >
""" % message, {
                          'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                          'txtServer': Form.StringInput(swidth=30,tp=Form.FT_ASCII, value=self.cnn.server),
                          'txtProtocol': Form.StringInput(swidth=30,tp=Form.FT_ASCII, value=self.cnn.protocol),
                          'txtPort': Form.StringInput(swidth=30,tp=Form.FT_ASCII, value=self.cnn.port),
                          'txtUser': Form.StringInput(swidth=30,tp=Form.FT_ASCII, value=self.cnn.un),
                          'txtPw': Form.StringInput(swidth=30,tp=Form.FT_ASCII, value=self.cnn.pw),
                      })
        self.Compile()



    def OnFormChange(self, fid):

        if fid == -1:
            self.EnableField(self.txtProtocol, False)



        if fid == -2:
            self.cnn.server = self.GetControlValue(self.txtServer)
            self.cnn.protocol = self.GetControlValue(self.txtProtocol)
            self.cnn.port = self.GetControlValue(self.txtPort)
            self.cnn.un = self.GetControlValue(self.txtUser)
            self.cnn.pw = self.GetControlValue(self.txtPw)

        return 1
