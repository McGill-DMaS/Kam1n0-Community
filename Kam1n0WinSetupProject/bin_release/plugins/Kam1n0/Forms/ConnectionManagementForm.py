from subprocess import PIPE, Popen
import threading
import time

from idaapi import Form, Choose2, plugin_t, info

from IDAutils import *

import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/' + '..'))
import json

class ConnectionListView(Choose2):
    def __init__(self, manager, flags=0):
        Choose2.__init__(self,
                         "cnns",
                         [
                           ["Connection Identifier", 30 | Choose2.CHCOL_PLAIN] ],
                         embedded=True, width=25, height=6,  flags=flags)
        self.manager = manager
        self.UpdateItems()

    def UpdateItems(self):
        Kconf = self.manager.Kconf
        allCnn = Kconf['cnns']
        self.items = [ [x] for x in allCnn ]

    def OnGetIcon(self, n):
        if not len(self.items) > 0:
            return -1
        return self.manager.icon[ICON_CONN]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)



class ConnectionManagementForm(Form):
    def __init__(self, manager):
        self.cnn = manager.connector
        self.Kconf = manager.Kconf
        self.listView = ConnectionListView(manager)

        dpItems = self.Kconf['cnns'].keys()
        if self.Kconf['default-cnn'] is not None:
            defaultIndex = self.Kconf['cnns'].keys().index(
                                     self.Kconf['default-cnn']
                                 )

        else:
            defaultIndex = 0

        Form.__init__(self,
r"""BUTTON YES* OK
BUTTON CANCEL NONE
Kam1n0 - Manage connections
{FormChangeCb}
Manage Connections:
<(Click to edit):{fvChooser}>
<Remove :{btnRemove}> Remove selected connection.
<Protocol :{txtProtocol}>
<Server   :{txtServer}>
<Port     :{txtPort}>
Login Info:
<User     :{txtUser}>
<Password :{txtPw}>
<Update / Add:{btnUpdate}>
<Default  :{dpCnn}>
<  >
""" , {
                          'fvChooser': Form.EmbeddedChooserControl(self.listView),
                          'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                          'txtServer': Form.StringInput(swidth=30,tp=Form.FT_ASCII),
                          'txtProtocol': Form.StringInput(swidth=30,tp=Form.FT_ASCII),
                          'txtPort': Form.StringInput(swidth=30,tp=Form.FT_ASCII),
                          'txtUser': Form.StringInput(swidth=30,tp=Form.FT_ASCII),
                          'txtPw': Form.StringInput(swidth=30,tp=Form.FT_ASCII),
                          'btnRemove' : Form.ButtonInput(self.OnButtonRemove),
                          'btnUpdate' : Form.ButtonInput(self.OnButtonUpdate),
                          'dpCnn' : Form.DropdownListControl(swidth=45, width=45, selval=defaultIndex, items=dpItems, readonly=True)
                      })
        self.Compile()

    def OnButtonRemove(self, code=0):
        inds = self.GetControlValue(self.fvChooser)
        if inds is not None and len(inds) > 0:
            ind = inds[0]
            if ind >= 0 and ind < len(self.listView.items):
                key = self.listView.items[ind][0]
                self.Kconf['cnns'].pop(key, None)
                self.listView.UpdateItems()
                self.RefreshField(self.fvChooser)
                if self.Kconf['default-cnn'] == key:
                    if len(self.Kconf['cnns']) > 0:
                        self.Kconf['default-cnn'] = self.Kconf['cnns'].keys()[0]
                    else:
                        self.Kconf['default-cnn'] = None
        self.updateDpList()

    def OnButtonUpdate(self, code=0):
        cnnInfo = {}
        cnnInfo['server'] = self.GetControlValue(self.txtServer)
        cnnInfo['protocol'] = self.GetControlValue(self.txtProtocol)
        cnnInfo['port'] = self.GetControlValue(self.txtPort)
        cnnInfo['un'] = self.GetControlValue(self.txtUser)
        cnnInfo['pw'] = self.GetControlValue(self.txtPw)
        cnnInfo['key'] = cnnInfo['un'] + " @ " + cnnInfo['protocol'] + cnnInfo['server'] + ":" +  cnnInfo['port']
        self.Kconf['cnns'][cnnInfo['key']] = cnnInfo
        self.listView.UpdateItems()
        self.RefreshField(self.fvChooser)
        # Select the newly added item
        self.SetControlValue(self.fvChooser, [
                                 self.Kconf['cnns'].keys().index(
                                     cnnInfo['key']
                                 )])
        self.updateDpList()
        info("Updated / added connection %s." % cnnInfo['key'])

    def updateDpList(self):
         # update dropdown list:
        dpItems = self.Kconf['cnns'].keys()
        if self.Kconf['default-cnn'] is not None:
            defaultIndex = self.Kconf['cnns'].keys().index(
                                     self.Kconf['default-cnn']
                                 )

            self.dpCnn.set_items(dpItems)
            self.RefreshField(self.dpCnn)
            self.SetControlValue(self.dpCnn, defaultIndex)
        else:
            self.dpCnn.set_items(dpItems)
            self.RefreshField(self.dpCnn)

    def OnFormChange(self, fid):

        if fid == -1:
            # self.EnableField(self.txtProtocol, False)
            # select the default connection
            if self.Kconf['default-cnn'] is not None:
                defaultIndex = self.Kconf['cnns'].keys().index(
                                     self.Kconf['default-cnn']
                                 )
                self.SetControlValue(self.fvChooser, [
                    defaultIndex
                                 ])

        if fid == self.dpCnn.id:
            if len(self.Kconf['cnns'].keys()) > 0:
                # update configuraion
                selectedInd = self.GetControlValue(self.dpCnn)
                key = self.Kconf['cnns'].keys()[selectedInd]
                self.Kconf['default-cnn'] = key



        if fid == self.fvChooser.id:
            inds = self.GetControlValue(self.fvChooser)
            if inds is not None and len(inds) > 0:
                ind = inds[0]
                key = self.listView.items[ind][0]
                cnnInfo = self.Kconf['cnns'][key]
                self.SetControlValue(self.txtServer,cnnInfo['server'])
                self.SetControlValue(self.txtProtocol,cnnInfo['protocol'])
                self.SetControlValue(self.txtPort,cnnInfo['port'])
                self.SetControlValue(self.txtUser,cnnInfo['un'])
                self.SetControlValue(self.txtPw,cnnInfo['pw'])

        return 1
