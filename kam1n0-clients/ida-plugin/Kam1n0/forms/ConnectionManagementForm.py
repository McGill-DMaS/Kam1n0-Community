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

import threading
import time
import os
import sys

from Kam1n0 import IDAUtils
if IDAUtils.is_hexrays_v7():
    from idaapi import Choose as Choose
    from ida_kernwin import Form, info
    from ida_idaapi import plugin_t
else:
    from idaapi import Choose2 as Choose
    from idaapi import Form, plugin_t, info


class ConnectionListView(Choose):
    def __init__(self, manager, flags=0):
        Choose.__init__(self,
                         "apps",
                         [
                             ["Connection Identifier",
                              50 | Choose.CHCOL_PLAIN]],
                         embedded=True, width=80, height=6, flags=flags)
        self.manager = manager
        self.UpdateItems()

    def UpdateItems(self):
        apps = self.manager.configuration['apps']
        self.items = [[x] for x in apps]

    def OnGetIcon(self, *_):
        if not len(self.items) > 0:
            return -1
        return self.manager.icons.ICON_CONN

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class ConnectionManagementForm(Form):
    def __init__(self, manager):
        self.cnn = manager.connector
        self.configuration = manager.configuration
        self.listView = ConnectionListView(manager)

        apps = self.configuration['apps'].keys()
        app_default = self.configuration['default-app']

        if app_default is not None:
            default_index = apps.index(app_default)

        else:
            default_index = 0

        # indent matters:
        Form.__init__(self,
r"""BUTTON YES* OK 
BUTTON CANCEL NONE 
Kam1n0 - Manage connections
{FormChangeCb}
Manage Connections:
<(Click to edit):{fvChooser}>
<Remove :{btnRemove}> Remove selected connection.
<App URL  :{txtServer}>
Login Info:
<User     :{txtUser}>
<Password :{txtPw}>
<Update / Add:{btnUpdate}>
<Threshold:{txtSim}>
<Top-K    :{txtTopK}>
<Avoid Same Binary  :{chkSameBin}>{chkGroup}>
<Multiple queries saved as .kam file  :{chkKamSave}>{chkGroupp}>
<Connector:{dpCnn}>
""", {
                          'fvChooser': Form.EmbeddedChooserControl(
                              self.listView),
                          'FormChangeCb': Form.FormChangeCb(
                              self.OnFormChange),
                          'txtServer': Form.StringInput(
                              swidth=60,
                              tp=Form.FT_ASCII),
                          'txtUser': Form.StringInput(
                              swidth=60,
                              tp=Form.FT_ASCII),
                          'txtPw': Form.StringInput(
                              swidth=60,
                              tp=Form.FT_ASCII),
                          'btnRemove': Form.ButtonInput(self.OnButtonRemove),
                          'btnUpdate': Form.ButtonInput(self.OnButtonUpdate),
                          'txtSim': Form.StringInput(
                              swidth=45,
                              tp=Form.FT_ASCII,
                              value=str(self.configuration[
                                            'default-threshold'])),
                          'txtTopK': Form.StringInput(
                              swidth=45,
                              tp=Form.FT_ASCII,
                              value=str(self.configuration[
                                            'default-topk'])),
                          'chkGroup': Form.ChkGroupControl(
                              ("chkSameBin", "")),
                          'chkGroupp': Form.ChkGroupControl(
                              ("chkKamSave", "")),
                          'dpCnn': Form.DropdownListControl(
                              swidth=60,
                              width=60,
                              selval=default_index,
                              items=apps,
                              readonly=True)
                      })
        self.Compile()

    def OnButtonRemove(self, *_):
        indexes = self.GetControlValue(self.fvChooser)
        if indexes is not None and len(indexes) > 0:
            ind = indexes[0]
            if 0 <= ind < len(self.listView.items):
                key = self.listView.items[ind][0]
                self.configuration['apps'].pop(key, None)
                self.listView.UpdateItems()
                self.RefreshField(self.fvChooser)
                if self.configuration['default-app'] == key:
                    if len(self.configuration['apps']) > 0:
                        self.configuration['default-app'] = \
                            self.configuration['apps'].keys()[0]
                    else:
                        self.configuration['default-app'] = None
        self.updateDpList()

    def OnButtonUpdate(self, *_):
        app = dict()
        app['app_url'] = self.GetControlValue(self.txtServer)
        app['un'] = self.GetControlValue(self.txtUser)
        app['pw'] = self.GetControlValue(self.txtPw)
        self.configuration['apps'][app['app_url']] = app
        self.listView.UpdateItems()
        self.RefreshField(self.fvChooser)
        # Select the newly added item
        self.SetControlValue(self.fvChooser, [
            self.configuration['apps'].keys().index(
                app['app_url']
            )])
        self.updateDpList()
        info("Updated / added connection %s." % app['app_url'])

    def updateDpList(self):
        # update dropdown list:
        apps = self.configuration['apps'].keys()
        default_app = self.configuration['default-app']
        if default_app is not None:
            default_index = apps.index(default_app)

            self.dpCnn.set_items(apps)
            self.RefreshField(self.dpCnn)
            self.SetControlValue(self.dpCnn, default_index)
        else:
            self.dpCnn.set_items(apps)
            self.RefreshField(self.dpCnn)

    def OnFormChange(self, fid):

        if fid == -1:
            # self.EnableField(self.txtProtocol, False)
            # select the default connection
            self.SetControlValue(self.chkSameBin, self.configuration['default-avoidSameBinary'])
            self.SetControlValue(self.chkKamSave, self.configuration['default-saveAsKam'])
            apps = self.configuration['apps'].keys()
            default_app = self.configuration['default-app']
            if default_app is not None:
                default_index = apps.index(default_app)
                app = self.configuration['apps'][default_app]
                self.SetControlValue(self.fvChooser, [default_index])
                self.SetControlValue(self.txtServer, app['app_url'])
                self.SetControlValue(self.txtUser, app['un'])
                self.SetControlValue(self.txtPw, app['pw'])

        if fid == self.dpCnn.id:
            if len(self.configuration['apps'].keys()) > 0:
                # update configuration
                selected_index = self.GetControlValue(self.dpCnn)
                key = self.configuration['apps'].keys()[selected_index]
                self.configuration['default-app'] = key

        if fid == self.fvChooser.id:
            selected_indexes = self.GetControlValue(self.fvChooser)
            #print(selected_indexes)
            if selected_indexes is not None and len(selected_indexes) > 0:
                ind = selected_indexes[0]
                key = self.listView.items[ind][0]
                app = self.configuration['apps'][key]
                self.SetControlValue(self.txtServer, app['app_url'])
                self.SetControlValue(self.txtUser, app['un'])
                self.SetControlValue(self.txtPw, app['pw'])

        if fid == -2:
            self.configuration['default-threshold'] = float(
                self.GetControlValue(self.txtSim))
            self.configuration['default-topk'] = int(
                self.GetControlValue(self.txtTopK))
            self.configuration['default-avoidSameBinary'] = bool(
                self.GetControlValue(self.chkSameBin)
            )
            self.configuration['default-saveAsKam'] = bool(
                self.GetControlValue(self.chkKamSave)
            )

        return 1
