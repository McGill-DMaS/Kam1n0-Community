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
#!/usr/bin/env python
#


import idaapi
from Forms.ProgressForm import SearchProgressForm
from Forms.ProgressFormIndex import IndexProgressForm
from Forms.SelectionForm import SelectionForm
from Forms.SelectionFormIndex import IndexSelectionForm
from Forms.ConnectionManagementForm import ConnectionManagementForm
import threading
from Connector import Connector, OK
import os
import pickle
import  IDAutils


class Kam1n0PluginManager():

    def __init__(self):
        self.actions = list()
        self.confDir = os.path.expanduser("~") + "/Kam1n0"
        if not os.path.exists(self.confDir):
            os.makedirs(self.confDir)
        self.loadIcons()

        self.Kconf = self.getConfiguration()
        if self.Kconf is None:
            self.connector = Connector()
            self.Kconf = {}
            self.Kconf['cnns'] = {}
            cnnInfo = self.connector.toMap()
            self.Kconf['cnns'][cnnInfo['key']] = cnnInfo
            self.Kconf['default-cnn'] = cnnInfo['key']
            self.setConfiguration(self.Kconf)
        else:
            if self.Kconf['default-cnn'] is None:
                self.connector = None
            else:
                cnnInfo = self.Kconf['cnns'][self.Kconf['default-cnn']]
                self.connector = Connector(
                    protocol=cnnInfo['protocol'],
                    server=cnnInfo['server'],
                    port=cnnInfo['port'],
                    un=cnnInfo['un'],
                    pw=cnnInfo['pw']
                )

        global hooks
        hooks = Hooks()
        re = hooks.hook()

    def loadIcons(self):
        self.icon = {}
        self.icon[IDAutils.ICON_SEARCH] = IDAutils.loadIcon(IDAutils.ICON_SEARCH)
        self.icon[IDAutils.ICON_SEARCHMULTI] = IDAutils.loadIcon(IDAutils.ICON_SEARCHMULTI)
        self.icon[IDAutils.ICON_INDEX] =  IDAutils.loadIcon(IDAutils.ICON_INDEX)
        self.icon[IDAutils.ICON_INDEXS] =  IDAutils.loadIcon(IDAutils.ICON_INDEXS)
        self.icon[IDAutils.ICON_SETT] =  IDAutils.loadIcon(IDAutils.ICON_SETT)
        self.icon[IDAutils.ICON_CONN] =  IDAutils.loadIcon(IDAutils.ICON_CONN)

    def removeAllAction(self):
        for action in self.actions:
            action.unregisterAction()

    def registerActions(self):

        action = ActionWrapper(
            id="Kam1n0:queryCurrent",
            name="Search current function",
            icon=self.icon[IDAutils.ICON_SEARCH],
            tooltip="Search the current function",
            shortcut="Ctrl+Shift+s",
            menuPath="Search/next code",
            callback=self.queryCurrentFunction,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction():
            return 1

        action = ActionWrapper(
            id="Kam1n0:querySelected",
            name="Select functions to search",
            icon=self.icon[IDAutils.ICON_SEARCHMULTI],
            tooltip="Select functions to search",
            shortcut="Ctrl+Shift+a",
            menuPath="Search/next code",
            callback=self.querySelectedFunctions,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction():
            return 1

        action = ActionWrapper(
            id="Kam1n0:indexCurrent",
            name="Index current function",
            icon=self.icon[IDAutils.ICON_INDEX],
            tooltip="Index current function",
            shortcut="Ctrl+Shift+k",
            menuPath="Edit/Export data",
            callback=self.indexCurrentFunction,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction():
            return 1

        action = ActionWrapper(
            id="Kam1n0:indexSelected",
            name="Index selected function",
            icon=self.icon[IDAutils.ICON_INDEXS],
            tooltip="Index selected function",
            shortcut="Ctrl+Shift+j",
            menuPath="Edit/Export data",
            callback=self.indexSelectedFunctions,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction():
            return 1

        action = ActionWrapper(
            id="Kam1n0:connectionManagement",
            name="Manage connection",
            icon=self.icon[IDAutils.ICON_CONN],
            tooltip="Manage connection",
            shortcut="",
            menuPath="Edit/Kam1n0/",
            callback=self.openConnectionManagmentForm,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction(True):
            return 1

        action = ActionWrapper(
            id="Kam1n0:storageManagement",
            name="Manage storage",
            icon=self.icon[IDAutils.ICON_SETT],
            tooltip="Manage storage",
            shortcut="",
            menuPath="Edit/Kam1n0/",
            callback=self.openAdminForm,
            args=None
        )
        self.actions.append(action)
        if not action.registerAction(False):
            return 1

        return 0

    def indexCurrentFunction(self, ctx):
        func = IDAutils.GetCurrentFunction()
        if not func:
            print "Current address does not belong to a function"
            return 0
        self.createIndexProgressForm([func])

    def indexSelectedFunctions(self, ctx):
        if ctx.form_title == "Functions window":
            funcs = []
            for fidx in ctx.chooser_selection:
                func = idaapi.getn_func(fidx - 1)
                funcs.append(func)
            self.createIndexProgressForm(funcs)
        else:
            form = IndexSelectionForm(self)
            ok = form.Execute()
            funcs = form.funcs
            s_cnn = form.cnn
            form.Free()
            if ok == 1:
                self.createIndexProgressForm(funcs, s_cnn)

    def querySelectedFunctions(self, ctx):
        if ctx.form_title == "Functions window":
            funcs = []
            for fidx in ctx.chooser_selection:
                func = idaapi.getn_func(fidx - 1)
                funcs.append(func)
            self.createProgressForm(funcs)
        else:
            form = SelectionForm(self)
            ok = form.Execute()
            funcs = form.funcs
            s_cnn = form.cnn
            form.Free()
            if ok == 1:
                self.createProgressForm(funcs, s_cnn)

    def queryCurrentFunction(self, ctx):
        func = IDAutils.GetCurrentFunction()
        if not func:
            print "Current address does not belong to a function"
            return 0
        self.createProgressForm([func])

    def openConnectionManagmentForm(self, ctx):
        form = ConnectionManagementForm(self)
        form.Execute()
        self.setConfiguration(self.Kconf)

        # update connection:
        if self.Kconf['default-cnn'] is not None:
            cnnInfo = self.Kconf['cnns'][self.Kconf['default-cnn']]
            self.connector = Connector(
                protocol=cnnInfo['protocol'],
                server=cnnInfo['server'],
                port=cnnInfo['port'],
                un=cnnInfo['un'],
                pw=cnnInfo['pw']
            )
            self.connector.reset()
        else:
            self.connector = None

    def openAdminForm(self, ctx):
        self.connector.openAdminPage()

    def createProgressForm(self, funcs, cnn=None):
        if cnn is None:
            cnn = self.connector
        form = SearchProgressForm(cnn, funcs)
        form.Execute()
        code = form.ErrorCode
        content = form.Content
        form.Free()
        if code > OK:
            Connector.getCodeDescription(code, content)
            idaapi.warning("Connection failed. Please review your connection. \n \"%s\"" % content)
            self.openConnectionManagmentForm(ctx=None)


    def createIndexProgressForm(self, funcs, cnn=None):
        if cnn is None:
            cnn = self.connector
        form = IndexProgressForm(cnn, funcs)
        form.Execute()
        code = form.ErrorCode
        content = form.Content
        form.Free()
        if code > OK:
            Connector.getCodeDescription(code, content)
            idaapi.warning("Connection failed. Please review your connection. \n \"%s\"" % content)
            self.openConnectionManagmentForm(ctx=None)

    def getConfiguration(self):
        try:
            with open(self.confDir + '/plugin-conf.pkl', 'rb') as f:
                return pickle.load(f)
        except:
            return None

    def setConfiguration(self, map):
        with open(self.confDir + '/plugin-conf.pkl', 'wb') as f:
            pickle.dump(map, f, pickle.HIGHEST_PROTOCOL)


class ActionWrapper(idaapi.action_handler_t):
    def __init__(self, id, name, icon, tooltip, shortcut, menuPath, callback, args = None):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.icon = icon
        self.tooltip = tooltip
        self.shortcut = shortcut
        self.menuPath = menuPath
        self.callback = callback
        self.args = args

    def registerAction(self, addToToolBar = True):
        action_desc = idaapi.action_desc_t(
        self.id,        # The action id
        self.name,      # The action text.
        self,           # The action handler.
        self.shortcut,  # Optional: the action shortcut
        self.tooltip,   # Optional: the action tooltip (available in menus/toolbar)
        self.icon)      # Optional: the action icon (shows when in menus/toolbars)
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        if addToToolBar:
            if not idaapi.attach_action_to_toolbar("SearchToolBar", self.id):
                return False
        return True

    def unregisterAction(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.detach_action_from_toolbar("SearchToolBar", self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        if self.args is None:
            self.callback(ctx)
        else:
            self.callback(ctx, self.args)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):

    def __init__(self):
        idaapi.UI_Hooks.__init__(self)


    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_title(form) == "IDA View-A":
            idaapi.attach_action_to_popup(
                form,
                popup,
                "Kam1n0:indexCurrent",
                None)
            idaapi.attach_action_to_popup(
                form,
                popup,
                "Kam1n0:queryCurrent",
                None)
        if idaapi.get_tform_title(form) == "Functions window":
            idaapi.attach_action_to_popup(
                form,
                popup,
                "Kam1n0:querySelected",
                None)
            idaapi.attach_action_to_popup(
                form,
                popup,
                "Kam1n0:indexSelected",
                None)

