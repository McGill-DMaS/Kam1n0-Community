#!/usr/bin/env python
#
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

import os
import json
import idaapi
import pickle
from .utilities.CloneConnector import CloneConnector
from .forms.ConnectionManagementForm import ConnectionManagementForm
from .forms.SelectionForm import SelectionForm

from . import IDAUtils

class Kam1n0PluginManager:
    def __init__(self):
        self.connector = None
        self.actions = list()
        self.conf_dir = os.path.expanduser("~") + "/Kam1n0"
        if not os.path.exists(self.conf_dir):
            os.makedirs(self.conf_dir)
        self.icons = IDAUtils.load_icons_as_dict()

        self.configuration = self.get_configuration()
        self.setup_default_connection()

        self.connection_management_form = ConnectionManagementForm(self)
        self.selection_form = SelectionForm(self)

        global hooks
        hooks = Hooks()
        hooks.hook()

    def _get_connector(self):
        if self.connector is None:
            self.open_cnn_manager()
        return self.connector

    def _get_ctx_title(self, ctx):
        if IDAUtils.is_hexrays_v7():
            return ctx.widget_title
        else:
            return ctx.form_title

    def setup_default_connection(self):
        if self.configuration is not None and len(self.configuration['apps']) > 0:
            if self.configuration['default-app'] is None:
                self.connector = None
            else:
                info = self.configuration['apps'][
                    self.configuration['default-app']]
                self.connector = CloneConnector(
                    app_url=info['app_url'],
                    un=info['un'],
                    pw=info['pw'],
                    msg_callback=IDAUtils.execute
                )
        else:
            self.configuration['apps'] = {}
            self.configuration['default-app'] = None
            self.connector = None
            
        if 'default-threshold' not in self.configuration:
            self.configuration['default-threshold'] = 0.01

        if 'default-topk' not in self.configuration:
            self.configuration['default-topk'] = 15

        if 'default-avoidSameBinary' not in self.configuration:
            self.configuration['default-avoidSameBinary'] = False
            
        if 'default-saveAsKam' not in self.configuration:
            self.configuration['default-saveAsKam'] = False

    def get_conf_topk(self):
        return self.configuration['default-topk']

    def get_conf_threshold(self):
        return self.configuration['default-threshold']

    def get_conf_avoidSameBinary(self):
        return self.configuration['default-avoidSameBinary']
        
    def get_conf_saveAsKam(self):
        return self.configuration['default-saveAsKam']

    def remove_all_actions(self):
        for action in self.actions:
            action.de_register_action()

    def register_all_actions(self):

        action = ActionWrapper(
            id="Kam1n0:queryCurrent",
            name="Search current function",
            icon=self.icons.ICON_SEARCH,
            tooltip="Search current function",
            shortcut="Ctrl+Shift+s",
            menuPath="Search/next code",
            callback=self.query_current_func,
            args=None
        )
        self.actions.append(action)
        if not action.register_action():
            return 1

        action = ActionWrapper(
            id="Kam1n0:querySelected",
            name="Search the selected functions",
            icon=self.icons.ICON_SEARCH_MULTIPLE,
            tooltip="Search the selected functions",
            shortcut="Ctrl+Shift+a",
            menuPath= "",            #"Search/next code",
            callback=self.query_selected_func,
            args=None
        )
        self.actions.append(action)
        if not action.register_action():
            return 1

        action = ActionWrapper(
            id="Kam1n0:indexCurrent",
            name="Index current function",
            icon=self.icons.ICON_INDEX,
            tooltip="Index current function",
            shortcut="Ctrl+Shift+k",
            menuPath="Edit/Export data",
            callback=self.index_current_func,
            args=None
        )
        self.actions.append(action)
        if not action.register_action():
            return 1

        action = ActionWrapper(
            id="Kam1n0:indexSelected",
            name="Index the selected functions",
            icon=self.icons.ICON_INDEX_MULTIPLE,
            tooltip="Index the selected functions",
            shortcut="Ctrl+Shift+j",
            menuPath="Edit/Export data",
            callback=self.index_selected_func,
            args=None
        )
        self.actions.append(action)
        if not action.register_action():
            return 1

        action = ActionWrapper(
            id="Kam1n0:connectionManagement",
            name="Manage connections",
            icon=self.icons.ICON_CONN,
            tooltip="Manage connections",
            shortcut="",
            menuPath="Edit/Kam1n0/",
            callback=self.open_cnn_manager,
            args=None
        )
        self.actions.append(action)
        if not action.register_action(True):
            return 1

        action = ActionWrapper(
            id="Kam1n0:storageManagement",
            name="Manage applications",
            icon=self.icons.ICON_SETT,
            tooltip="Manage applications",
            shortcut="",
            menuPath="Edit/Kam1n0/",
            callback=self.open_user_home,
            args=None
        )
        self.actions.append(action)
        if not action.register_action(False):
            return 1

        action = ActionWrapper(
            id="Kam1n0:compositionQuery",
            name="Composition analysis",
            icon=self.icons.ICON_COMP,
            tooltip="Composition analysis",
            shortcut="",
            menuPath="Search/next code",
            callback=self.query_binary,
            args=None
        )
        self.actions.append(action)
        if not action.register_action(True):
            return 1

        action = ActionWrapper(
            id="Kam1n0:queryFragment",
            name="Query fragment",
            icon=self.icons.ICON_FRAG,
            tooltip="Query a code fragment",
            shortcut="",
            menuPath="Search/next code",
            callback=self.query_fragment,
            args=None
        )
        self.actions.append(action)
        if not action.register_action(False):
            return 1
        # no error registering all actions
        return 0

    def index_current_func(self, *_):
        func = IDAUtils.get_ida_func()
        if not func:
            print()
            "Current address does not belong to a function"
            return 0
        if self._get_connector() is not None:
            self.connector.index(IDAUtils.get_as_single_surrogate(func))

    def index_selected_func(self, ctx):
        title = self._get_ctx_title(ctx)
        if title == "Functions window":
            if IDAUtils.is_hexrays_v7():
                ida_funcs_t = [idaapi.getn_func(f_idx) for f_idx in
                             ctx.chooser_selection]
            else:
                ida_funcs_t = [idaapi.getn_func(f_idx - 1) for f_idx in
                             ctx.chooser_selection]
            connector, ida_funcs, _, _, _, _ = self.select_funcs(ida_funcs_t, type='Index')
        else:
            connector, ida_funcs, _, _, _, _ = self.select_funcs([], type='Index')

        if ida_funcs is None:
            return
        if connector is None:
            self.open_cnn_manager()
            connector = self.connector
        if connector is not None and ida_funcs is not None and len(ida_funcs) > 0:
            connector.index(IDAUtils.get_as_single_surrogate(ida_funcs))

    def query_current_func(self, *_):
        func = IDAUtils.get_ida_func()
        if not func:
            print()
            "Current address does not belong to a function"
            return 0
        if self._get_connector() is not None:
            self.connector.search_func(
                queries=IDAUtils.get_as_single_surrogate(func),
                topk=self.get_conf_topk(),
                threshold=self.get_conf_threshold(),
                avoid_same_binary=self.get_conf_avoidSameBinary())

    def query_fragment(self, *_):
        view = idaapi.get_current_viewer()
        selection = idaapi.read_range_selection(view)
        content = ""
        if selection[0] is True:
            content = IDAUtils.get_selected_code(selection[1], selection[2])
        if self._get_connector() is not None:
            self.connector.search_func(
                queries=content,
                topk=self.get_conf_topk(),
                threshold=self.get_conf_threshold(),
                avoid_same_binary=self.get_conf_avoidSameBinary())

    def query_selected_func(self, ctx):
        title = self._get_ctx_title(ctx)
        if title == "Functions window":
            if IDAUtils.is_hexrays_v7():
                ida_funcs_t = [idaapi.getn_func(f_idx) for f_idx in
                             ctx.chooser_selection]
            else:
                ida_funcs_t = [idaapi.getn_func(f_idx - 1) for f_idx in
                             ctx.chooser_selection]
            connector, ida_funcs, threshold, topk, avoidSameBinary, saveAsKam = self.select_funcs(ida_funcs_t, type='Search')
        else:
            connector, ida_funcs, threshold, topk, avoidSameBinary, saveAsKam = self.select_funcs([], type='Search')

        if ida_funcs is None:
            return
        if connector is None:
            self.open_cnn_manager()
            connector = self.connector
        if connector is not None and ida_funcs is not None and len(ida_funcs) > 0:
            if not saveAsKam:
                connector.search_func(
                    queries=IDAUtils.get_as_multiple_surrogate(ida_funcs),
                    topk=topk,
                    threshold=threshold,
                    avoid_same_binary=avoidSameBinary)
            else:
                connector.search_binary(
                    IDAUtils.get_as_single_surrogate(ida_funcs),
                    topk=topk,
                    threshold=threshold,
                    avoid_same_binary=avoidSameBinary)

    def query_binary(self, *_):
        print()
        "Generating binary surrogate for composition query..."
        surrogate = IDAUtils.get_as_single_surrogate()
        if not surrogate:
            print()
            "Cannot generate the binary surrogate"
            return 0
        if self._get_connector() is not None:
            self.connector.search_binary(surrogate, self.get_conf_topk(),
                                         self.get_conf_threshold(), self.get_conf_avoidSameBinary())

    def open_cnn_manager(self, *_):
        self.connection_management_form.OnStart()
        if self.connection_management_form.exec():
            self.save_configuration(self.configuration)
            self.setup_default_connection()

    def open_user_home(self, *_):
        if self._get_connector() is not None:
            self.connector.open_user_home()

    def select_funcs(self, ida_funcs, type='Search'):
        self.selection_form.OnStart(ida_funcs, type)
        if self.selection_form.exec():
            ida_funcs = self.selection_form.selected_funcs
            selected_key = self.selection_form.selected_app_key
            threshold = self.selection_form.threshold
            topk = self.selection_form.topk
            avoidSameBinary = self.selection_form.avoidSameBinary
            saveAsKam = self.selection_form.saveAsKam
            if selected_key is None:
                app = None
            else:
                app = self.configuration['apps'][selected_key]
            if app:
                connector = CloneConnector(msg_callback=IDAUtils.execute, **app)
                return connector, ida_funcs, threshold, topk, avoidSameBinary, saveAsKam
        return None, None, None, None, None, None

    def get_configuration(self):
        conf_file = self.conf_dir + '/plugin-conf.pk'
        if os.path.exists(conf_file):
            with open(conf_file, 'rb') as f:
                return pickle.load(f)

    def save_configuration(self, conf):
        conf_file = self.conf_dir + '/plugin-conf.pk'
        with open(conf_file, 'wb') as f:
            pickle.dump(conf, f, pickle.HIGHEST_PROTOCOL)


class ActionWrapper(idaapi.action_handler_t):
    def __init__(self, id, name, icon, tooltip, shortcut, menuPath, callback,
                 args=None):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.icon = icon
        self.tooltip = tooltip
        self.shortcut = shortcut
        self.menuPath = menuPath
        self.callback = callback
        self.args = args

    def register_action(self, add_to_toolbar=True):
        action_desc = idaapi.action_desc_t(
            self.id,  # The action id
            self.name,  # The action text.
            self,  # The action handler.
            self.shortcut,  # Optional: the action shortcut
            self.tooltip,
            # Optional: the action tooltip (available in menus/toolbar)
            self.icon)  # Optional: the action icon (shows when in menus/toolbars)
        if not idaapi.register_action(action_desc):
            return False
        if self.menuPath != "":
            if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
                return False
        if add_to_toolbar:
            if not idaapi.attach_action_to_toolbar("SearchToolBar", self.id):
                return False
        return True

    def de_register_action(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.detach_action_from_toolbar("SearchToolBar", self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        if self.args is None:
            self.callback(ctx)
        else:
            self.callback(ctx, self.args)
        return 1

    def update(self, arg):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_title(form).startswith("IDA View"):
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
            idaapi.attach_action_to_popup(
                form,
                popup,
                "Kam1n0:queryFragment",
                None)
        if idaapi.get_widget_title(form) == "Functions window":
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
