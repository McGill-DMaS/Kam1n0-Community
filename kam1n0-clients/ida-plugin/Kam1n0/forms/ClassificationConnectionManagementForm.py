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
import inspect
import threading
import time
import os
import sys

from Kam1n0 import IDAUtils
from ..utilities.CloneConnector import CloneConnector

if IDAUtils.is_hexrays_v7():
    from idaapi import Choose as Choose
    from ida_kernwin import Form, info
    from ida_idaapi import plugin_t
else:
    from idaapi import Choose2 as Choose
    from idaapi import Form, plugin_t, info

from PyQt5 import QtWidgets, QtCore, QtGui

conn_icon = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'img', 'setting-cnn.png'))


class ConnectionListView(QtWidgets.QTreeWidget):
    def __init__(self, config, parent=None):
        super(ConnectionListView, self).__init__(parent)

        self.setHeaderLabels(['Connection identifier'])
        self.config = config
        self.UpdateItems()

    def UpdateItems(self):
        apps = self.config['cls-apps']
        self.items = [[x] for x in apps]
        self.clear()
        for item in self.items:
            tree_item = QtWidgets.QTreeWidgetItem(self)
            tree_item.setText(0, item[0])
            tree_item.setIcon(0, QtGui.QIcon(conn_icon))
            self.addTopLevelItem(tree_item)


class ClassificationConnectionManagementForm(QtWidgets.QDialog):
    def __init__(self, manager, parent=None):
        super(ClassificationConnectionManagementForm, self).__init__(parent)
        self.setWindowFlags(
            QtCore.Qt.WindowCloseButtonHint
        )
        self.setModal(True)
        self.setWindowTitle("Kam1n0 - Manage connections")
        self.cnn = manager.connector
        self.configuration = manager.configuration

        self.listView = ConnectionListView(self.configuration)

        # Application
        self.url_line_edit = QtWidgets.QLineEdit()
        self.user_line_edit = QtWidgets.QLineEdit()
        self.pass_line_edit = QtWidgets.QLineEdit()

        # Search settings
        self.exclude_check_box = QtWidgets.QCheckBox()
        self.kam_check_box = QtWidgets.QCheckBox()

        # Connector
        connector_label = QtWidgets.QLabel("Connector")
        self.connector_combo = QtWidgets.QComboBox()
        self.connector_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        # Controls
        self.add_update_button = QtWidgets.QPushButton('Update/Add')
        self.remove_button = QtWidgets.QPushButton('Remove')
        self.save_button = QtWidgets.QPushButton('OK')
        self.cancel_button = QtWidgets.QPushButton('Cancel')

        spacer = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)

        # Layouts
        app_form_layout = QtWidgets.QFormLayout()
        app_form_layout.setHorizontalSpacing(10)
        app_form_layout.setVerticalSpacing(5)
        app_form_layout.addRow(QtWidgets.QLabel("URL"), self.url_line_edit)
        app_form_layout.addRow(QtWidgets.QLabel("User"), self.user_line_edit)
        app_form_layout.addRow(QtWidgets.QLabel("Password"), self.pass_line_edit)

        applications_group = QtWidgets.QGroupBox('Application')
        vbox = QtWidgets.QVBoxLayout()
        vbox.addItem(app_form_layout)
        applications_group.setLayout(vbox)


        connector_layout = QtWidgets.QHBoxLayout()
        connector_layout.addItem(spacer)
        connector_layout.addWidget(connector_label)
        connector_layout.addItem(spacer)
        connector_layout.addWidget(self.connector_combo)
        connector_layout.addItem(spacer)

        control_layout = QtWidgets.QHBoxLayout()
        control_layout.addItem(spacer)
        control_layout.addWidget(self.add_update_button)
        control_layout.addWidget(self.remove_button)
        control_layout.addWidget(self.save_button)
        control_layout.addWidget(self.cancel_button)
        control_layout.addItem(spacer)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(self.listView)
        main_layout.addWidget(applications_group)
        main_layout.addItem(connector_layout)
        main_layout.addItem(control_layout)
        self.setLayout(main_layout)

        apps = list(self.configuration['cls-apps'].keys())
        app_default = self.configuration['default-cls-app']
        if app_default is not None:
            default_index = apps.index(app_default)
        else:
            default_index = 0
        self.listView.setCurrentItem(self.listView.topLevelItem(default_index))

        # Events
        self.remove_button.clicked.connect(self.OnButtonRemove)
        self.add_update_button.clicked.connect(self.OnButtonUpdate)
        self.save_button.clicked.connect(self.OnSave)
        self.listView.itemSelectionChanged.connect(self.OnSelectionChange)
        self.connector_combo.currentIndexChanged.connect(self.OnConnChange)
        self.cancel_button.clicked.connect(self.OnCancel)

    def OnButtonUpdate(self):
        if self.url_line_edit.text():
            app = dict()
            app['app_url'] = str(self.url_line_edit.text())
            app['un'] = str(self.user_line_edit.text())
            app['pw'] = str(self.pass_line_edit.text())
            cnn = CloneConnector(
                    app_url=app['app_url'],
                    un=app['un'],
                    pw=app['pw'],
                    msg_callback=IDAUtils.execute
                )
            resp = cnn.request._do_get(app['app_url']+'home')
            if resp[0] == 0:
                self.configuration['cls-apps'][app['app_url']] = app
                self.listView.UpdateItems()
                # Select the newly added item
                idx = list(self.configuration['cls-apps'].keys()).index(app['app_url'])
                self.listView.setCurrentItem(self.listView.topLevelItem(idx))
                self.UpdateDropDownList(idx)
                info("The connection \'%s\' was added/updated." % app['app_url'])
            else:
                info("The input information is not valid.")

    def OnButtonRemove(self):
        idx = int(self.listView.currentIndex().row())
        if 0 <= idx < len(self.listView.items):
            key = self.listView.items[idx][0]
            self.configuration['cls-apps'].pop(key, None)
            self.listView.UpdateItems()
            # self.RefreshField(self.fvChooser)
            if self.configuration['default-cls-app'] == key:
                if len(self.configuration['cls-apps']) > 0:
                    self.configuration['default-cls-app'] = \
                        list(self.configuration['cls-apps'].keys())[0]
                else:
                    self.configuration['default-cls-app'] = None
        self.UpdateDropDownList()

    def UpdateDropDownList(self, idx=None):
        apps = list(self.configuration['cls-apps'].keys())
        default_app = self.configuration['default-cls-app']
        if default_app is not None:
            default_index = apps.index(default_app)
            self.connector_combo.clear()
            self.connector_combo.addItems(apps)
            self.listView.setCurrentItem(self.listView.topLevelItem(default_index))
            self.connector_combo.setCurrentIndex(default_index)
            if idx:
                self.listView.setCurrentItem(self.listView.topLevelItem(idx))
        else:
            self.connector_combo.clear()
            self.connector_combo.addItems(apps)

    def OnStart(self):
        self.listView.UpdateItems()
        self.UpdateDropDownList()
        apps = list(self.configuration['cls-apps'].keys())
        default_app = self.configuration['default-cls-app']
        if default_app is not None:
            default_index = apps.index(default_app)
            app = self.configuration['cls-apps'][default_app]
            self.listView.setCurrentItem(self.listView.topLevelItem(default_index))
            self.connector_combo.setCurrentIndex(default_index)
            self.url_line_edit.setText(app['app_url'])
            self.user_line_edit.setText(app['un'])
            self.pass_line_edit.setText(app['pw'])

    def closeEvent(self, evnt):
        pass
        #self.OnSave()
        #super(ConnectionManagementForm, self).closeEvent(evnt)

    def OnCancel(self):
        self.close()

    def OnSave(self):
        self.accept()

    def OnConnChange(self):
        if len(list(self.configuration['cls-apps'].keys())) > 0:
            # update configuration
            selected_index = self.connector_combo.currentIndex()
            key = list(self.configuration['cls-apps'].keys())[selected_index]
            self.configuration['default-cls-app'] = key

    def OnSelectionChange(self):
        selected_indexes = self.listView.selectedItems()
        # print(selected_indexes)
        if selected_indexes is not None and len(selected_indexes) > 0:
            ind = self.listView.indexOfTopLevelItem(selected_indexes[0])
            key = self.listView.items[ind][0]
            app = self.configuration['cls-apps'][key]
            self.url_line_edit.setText(app['app_url'])
            self.user_line_edit.setText(app['un'])
            self.pass_line_edit.setText(app['pw'])
