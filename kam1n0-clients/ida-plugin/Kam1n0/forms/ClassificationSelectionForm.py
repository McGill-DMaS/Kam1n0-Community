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

from PyQt5 import QtWidgets, QtCore, QtGui


class ClassificationSelectionForm(QtWidgets.QDialog):
    def __init__(self, manager, parent=None):
        super(ClassificationSelectionForm, self).__init__(parent)

        self.configuration = manager.configuration

        self.setWindowFlags(
            QtCore.Qt.WindowCloseButtonHint
        )
        self.setModal(True)


        # Search settings

        # Connector
        connector_label = QtWidgets.QLabel("Application")
        self.connector_combo = QtWidgets.QComboBox()
        self.connector_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)

        # Controls
        self.continue_button = QtWidgets.QPushButton('Continue')
        self.cancel_button = QtWidgets.QPushButton('Cancel')

        spacer = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)


        search_form_layout = QtWidgets.QFormLayout()
        search_form_layout.setHorizontalSpacing(10)
        search_form_layout.setVerticalSpacing(5)


        connector_layout = QtWidgets.QHBoxLayout()
        connector_layout.addItem(spacer)
        connector_layout.addWidget(connector_label)
        connector_layout.addItem(spacer)
        connector_layout.addWidget(self.connector_combo)
        connector_layout.addItem(spacer)

        control_layout = QtWidgets.QHBoxLayout()
        control_layout.addItem(spacer)
        control_layout.addWidget(self.continue_button)
        control_layout.addWidget(self.cancel_button)
        control_layout.addItem(spacer)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addItem(connector_layout)
        main_layout.addItem(control_layout)
        self.setLayout(main_layout)

        self.cancel_button.clicked.connect(self.OnCancel)
        self.continue_button.clicked.connect(self.OnContinue)

    def OnContinue(self):

        try:
            self.selected_app_key = list(self.configuration['cls-apps'].keys())[self.connector_combo.currentIndex()]
        except:
            self.selected_app_key = None
        self.accept()

    def OnCancel(self):
        self.close()

    def UpdateDropDownList(self, idx=None):
        apps = list(self.configuration['cls-apps'].keys())
        default_app = self.configuration['default-cls-app']
        if default_app is not None:
            default_index = apps.index(default_app)
            self.connector_combo.clear()
            self.connector_combo.addItems(apps)
            self.connector_combo.setCurrentIndex(default_index)
            if idx:
                self.listView.setCurrentItem(self.listView.topLevelItem(idx))
        else:
            self.connector_combo.clear()
            self.connector_combo.addItems(apps)

    def OnStart(self):
        self.setWindowTitle("Kam1n0 - Classification settings")

        self.UpdateDropDownList()
