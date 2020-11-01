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


class SelectionForm(QtWidgets.QDialog):
    def __init__(self, manager, parent=None):
        super(SelectionForm, self).__init__(parent)

        self.configuration = manager.configuration

        self.setWindowFlags(
            QtCore.Qt.WindowCloseButtonHint
        )
        self.setModal(True)

        # Selection settings
        self.select_all = QtWidgets.QCheckBox("Select All Functions")
        self.skip_library = QtWidgets.QCheckBox("Skip Library Functions")

        # Search settings
        self.threshold_line_edit = QtWidgets.QLineEdit()
        self.topk_line_edit = QtWidgets.QLineEdit()
        self.exclude_check_box = QtWidgets.QCheckBox()
        self.kam_check_box = QtWidgets.QCheckBox()

        # Connector
        connector_label = QtWidgets.QLabel("Application")
        self.connector_combo = QtWidgets.QComboBox()
        self.connector_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)

        # Controls
        self.continue_button = QtWidgets.QPushButton('Continue')
        self.cancel_button = QtWidgets.QPushButton('Cancel')

        spacer = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)

        choose_group = QtWidgets.QGroupBox()
        hlayout = QtWidgets.QHBoxLayout()
        hlayout.addWidget(self.select_all)
        hlayout.addWidget(self.skip_library)
        choose_group.setLayout(hlayout)

        search_form_layout = QtWidgets.QFormLayout()
        search_form_layout.setHorizontalSpacing(10)
        search_form_layout.setVerticalSpacing(5)
        search_form_layout.addRow(QtWidgets.QLabel("Threshold"), self.threshold_line_edit)
        search_form_layout.addRow(QtWidgets.QLabel("Top-K"), self.topk_line_edit)
        search_form_layout.addRow(QtWidgets.QLabel("Exclude Results from the Same Binary"), self.exclude_check_box)
        search_form_layout.addRow(QtWidgets.QLabel("Save multiple queries as .kam file"), self.kam_check_box)

        self.search_group = QtWidgets.QGroupBox('Configuration')
        vbox = QtWidgets.QVBoxLayout()
        vbox.addItem(search_form_layout)
        self.search_group.setLayout(vbox)

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
        main_layout.addWidget(choose_group)
        main_layout.addWidget(self.search_group)
        main_layout.addItem(connector_layout)
        main_layout.addItem(control_layout)
        self.setLayout(main_layout)

        self.cancel_button.clicked.connect(self.OnCancel)
        self.continue_button.clicked.connect(self.OnContinue)

    def OnContinue(self):
        if self.select_all.isChecked() and self.skip_library.isChecked():
            all_func = IDAUtils.get_all_ida_funcs()
            self.selected_funcs = [all_func[x] for x in IDAUtils.get_not_lib_ida_func_indexes(all_func)]
        elif self.select_all.isChecked():
            self.selected_funcs = IDAUtils.get_all_ida_funcs()
        elif self.selected_funcs is not None and self.skip_library.isChecked():
            self.selected_funcs = [self.selected_funcs[x] for x in IDAUtils.get_not_lib_ida_func_indexes(self.selected_funcs)]
        elif self.selected_funcs is not None:
            pass
        else:
            self.selected_funcs = []

        try:
            self.selected_app_key = list(self.configuration['apps'].keys())[self.connector_combo.currentIndex()]
        except:
            self.selected_app_key = None
        self.threshold = float(self.threshold_line_edit.text())
        self.topk = int(self.topk_line_edit.text())
        self.avoidSameBinary = self.exclude_check_box.isChecked()
        self.saveAsKam = self.kam_check_box.isChecked()

        self.accept()

    def OnCancel(self):
        self.close()

    def UpdateDropDownList(self, idx=None):
        apps = list(self.configuration['apps'].keys())
        default_app = self.configuration['default-app']
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

    def OnStart(self, selectedFun, type='Search'):
        if type == 'Search':
            self.setWindowTitle("Kam1n0 - Select Functions to Search")
            self.search_group.setVisible(True)
        elif type == 'Index':
            self.setWindowTitle("Kam1n0 - Select Functions to Index")
            self.search_group.setVisible(False)
        else:
            self.setWindowTitle("Kam1n0 - Search/Index")

        self.UpdateDropDownList()
        self.threshold_line_edit.setText(str(self.configuration['default-threshold']))
        self.topk_line_edit.setText(str(self.configuration['default-topk']))
        self.exclude_check_box.setChecked(self.configuration['default-avoidSameBinary'])
        self.kam_check_box.setChecked(self.configuration['default-saveAsKam'])
        self.skip_library.setChecked(False)

        if selectedFun:
            self.selected_funcs = selectedFun
            self.select_all.setChecked(False)
        else:
            self.selected_funcs = []
            self.select_all.setChecked(True)
