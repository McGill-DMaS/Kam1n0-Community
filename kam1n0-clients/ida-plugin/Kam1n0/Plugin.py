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

import idaapi
from . import Manager
from idaapi import plugin_t



class kam1n0_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Kam1n0."
    help = "Kam1n0."
    wanted_name = "Kam1n0"
    wanted_hotkey = ""

    def init(self):
        global kam1n0_manager

        # Check if already initialized
        if not 'kam1n0_manager' in globals():
            print("Kam1n0: initializing Kam1n0 IDA-pro plugin ...")
            kam1n0_manager = Manager.Kam1n0PluginManager()
            if kam1n0_manager.register_all_actions():
                print("Failed to initialize Kam1n0.")
                # kam1n0_manager.removeAllAction()
                del kam1n0_manager
                return idaapi.PLUGIN_SKIP
            else:
                print("Kam1n0: Completed initialization.")

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass