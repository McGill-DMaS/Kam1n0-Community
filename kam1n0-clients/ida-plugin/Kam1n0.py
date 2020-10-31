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
res = idaapi.get_plugin_options("kam1n0")
if res != 'noinit':
    import Kam1n0.Plugin as kp
    
    def PLUGIN_ENTRY():
        return kp.kam1n0_t()
