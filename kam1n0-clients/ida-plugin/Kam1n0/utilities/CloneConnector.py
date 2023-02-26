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
from .RequestMini import Request, get_root_domain, has_error, \
    get_error_description
import json, datetime
from queue import Queue, Empty
from threading import Thread
import traceback


def console_callback(error_code, message):
    code, msg = get_error_description(error_code, message)
    tstr = datetime.datetime.now().strftime("%m-%d %H:%M:%S")
    print("[%s] Kam1n0: [E%s]: %s" % (tstr, code, msg))


class CloneConnector:
    def __init__(self, app_url, un="admin", pw="admin",
                 error_callback=console_callback, msg_callback=None):
        self.app_url = app_url
        self.un = un
        self.pw = pw
        self.error_callback = error_callback
        self.request = Request(self.get_validation_url(),
                               self.get_login_url(), self.un, self.pw)
        self.msg_queue = Queue()

        def read_queue():
            while True:
                msg = self.msg_queue.get()
                if msg_callback is not None:
                    msg_callback(msg)
                else:
                    console_callback(-1, msg)

        t = Thread(target=read_queue)
        t.daemon = True  # thread dies with the program
        t.start()

    def get_login_url(self):
        return get_root_domain(self.app_url) + 'login'

    def get_user_home(self):
        return get_root_domain(self.app_url) + 'userHome'

    def get_validation_url(self):
        return get_root_domain(self.app_url) + 'validate'

    def get_progress_url(self):
        return get_root_domain(self.app_url) + 'userProgress'

    def get_app_home(self):
        return self.app_url + 'home'

    def get_search_url(self):
        return self.app_url + 'search_func'

    def get_index_url(self):
        return self.app_url + 'push_bin'

    def get_index_url_for_classification(self):
        return self.app_url + 'push_one_file'

    def get_composition_url(self):
        return self.app_url + 'search_bin_single'

    def open_user_home(self):
        self.request.show_get(self.get_user_home(),
                              call_back=self.error_callback, queue=self.msg_queue)

    def _job_submit_callback(self, error_code, content):
        if type(content) == bytes:
            jid = 'jid'.encode('utf-8')
        else:
            jid = 'jid'
        if jid in content:
            self.request.show_get(self.get_progress_url(),
                                  call_back=self.error_callback, queue=self.msg_queue)
        else:
            self.error_callback(error_code, content)
        # self.error_callback(error_code, content)

    def search_func(self, queries, topk, threshold, avoid_same_binary):
        if not isinstance(queries, list):
            queries = [queries]
        queries = [
            query if isinstance(query, str) else json.dumps(query, ensure_ascii=False) for
            query in queries]
        external = {'func_queries': queries,
                    'other_params': {'topk': topk, 'threshold': threshold, 'avoidSameBinary': avoid_same_binary}}
        self.request.show_post(self.get_search_url(), None, external=external,
                               call_back=self.error_callback, queue=self.msg_queue)

    def search_binary(self, binary, topk, threshold, avoid_same_binary):
        if isinstance(binary, list) and len(binary) > 1:
            print()
            "Error in searching binary. Multiple binaries found." \
            " Will search only the first one."
        if isinstance(binary, list):
            binary = binary[0]
        request_param = {'bin': json.dumps(binary, ensure_ascii=False), 'topk': topk,
                         'threshold': threshold, 'avoidSameBinary': avoid_same_binary}
        #print("search_binary request_param:",request_param)

        self.request.ajax_post(self.get_composition_url(), request_param,
                               call_back=self._job_submit_callback)

    def index(self, binaries):
        if not isinstance(binaries, list):
            binaries = [binaries]
        binaries = [
            binary if isinstance(binary, str) else json.dumps(binary, ensure_ascii=False)
            for binary in binaries]
        param = [('files', binary) for binary in binaries]
        if len(param) == 1:
            param.append(('files', ''))
        self.request.ajax_post(self.get_index_url(), param,
                               call_back=self._job_submit_callback)

    def index_for_classification(self, binaries,class_name, classify_type, train_or_not, cluster_or_not, train_classifier_or_not, pattern_recognition_or_not):
        if not isinstance(binaries, list):
            binaries = [binaries]
        binaries = [
            binary if isinstance(binary, str) else json.dumps(binary, ensure_ascii=False)
            for binary in binaries]
        #request_param = [('files',binaries),('softwareClass',class_name),("trainOrNot",train_or_not),("clusterOrNot",cluster_or_not)]   

        request_param = {'file':binaries[0],'softwareClass':class_name,"trainOrNot":train_or_not,"clusterOrNot":cluster_or_not}   
        if classify_type == 'severity':
            request_param["trainClassifier"] = train_classifier_or_not
            #request_param.append(("trainClassifier",train_classifier_or_not))
        elif classify_type == "interpretable":
            request_param["trainClassifier"] = train_classifier_or_not
            request_param["clusterPatternRecognition"] = pattern_recognition_or_not

        self.request.ajax_post(self.get_index_url_for_classification(), request_param,
                               call_back=self._job_submit_callback)

if __name__ == '__main__':
    cnn = CloneConnector(
        'http://127.0.0.1:8571/sym1n0-clone/-9204093734748848546/', 'admin',
        'admin')
    cnn.open_user_home()
