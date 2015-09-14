import idaapi
import Manager
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
            print("Kam1n0: initializing kam1n0 IDA-pro plugin ...")
            kam1n0_manager = Manager.Kam1n0PluginManager()
            if kam1n0_manager.registerActions():
                print "Failed to initialize Kam1n0."
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