from Kam1n0.Manager import Kam1n0PluginManager
from Kam1n0 import IDAUtils as ut
import idaapi
import idc

print('Kam1n0 testing script for idapro is now running...')
print('Waiting for idapro...')
idaapi.auto_wait()
print('Testing every callback functions provided by the connector.')

def get_mgr():
    print('Creating a new manager instance..')
    mg = Kam1n0PluginManager()
    print('Existing connections {}'.format(mg.configuration))
    info = {
        'app_url' : os.getenv('KT_APP_LINK', None),
        'un' : 'admin',
        'pw' : 'admin',
    }
    assert info['app_url'] is not None and len(info['app_url']) > 0
    mg.configuration['apps'].append(info)
    mg.configuration['default-app'] = info['app_url']
    mg.setup_default_connection()
    return mg

def test_index_current_func(mg):
    addr = os.getenv('KT_APP_QUERY', None);
    # hex string
    assert addr is not None and len(addr) > 0
    ut.jumpto(addr);
    assert get_screen_ea() == long(addr, 16)
    assert fire_action("Kam1n0:indexCurrent")
    mg.index_current_func()
    
    
def test_index_selected_func(mg):
    addr = os.getenv('KT_APP_QUERY', None);
    # hex string
    assert addr is not None and len(addr) > 0
    ut.jumpto(addr);
    assert get_screen_ea() == long(addr, 16)
    ind = idaapi.get_func_num(long(addr, 16))
    assert ind is not None and ind > 0
    ctx = idaapi.action_activation_ctx_t()
    if IDAUtils.is_hexrays_v7():
        ctx.widget_title = 'Functions window'
    else:
        ctx.form_title = 'Functions window'
    ctx.chooser_selection = [ind]
    mg.index_selected_func(ctx)
    

def test_query_current_func(mg):
    addr = os.getenv('KT_APP_QUERY', None);
    # hex string
    assert addr is not None and len(addr) > 0
    ut.jumpto(addr);
    assert get_screen_ea() == long(addr, 16)
    mg.query_current_func()
    
    
def test_query_selected_func(mg):
    addr = os.getenv('KT_APP_QUERY', None);
    # hex string
    assert addr is not None and len(addr) > 0
    ut.jumpto(addr);
    assert get_screen_ea() == long(addr, 16)
    ind = idaapi.get_func_num(long(addr, 16))
    assert ind is not None and ind > 0
    ctx = idaapi.action_activation_ctx_t()
    if IDAUtils.is_hexrays_v7():
        ctx.widget_title = 'Functions window'
    else:
        ctx.form_title = 'Functions window'
    ctx.chooser_selection = [ind]
    mg.query_selected_func(ctx)
